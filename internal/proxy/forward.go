package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/oktalz/reverse-http/internal/h2"
	"golang.org/x/net/http2"
)

// forward handles one public request: pick a worker, open an outbound
// stream, send the request, stream the response back. Errors are translated
// to plain-text 5xx responses if no bytes have been written yet; otherwise
// the public peer sees a truncated body.
func (p *Proxy) forward(w http.ResponseWriter, req *http.Request) {
	worker := p.selector.Pick(req, p.snapshotWorkers())
	if worker == nil {
		http.Error(w, "no worker attached", http.StatusServiceUnavailable)
		return
	}

	worker.inFlight.Add(1)
	defer worker.inFlight.Add(-1)

	cs, bodyErrCh, err := openForward(worker, req)
	if err != nil {
		http.Error(w, "rhttp/proxy: failed to open tunnel stream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() {
		worker.conn.RemoveStream(cs.h2.ID)
		worker.deregisterStream(cs.h2.ID)
		h2.Release(cs.h2)
	}()

	if !waitForResponseHeaders(w, req, worker, cs, bodyErrCh) {
		return
	}
	writeResponse(w, req, worker, cs)
	<-bodyErrCh
}

// openForward picks the request shape, opens a stream, and (if needed)
// fires off a goroutine to pump the request body. Returns the body-pump
// channel so the caller can drain it before returning to the http.Server.
func openForward(worker *Worker, req *http.Request) (*clientStream, chan error, error) {
	bodyEmpty := req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0

	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	scheme := "https"
	if req.TLS == nil {
		scheme = "http"
	}

	reqHeader := buildForwardedHeader(req)

	initialWindow := worker.conn.Send.InitialStreamWindow()
	cs, err := worker.openStream(initialWindow, func(streamID uint32) error {
		return worker.conn.SendRequestHeaders(streamID, req.Method, scheme, authority, path, reqHeader, bodyEmpty)
	})
	if err != nil {
		return nil, nil, err
	}

	bodyErrCh := make(chan error, 1)
	if !bodyEmpty {
		go func() {
			bodyErrCh <- streamRequestBody(worker, cs, req.Body)
		}()
	} else {
		bodyErrCh <- nil
	}
	return cs, bodyErrCh, nil
}

// waitForResponseHeaders blocks until response HEADERS arrive or the request
// is cancelled / the worker disconnects. Returns true iff the caller should
// proceed to copy the response; otherwise an error response has already been
// written or the connection is closed.
func waitForResponseHeaders(w http.ResponseWriter, req *http.Request, worker *Worker, cs *clientStream, bodyErrCh chan error) bool {
	select {
	case <-cs.respCh:
	case <-req.Context().Done():
		worker.conn.SendRSTStream(cs.h2.ID, http2.ErrCodeCancel)
		<-bodyErrCh
		return false
	case <-worker.done():
		http.Error(w, "rhttp/proxy: tunnel disconnected", http.StatusBadGateway)
		<-bodyErrCh
		return false
	}
	if cs.respErr != nil {
		http.Error(w, "rhttp/proxy: stream failed: "+cs.respErr.Error(), http.StatusBadGateway)
		<-bodyErrCh
		return false
	}
	return true
}

// writeResponse copies the worker's response headers + body to the public
// http.ResponseWriter. Headers and status have already been delivered by the
// tunnel frame reader; the body is drained from the stream's queue.
//
// A goroutine watches req.Context() so that a mid-response disconnect by the
// public peer (Go's http.Server cancels the request ctx when its connection
// drops) translates into RST_STREAM toward the worker. Without this, body
// reads would park indefinitely while the worker keeps producing into a
// stream nobody's reading.
func writeResponse(w http.ResponseWriter, req *http.Request, worker *Worker, cs *clientStream) {
	for k, vv := range cs.respHeader {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	if cs.respHeader != nil {
		h2.HeaderPool.Put(cs.respHeader)
		cs.respHeader = nil
	}
	status := cs.respStatus
	if status == 0 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)

	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		select {
		case <-req.Context().Done():
			worker.conn.SendRSTStream(cs.h2.ID, http2.ErrCodeCancel)
		case <-doneCh:
		}
	}()

	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 16*1024)
	body := cs.h2.Body()
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				worker.conn.SendRSTStream(cs.h2.ID, http2.ErrCodeCancel)
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				// Headers already on the wire — nothing to surface;
				// public peer sees a truncated body.
				_ = err
			}
			return
		}
	}
}

// streamRequestBody reads body and emits DATA frames, respecting both the
// conn-level and per-stream send windows (RFC 7540 §6.9). Ends with an empty
// DATA frame with END_STREAM. Cancellation: returns promptly if the worker
// has detached.
func streamRequestBody(worker *Worker, cs *clientStream, body io.ReadCloser) error {
	defer func() { _ = body.Close() }()

	c := worker.conn
	maxFrame := int32(c.MaxFrameSize())
	if maxFrame <= 0 {
		maxFrame = 16384
	}
	buf := make([]byte, maxFrame)

	for {
		select {
		case <-worker.done():
			return errors.New("worker detached")
		default:
		}
		n, err := body.Read(buf)
		for offset := 0; offset < n; {
			want := int32(n - offset)
			got, dead := c.Send.Reserve(&cs.h2.SendWindow, want)
			if dead {
				return errors.New("conn dead")
			}
			chunk := buf[offset : offset+int(got)]
			if werr := c.SendData(cs.h2.ID, chunk, false); werr != nil {
				return werr
			}
			offset += int(got)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return c.SendData(cs.h2.ID, nil, true)
			}
			c.SendRSTStream(cs.h2.ID, http2.ErrCodeCancel)
			return fmt.Errorf("read req body: %w", err)
		}
	}
}

// buildForwardedHeader copies the inbound request headers into a fresh
// http.Header drawn from the pool. Hop-by-hop and Connection-listed values
// are dropped per RFC 7230 §6.1. The worker side (h2 encode path) drops
// Connection-style headers per RFC 9113 §8.2.2 anyway, but stripping them
// here also helps any logging hooks see a clean header set.
func buildForwardedHeader(req *http.Request) http.Header {
	h, _ := h2.HeaderPool.Get().(http.Header)
	clear(h)
	for k, vv := range req.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			h.Add(k, v)
		}
	}
	return h
}

// isHopByHop reports whether name (canonical form) is a hop-by-hop header
// the proxy must strip.
func isHopByHop(name string) bool {
	switch name {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Connection":
		return true
	}
	return false
}
