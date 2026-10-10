package rhttp

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/oktalz/reverse-http/internal/h2"
)

// errConnDead is returned from Write when the underlying connection has been
// torn down while a handler was blocked on flow control.
var errConnDead = errors.New("rhttp: connection closed")

// errShortContentLength is returned by endStream when the handler declared a
// Content-Length it didn't fulfil. The stream must then be reset rather than
// closed with END_STREAM: HAProxy (2.8+ after the f572cc242 backport) treats
// a short content-length message as truncated and the mismatch counts against
// the connection's glitch budget, which can get the shared tunnel killed.
var errShortContentLength = errors.New("rhttp: handler wrote less than declared Content-Length")

// responseWriter implements http.ResponseWriter and http.Flusher for a
// worker-side HTTP/2 stream.
type responseWriter struct {
	err          error // first transport-level error from Write/Flush/writeHeaders
	stream       *h2.Stream
	conn         *h2.Conn
	declaredCL   int64 // Content-Length the handler declared; -1 = none
	written      int64 // body bytes accepted from the handler so far
	status       int
	wroteHeaders bool
	prepared     bool
	isHead       bool // request method was HEAD
	noBody       bool // response must not carry a body (HEAD, 204, 304)
	clViolated   bool // handler attempted to write past declaredCL
}

func (rw *responseWriter) Header() http.Header {
	// h2.Stream.Header is pre-allocated by the pool and cleared on acquire.
	return rw.stream.Header
}

// WriteHeader records the final status. A 1xx status is informational
// (net/http semantics): it goes out immediately as an interim HEADERS frame
// and the final status stays open, so a later Write still gets an implicit
// 200. Once the response shape is resolved (first Write, Flush or the
// headers on the wire), further calls are ignored.
func (rw *responseWriter) WriteHeader(statusCode int) {
	if rw.prepared || rw.err != nil {
		return
	}
	if statusCode >= 100 && statusCode <= 199 {
		if rw.status == 0 {
			rw.writeInformational(statusCode)
		}
		return
	}
	rw.status = statusCode
}

// writeInformational sends a 1xx interim response without END_STREAM. 101 is
// dropped: RFC 9113 §8.6 forbids it on HTTP/2. Content-Length describes the
// final response, so it is kept off the interim one (as x/net/http2 does).
func (rw *responseWriter) writeInformational(status int) {
	if status == http.StatusSwitchingProtocols {
		return
	}
	h := rw.stream.Header
	if _, ok := h["Content-Length"]; ok {
		h = h.Clone()
		h.Del("Content-Length")
	}
	if err := rw.conn.SendResponseHeaders(rw.stream.ID, status, h, false); err != nil {
		rw.err = err
	}
}

// bodyAllowedForStatus mirrors net/http: 204 and 304 responses carry no body
// on the wire regardless of what the handler writes. 1xx never reaches here —
// WriteHeader sends those as interim responses.
func bodyAllowedForStatus(status int) bool {
	return status != http.StatusNoContent && status != http.StatusNotModified
}

// prepare resolves the response shape once, before anything hits the wire:
// the default status, whether a body is allowed at all, and the declared
// Content-Length. A Content-Length that doesn't parse as a decimal length is
// dropped rather than forwarded — strict peers (HAProxy) reject the whole
// message over a malformed value.
func (rw *responseWriter) prepare() {
	if rw.prepared {
		return
	}
	rw.prepared = true
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	rw.noBody = rw.isHead || !bodyAllowedForStatus(rw.status)
	rw.declaredCL = -1
	if cl := rw.stream.Header.Get("Content-Length"); cl != "" {
		if v, err := strconv.ParseUint(cl, 10, 63); err == nil {
			rw.declaredCL = int64(v)
		} else {
			rw.stream.Header.Del("Content-Length")
		}
	}
}

// Flush sends a zero-length DATA frame so any buffered response bytes leave
// the process immediately. http.Flusher's interface has no error return, so
// any failure is latched on the responseWriter and surfaced from the next
// Write. On a bodyless response (HEAD, 204, 304) it does nothing — the
// headers go out with END_STREAM set when the handler returns.
func (rw *responseWriter) Flush() {
	if rw.err != nil {
		return
	}
	rw.prepare()
	if rw.noBody {
		return
	}
	if !rw.wroteHeaders {
		if err := rw.writeHeaders(false); err != nil {
			rw.err = err
			return
		}
	}
	if err := rw.conn.SendData(rw.stream.ID, nil, false); err != nil {
		rw.err = err
	}
}

func (rw *responseWriter) writeHeaders(endStream bool) error {
	if rw.wroteHeaders {
		return nil
	}
	rw.prepare()
	rw.wroteHeaders = true
	err := rw.conn.SendResponseHeaders(rw.stream.ID, rw.status, rw.stream.Header, endStream)
	if err != nil {
		rw.err = err
	}
	return err
}

// Write emits DATA frames respecting both the conn-level and per-stream send
// windows (RFC 7540 §6.9). When credit runs out we block in Send.Reserve
// until a WINDOW_UPDATE arrives or the conn is torn down.
//
// Writes on a bodyless response are accepted and discarded (net/http
// semantics) — forwarding them would be a malformed message on H2, which
// HAProxy answers with a stream reset and a glitch against the connection.
// Writes past a declared Content-Length are refused with
// http.ErrContentLength for the same reason.
func (rw *responseWriter) Write(p []byte) (int, error) {
	if rw.err != nil {
		return 0, rw.err
	}
	rw.prepare()
	if rw.noBody {
		return len(p), nil
	}
	if !rw.wroteHeaders {
		if err := rw.writeHeaders(false); err != nil {
			return 0, err
		}
	}
	if len(p) == 0 {
		return 0, nil
	}
	if rw.declaredCL >= 0 && rw.written+int64(len(p)) > rw.declaredCL {
		rw.clViolated = true
		rw.err = http.ErrContentLength
		return 0, rw.err
	}

	maxFrame := int32(rw.conn.MaxFrameSize())
	if maxFrame <= 0 {
		maxFrame = 16384
	}

	total := 0
	for len(p) > 0 {
		want := min(int32(len(p)), maxFrame)
		got, dead := rw.conn.Send.Reserve(&rw.stream.SendWindow, want)
		if dead {
			rw.err = errConnDead
			return total, errConnDead
		}
		chunk := p[:got]
		p = p[got:]

		if err := rw.conn.SendData(rw.stream.ID, chunk, false); err != nil {
			rw.err = err
			return total, err
		}
		total += int(got)
		rw.written += int64(got)
	}
	return total, nil
}

// endStream sends the final END_STREAM signal after the handler returns. If
// the handler never wrote headers (including every bodyless response), the
// HEADERS frame itself carries END_STREAM; otherwise an empty DATA frame
// does. A response short of its declared Content-Length gets neither —
// errShortContentLength is returned and the caller resets the stream, so the
// peer sees an explicit stream error instead of a "complete" truncated
// message.
func (rw *responseWriter) endStream() error {
	rw.prepare()
	if !rw.noBody && rw.declaredCL >= 0 && rw.written < rw.declaredCL {
		return errShortContentLength
	}
	if !rw.wroteHeaders {
		return rw.writeHeaders(true)
	}
	err := rw.conn.SendData(rw.stream.ID, nil, true)
	if err != nil {
		rw.err = err
	}
	return err
}
