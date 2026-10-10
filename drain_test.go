package rhttp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/oktalz/reverse-http/internal/h2"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestWorkerGoAwayGracefulDrain: a GOAWAY(NO_ERROR) from the peer (HAProxy
// soft-stop/reload) must NOT kill in-flight streams — the handler runs to
// completion, its response reaches the peer, and only then does the frame
// loop exit with ErrGoaway.
func TestWorkerGoAwayGracefulDrain(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, "drained")
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	<-started

	if err := peer.framer.WriteGoAway(1, http2.ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}

	// The frame loop must keep running while the stream is in flight.
	select {
	case err := <-peer.errCh:
		t.Fatalf("serve exited during drain: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(release)
	status, _, body := peer.collectResponse(1)
	if status != 200 || string(body) != "drained" {
		t.Fatalf("got status %d body %q, want 200 %q", status, body, "drained")
	}

	select {
	case err := <-peer.errCh:
		if !errors.Is(err, h2.ErrGoaway) {
			t.Fatalf("serve exit error = %v, want ErrGoaway", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not exit after the drain completed")
	}
}

// TestWorkerGoAwayWithErrorTearsDownImmediately: a GOAWAY carrying a real
// error code is not a drain — the connection is torn down at once.
func TestWorkerGoAwayWithErrorTearsDownImmediately(t *testing.T) {
	started := make(chan struct{}, 1)
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			started <- struct{}{}
			<-r.Context().Done() // released by FailAllStreams on teardown
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	<-started

	if err := peer.framer.WriteGoAway(1, http2.ErrCodeProtocol, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}
	select {
	case err := <-peer.errCh:
		if !errors.Is(err, h2.ErrGoaway) {
			t.Fatalf("serve exit error = %v, want ErrGoaway", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not exit on GOAWAY(PROTOCOL_ERROR)")
	}
}

// TestWorkerGoAwayNoStreamsExitsPromptly: a graceful GOAWAY with nothing in
// flight completes the drain immediately.
func TestWorkerGoAwayNoStreamsExitsPromptly(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{})
	defer cleanup()

	if err := peer.framer.WriteGoAway(0, http2.ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}
	select {
	case err := <-peer.errCh:
		if !errors.Is(err, h2.ErrGoaway) {
			t.Fatalf("serve exit error = %v, want ErrGoaway", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not exit on GOAWAY with no in-flight streams")
	}
}

// TestDialReleasesSlotOnGracefulGoaway: when the peer starts a graceful
// drain, dial must return promptly (so the pool slot redials a replacement
// immediately) while the draining connection finishes in the background and
// deregisters itself once done.
func TestDialReleasesSlotOnGracefulGoaway(t *testing.T) {
	ca := newCA(t)
	serverPEM, serverKeyPEM := ca.issue(t, "127.0.0.1", true)
	serverCert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	clientPEM, clientKeyPEM := ca.issue(t, "rhttp-worker", false)
	clientCert, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Fake gateway: handshake, open stream 1, send graceful GOAWAY while the
	// stream is still in flight, then drain the worker's frames until it
	// finishes and closes.
	gatewayDone := make(chan struct{})
	go func() {
		defer close(gatewayDone)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))

		pref := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(c, pref); err != nil {
			t.Errorf("gateway: read preface: %v", err)
			return
		}
		fr := http2.NewFramer(c, c)
		if _, err := fr.ReadFrame(); err != nil { // worker SETTINGS
			t.Errorf("gateway: read SETTINGS: %v", err)
			return
		}
		_ = fr.WriteSettings()
		_ = fr.WriteSettingsAck()

		var encBuf bytes.Buffer
		enc := hpack.NewEncoder(&encBuf)
		_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
		_ = fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: encBuf.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		})
		_ = fr.WriteGoAway(1, http2.ErrCodeNo, nil)

		// Consume the worker's remaining frames (SETTINGS ack, the response,
		// its teardown GOAWAY) until it closes the conn.
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	opts := ServerOptions{
		Addr:          ln.Addr().String(),
		SNIServerName: "127.0.0.1",
		TLSCert:       clientCert,
		CACertPool:    caPool,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
			}
			_, _ = io.WriteString(w, "ok")
		}),
	}

	p := newTestPool()
	once := &sync.Once{}
	dialRet := make(chan error, 1)
	go func() { dialRet <- dial(opts, p, once) }()

	<-started

	// dial must hand the slot back shortly after the GOAWAY even though the
	// handler is still blocked mid-drain.
	select {
	case err := <-dialRet:
		if err != nil {
			t.Fatalf("dial returned %v, want nil (drain handoff)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not release the slot after graceful GOAWAY")
	}

	// Finish the drain; the background reaper must deregister the conn.
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.connsMu.Lock()
		n := len(p.conns)
		p.connsMu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("draining conn still registered after completion (%d left)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-gatewayDone:
	case <-time.After(3 * time.Second):
		t.Fatal("fake gateway did not observe the worker finishing")
	}
}

// TestProxyWorkerGracefulGoAwayDrain: the proxy side of the same contract —
// a worker (e.g. an HAProxy edge on soft-stop) that sends GOAWAY(NO_ERROR)
// stops receiving new requests immediately but its in-flight response still
// reaches the public caller, and the worker detaches once drained.
func TestProxyWorkerGracefulGoAwayDrain(t *testing.T) {
	attached := make(chan struct{}, 1)
	proxy, err := NewProxy(ProxyOptions{
		TunnelTLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		OnWorkerAttach:  func(*ProxyWorker) { attached <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	// Plain TCP is fine here: ServeTunnelListener only enforces TLS/ALPN on
	// *tls.Conn, and this test drives the raw H2 tunnel protocol directly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = proxy.ServeTunnelListener(ln) }()

	public := httptest.NewServer(proxy.Handler())
	defer public.Close()

	// Fake worker: preface + SETTINGS exchange.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, clientPreface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
	select {
	case <-attached:
	case <-time.After(3 * time.Second):
		t.Fatal("fake worker did not attach")
	}

	// Fire the first public request; it blocks until the fake worker answers.
	type result struct {
		resp *http.Response
		err  error
	}
	res1 := make(chan result, 1)
	go func() {
		resp, err := http.Get(public.URL)
		res1 <- result{resp, err}
	}()

	// Read tunnel frames until the request HEADERS arrive (ack SETTINGS on
	// the way).
	var reqStream uint32
	for reqStream == 0 {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("fake worker read: %v", err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			reqStream = f.StreamID
		}
	}

	// Graceful GOAWAY while the request is in flight.
	if err := fr.WriteGoAway(reqStream, http2.ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}

	// Wait until the proxy has marked the worker draining, then a new public
	// request must be refused — the draining worker is invisible to selectors.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ws := proxy.Workers()
		if len(ws) == 1 && ws[0].Draining() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker never reported draining")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resp2, err := http.Get(public.URL)
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("request during drain: status %d, want 503", resp2.StatusCode)
	}

	// Answer the in-flight stream; the blocked public caller must get it.
	var encBuf bytes.Buffer
	enc := hpack.NewEncoder(&encBuf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      reqStream,
		BlockFragment: encBuf.Bytes(),
		EndHeaders:    true,
		EndStream:     true,
	}); err != nil {
		t.Fatalf("write response HEADERS: %v", err)
	}

	select {
	case r := <-res1:
		if r.err != nil {
			t.Fatalf("first GET: %v", r.err)
		}
		_ = r.resp.Body.Close()
		if r.resp.StatusCode != http.StatusOK {
			t.Fatalf("first GET status %d, want 200 (drain must not kill in-flight requests)", r.resp.StatusCode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not complete during drain")
	}

	// Drain finished — the worker must detach.
	deadline = time.Now().Add(3 * time.Second)
	for {
		if len(proxy.Workers()) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("drained worker never detached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
