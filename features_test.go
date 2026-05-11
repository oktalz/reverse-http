package rhttp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestResponseWriterIsFlusher: a handler that casts to http.Flusher and calls
// Flush() should produce an immediate empty DATA frame on the wire, even
// before the handler writes the response body.
func TestResponseWriterIsFlusher(t *testing.T) {
	flushed := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("ResponseWriter doesn't implement http.Flusher")
			return
		}
		w.WriteHeader(200)
		f.Flush()
		<-flushed // hold the handler so the second body Write doesn't end the stream first
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer func() {
		close(flushed) // release handler before tearing down
		cleanup()
	}()

	peer.sendHeaders(1, true,
		":method", "GET", ":scheme", "https", ":authority", "x", ":path", "/")

	// We expect: HEADERS (no END_STREAM, since handler isn't done) then an
	// empty DATA frame from Flush. Both must arrive before the handler returns.
	sawHeaders := false
	sawEmptyData := false
	deadline := time.After(2 * time.Second)
	for !sawHeaders || !sawEmptyData {
		select {
		case <-deadline:
			t.Fatalf("did not see HEADERS+empty-DATA from Flush (headers=%v data=%v)", sawHeaders, sawEmptyData)
		default:
		}
		f := peer.readFrameWithin(time.Second)
		if f == nil {
			t.Fatalf("no frame; sawHeaders=%v sawEmptyData=%v", sawHeaders, sawEmptyData)
		}
		switch ff := f.(type) {
		case *http2.HeadersFrame:
			if ff.StreamEnded() {
				t.Fatal("HEADERS arrived with END_STREAM — handler shouldn't be done yet")
			}
			sawHeaders = true
		case *http2.DataFrame:
			if len(ff.Data()) != 0 {
				t.Fatalf("expected empty DATA from Flush, got %d bytes", len(ff.Data()))
			}
			sawEmptyData = true
		}
	}
}

// TestRequestContextCancelledOnRSTStream: when the peer resets a stream, the
// handler's req.Context().Done() must fire so a handler that's parked on a
// downstream call (i.e. not in Body.Read) can bail out.
func TestRequestContextCancelledOnRSTStream(t *testing.T) {
	ctxDone := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush() // get headers out so peer can RST after that
		select {
		case <-r.Context().Done():
			ctxDone <- r.Context().Err()
		case <-time.After(3 * time.Second):
			ctxDone <- nil
		}
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	peer.sendHeaders(1, false,
		":method", "POST", ":scheme", "https", ":authority", "x", ":path", "/")

	// Wait for response HEADERS to confirm handler is running, then reset.
	for {
		f := peer.readFrameWithin(2 * time.Second)
		if f == nil {
			t.Fatal("no HEADERS arrived before timeout")
		}
		if _, ok := f.(*http2.HeadersFrame); ok {
			break
		}
	}

	if err := peer.framer.WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
		t.Fatalf("write RST_STREAM: %v", err)
	}

	select {
	case err := <-ctxDone:
		if err == nil {
			t.Fatal("handler timed out waiting on ctx; expected cancellation")
		}
		if err != context.Canceled {
			t.Fatalf("ctx.Err() = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never observed ctx cancellation")
	}
}

// TestRequestContextCancelledOnConnClose: when the peer drops the connection,
// every live handler must observe ctx cancellation — not hang on the bodyReader
// cond.
func TestRequestContextCancelledOnConnClose(t *testing.T) {
	ctxDone := make(chan error, 1)
	handlerEntered := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(handlerEntered)
		select {
		case <-r.Context().Done():
			ctxDone <- r.Context().Err()
		case <-time.After(3 * time.Second):
			ctxDone <- nil
		}
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	peer.sendHeaders(1, false,
		":method", "POST", ":scheme", "https", ":authority", "x", ":path", "/")

	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started")
	}

	// Slam the peer conn shut — server's ReadFrame surfaces EOF, serve exits,
	// failAllStreams fires, ctx cancels.
	_ = peer.conn.Close()

	select {
	case err := <-ctxDone:
		if err == nil {
			t.Fatal("handler timed out; expected ctx cancellation from conn close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never observed ctx cancellation after conn close")
	}
}

// TestHandlerPanicRecovered: a handler that panics must not crash the worker,
// and the connection must remain usable for subsequent streams.
func TestHandlerPanicRecovered(t *testing.T) {
	// Capture the structured panic log via a buffered slog handler. Keeps
	// test output clean and lets us assert the panic actually fired.
	var logBuf bytes.Buffer
	prevDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prevDefault)

	var counter int
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		counter++
		n := counter
		mu.Unlock()
		if n == 1 {
			panic("boom")
		}
		w.WriteHeader(204)
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	// First request: handler panics. Recovery emits 500.
	peer.sendHeaders(1, true,
		":method", "GET", ":scheme", "https", ":authority", "x", ":path", "/")
	status, _, _ := peer.collectResponse(1)
	if status != http.StatusInternalServerError {
		t.Fatalf("first request: status = %d, want 500", status)
	}

	// Second request: same connection, handler should run normally.
	peer.sendHeaders(3, true,
		":method", "GET", ":scheme", "https", ":authority", "x", ":path", "/")
	status, _, _ = peer.collectResponse(3)
	if status != http.StatusNoContent {
		t.Fatalf("second request: status = %d, want 204", status)
	}

	// slog.TextHandler emits key=value pairs; check for the message + the
	// structured fields rather than the old fmt.Sprintf shape.
	out := logBuf.String()
	if !bytes.Contains(logBuf.Bytes(), []byte("panic serving stream")) {
		t.Fatalf("expected panic log message; got %q", out)
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("stream_id=1")) {
		t.Fatalf("expected stream_id=1 in log; got %q", out)
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("panic=boom")) {
		t.Fatalf("expected panic=boom in log; got %q", out)
	}
}

// TestGoAwaySentOnTeardown: when serve exits via the Shutdown path, the
// defer must put a GOAWAY frame on the wire BEFORE closing the conn so the
// peer can distinguish "we're closing cleanly, last-stream-id was N" from a
// raw TCP RST.
//
// We simulate Shutdown by wiring a shutdownCh into the connection and then
// poking ReadFrame's deadline. Closing the conn directly would race with
// the writer goroutine — the write would fail because the conn is already
// dead. The real Pool.Shutdown path keeps the conn open until the deferred
// GOAWAY makes it through.
func TestGoAwaySentOnTeardown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	// shutdownCh wired in before serve starts — no race.
	shutdownCh := make(chan struct{})
	peer, serverConn, cleanup := newTestPeerShutdown(t, ServerOptions{Handler: handler}, shutdownCh)
	defer cleanup()

	// Send a complete request so lastStreamID advances to 1.
	peer.sendHeaders(1, true,
		":method", "GET", ":scheme", "https", ":authority", "x", ":path", "/")
	if status, _, _ := peer.collectResponse(1); status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}

	// Trigger the same path Pool.Shutdown takes: close shutdownCh + nudge
	// ReadFrame's deadline so serve returns through the GOAWAY-emitting defer.
	close(shutdownCh)
	_ = serverConn.SetReadDeadline(time.Now())

	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("never saw GOAWAY")
		default:
		}
		f := peer.readFrameWithin(2 * time.Second)
		if f == nil {
			t.Fatal("no frame within 2s; expected GOAWAY")
		}
		ga, ok := f.(*http2.GoAwayFrame)
		if !ok {
			continue
		}
		if ga.LastStreamID != 1 {
			t.Fatalf("GOAWAY last-stream-id = %d, want 1", ga.LastStreamID)
		}
		if ga.ErrCode != http2.ErrCodeNo {
			t.Fatalf("GOAWAY err = %v, want NO_ERROR", ga.ErrCode)
		}
		return
	}
}

// TestPoolShutdownDrains: Pool.Shutdown signals shutdownCh, fires
// SetReadDeadline on every registered conn, and waits for maintainers to
// exit — all within the provided ctx.
func TestPoolShutdownDrains(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	// Pool's shutdownCh must be wired into the conn before serve starts —
	// otherwise the close(pool.shutdownCh) in Shutdown wouldn't reach serve
	// (and we'd race the field-write besides). Build the pool first.
	pool := &Pool{
		ready:      &sync.WaitGroup{},
		shutdownCh: make(chan struct{}),
		conns:      make(map[*connection]struct{}),
	}
	pool.ready.Add(1)
	pool.ready.Done()
	pool.maintainers.Go(func() {
		<-pool.shutdownCh
	})

	peer, serverConn, cleanup := newTestPeerShutdown(t, ServerOptions{Handler: handler}, pool.shutdownCh)
	defer cleanup()
	pool.registerConn(serverConn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	if err := pool.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown returned %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("Shutdown took too long: %v", elapsed)
	}

	// After Shutdown, the conn's serve loop should exit (it sees shutdownCh
	// closed via SetReadDeadline's wakeup); confirm by reading GOAWAY.
	for {
		f := peer.readFrameWithin(2 * time.Second)
		if f == nil {
			t.Fatal("no frame after Shutdown; expected GOAWAY")
		}
		if _, ok := f.(*http2.GoAwayFrame); ok {
			return
		}
	}
}

// TestPoolShutdownContextDeadline: when a maintainer goroutine refuses to
// exit (simulating a stuck handler), Shutdown returns ctx.Err() at the
// deadline rather than hanging forever.
func TestPoolShutdownContextDeadline(t *testing.T) {
	pool := &Pool{
		ready:      &sync.WaitGroup{},
		shutdownCh: make(chan struct{}),
		conns:      make(map[*connection]struct{}),
	}
	// Maintainer that never exits.
	pool.maintainers.Add(1)
	defer pool.maintainers.Done() // released after the test asserts ctx.Err

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := pool.Shutdown(ctx)
	if err != context.DeadlineExceeded {
		t.Fatalf("Shutdown returned %v, want DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Shutdown took too long: %v", elapsed)
	}
}

// Compile-time assertion that responseWriter implements http.Flusher; if a
// future refactor accidentally drops the Flush method, the build breaks here
// rather than at the next handler that depends on it.
var _ http.Flusher = (*responseWriter)(nil)

// io import kept for any future tests that need it.
var _ = io.EOF
