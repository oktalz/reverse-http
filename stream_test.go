package rhttp

import (
	"bytes"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestRequestBodyDelivered: bytes the peer writes as DATA frames must arrive
// to the handler via r.Body, complete and in order, with EOF on END_STREAM.
func TestRequestBodyDelivered(t *testing.T) {
	got := make(chan []byte, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- b
		w.WriteHeader(200)
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	peer.sendHeaders(1, false,
		":method", "POST", ":scheme", "https", ":authority", "x", ":path", "/")
	// Chunk the body into a few DATA frames; rhttp's bodyReader has to stitch
	// them back together.
	peer.sendData(1, false, []byte("hello "))
	peer.sendData(1, false, []byte("world"))
	peer.sendData(1, true, []byte(" again"))

	select {
	case b := <-got:
		if string(b) != "hello world again" {
			t.Fatalf("body = %q, want %q", b, "hello world again")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler never finished reading")
	}
}

// TestHandlerReturnWithoutDrain: a handler that returns without reading the
// request body must not leak the stream — rhttp should emit RST_STREAM so the
// peer stops sending body, and the stream registry must drain.
func TestHandlerReturnWithoutDrain(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Read nothing; return immediately with a 200.
		w.WriteHeader(200)
	})
	peer, c, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	peer.sendHeaders(1, false,
		":method", "POST", ":scheme", "https", ":authority", "x", ":path", "/")
	// Send some body but never END_STREAM — naive impl would hang on
	// io.Copy(io.Discard, body).
	peer.sendData(1, false, []byte("never-finished-body"))

	// Collect frames until we see RST_STREAM(NO_ERROR) for stream 1, or until
	// stream 1's HEADERS+END_STREAM passes by.
	var sawRST, sawEnd bool
	deadline := time.After(2 * time.Second)
	for !sawRST {
		select {
		case <-deadline:
			t.Fatalf("did not see RST_STREAM (sawEnd=%v)", sawEnd)
		default:
		}
		f := peer.readFrame()
		switch f := f.(type) {
		case *http2.HeadersFrame:
			if f.StreamID == 1 && f.StreamEnded() {
				sawEnd = true
			}
		case *http2.DataFrame:
			if f.StreamID == 1 && f.StreamEnded() {
				sawEnd = true
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				if f.ErrCode != http2.ErrCodeNo {
					t.Errorf("RST_STREAM code = %v, want NO_ERROR", f.ErrCode)
				}
				sawRST = true
			}
		}
	}

	// Stream registry should drain promptly.
	for range 50 {
		if c.ActiveStreams() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("stream registry still populated after handler returned without drain")
}

// TestLargeResponse: a multi-MB response streamed under default flow control
// must arrive byte-identical at the peer. Exercises Write's flow-control
// chunking and WINDOW_UPDATE refills under normal conditions.
func TestLargeResponse(t *testing.T) {
	const n = 256 * 1024
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write(payload)
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	peer.sendHeaders(1, true,
		":method", "GET", ":scheme", "https", ":authority", "x", ":path", "/")

	// Collect manually; auto-refill the stream + conn windows so flow control
	// doesn't stall the test.
	var got bytes.Buffer
	consumed := int32(0)
	connConsumed := int32(0)
	for got.Len() < n {
		f := peer.readFrame()
		if df, ok := f.(*http2.DataFrame); ok {
			written, _ := got.Write(df.Data())
			consumed += int32(written)
			connConsumed += int32(written)
			// Refill aggressively (every chunk) — keeps the test fast and
			// confirms WINDOW_UPDATE handling is symmetric.
			if consumed >= 8192 {
				_ = peer.framer.WriteWindowUpdate(1, uint32(consumed))
				consumed = 0
			}
			if connConsumed >= 8192 {
				_ = peer.framer.WriteWindowUpdate(0, uint32(connConsumed))
				connConsumed = 0
			}
		}
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("body mismatch (got %d bytes, want %d)", got.Len(), n)
	}
}

// TestLargeRequestBody: rhttp must emit WINDOW_UPDATEs aggressively enough
// that the peer can keep sending past the default 64 KB window. The handler
// reads all bytes and the count matches.
func TestLargeRequestBody(t *testing.T) {
	const n = 256 * 1024
	got := make(chan int, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
		}
		got <- len(b)
		w.WriteHeader(200)
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	peer.sendHeaders(1, false,
		":method", "POST", ":scheme", "https", ":authority", "x", ":path", "/")

	// Drive DATA + drain WINDOW_UPDATE concurrently so the peer never blocks.
	var done atomic.Bool
	go func() {
		for !done.Load() {
			f := peer.readFrameWithin(50 * time.Millisecond)
			if f == nil {
				continue
			}
			// Just drain — WINDOW_UPDATEs/HEADERS/DATA all OK.
			_ = f
		}
	}()

	payload := bytes.Repeat([]byte{'A'}, 16384)
	for sent := 0; sent < n; sent += len(payload) {
		end := sent+len(payload) >= n
		peer.sendData(1, end, payload)
	}

	select {
	case got := <-got:
		done.Store(true)
		if got != n {
			t.Fatalf("body length = %d, want %d", got, n)
		}
	case <-time.After(5 * time.Second):
		done.Store(true)
		t.Fatal("handler never finished reading body")
	}
}

// TestSSEStyleStreaming: a handler that writes + flushes repeatedly over a
// long-lived response (no END_STREAM until the very end) must deliver each
// flushed chunk to the peer promptly. Mirrors the slides SSE endpoints.
func TestSSEStyleStreaming(t *testing.T) {
	ready := make(chan struct{})
	done := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher, _ := w.(http.Flusher)
		close(ready)
		for range 5 {
			_, _ = io.WriteString(w, "event:tick\ndata:hi\n\n")
			flusher.Flush()
			time.Sleep(20 * time.Millisecond)
		}
		<-done
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	peer.sendHeaders(1, true,
		":method", "GET", ":scheme", "https", ":authority", "x", ":path", "/api/events")

	<-ready
	chunks := 0
	deadline := time.After(2 * time.Second)
	for chunks < 5 {
		select {
		case <-deadline:
			close(done)
			t.Fatalf("only got %d/5 SSE chunks", chunks)
		default:
		}
		f := peer.readFrame()
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == 1 && len(df.Data()) > 0 {
			chunks++
		}
	}
	close(done)
}

// TestSendCreditMarkedDeadOnConnClose: tearing down the connection wakes any
// handler goroutine blocked on the send credit cond rather than letting it
// hang forever.
func TestSendCreditMarkedDeadOnConnClose(t *testing.T) {
	// Squeeze the send window to zero from the peer side so Write blocks.
	peerSettings := func(p *testPeer) {
		if err := p.framer.WriteSettings(http2.Setting{
			ID: http2.SettingInitialWindowSize, Val: 0,
		}); err != nil {
			t.Fatalf("write SETTINGS: %v", err)
		}
		// Drain the ACK.
		for {
			f := p.readFrame()
			if sf, ok := f.(*http2.SettingsFrame); ok && sf.IsAck() {
				return
			}
		}
	}

	writeErr := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blocked-by-flow-control"))
		writeErr <- err
	})
	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: handler})
	defer cleanup()

	peerSettings(peer)
	peer.sendHeaders(1, true,
		":method", "GET", ":scheme", "https", ":authority", "x", ":path", "/")

	// Handler should be parked in sendCredit.reserve right now. Yank the
	// rug — close the peer side. The serve loop notices ReadFrame error and
	// markDead releases the writer.
	time.Sleep(50 * time.Millisecond)
	_ = peer.conn.Close()

	select {
	case err := <-writeErr:
		if err == nil {
			t.Fatal("Write returned nil, want connection-closed error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler hung in Write after conn close")
	}
}
