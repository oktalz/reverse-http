package rhttp

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// expectHeadersThenRST reads frames until it sees the response HEADERS for
// streamID followed by RST_STREAM with the given code. Interleaved DATA on
// the stream is tolerated (some tests write part of a body first); anything
// else fails the test.
func expectHeadersThenRST(t *testing.T, peer *testPeer, streamID uint32, wantCode http2.ErrCode) {
	t.Helper()
	sawHeaders := false
	for {
		f := peer.readFrame()
		switch f := f.(type) {
		case *http2.HeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			if f.StreamEnded() {
				t.Fatal("response HEADERS carried END_STREAM; want stream reset instead")
			}
			sawHeaders = true
		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}
			if f.StreamEnded() {
				t.Fatal("DATA carried END_STREAM; want stream reset instead")
			}
		case *http2.RSTStreamFrame:
			if f.Header().StreamID != streamID {
				continue
			}
			if !sawHeaders {
				t.Fatal("RST_STREAM before response HEADERS")
			}
			if f.ErrCode != wantCode {
				t.Fatalf("RST_STREAM code = %v, want %v", f.ErrCode, wantCode)
			}
			return
		case *http2.WindowUpdateFrame:
		default:
			t.Fatalf("unexpected frame %T while waiting for RST_STREAM", f)
		}
	}
}

// TestResponseShortContentLength: a handler that declares Content-Length but
// writes fewer bytes must NOT produce a clean END_STREAM — HAProxy (2.8+)
// treats a short content-length message as truncated and glitch-counts the
// mismatch. The stream is reset with INTERNAL_ERROR instead.
func TestResponseShortContentLength(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("hi"))
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	expectHeadersThenRST(t, peer, 1, http2.ErrCodeInternal)
}

// TestResponseExcessContentLength: writing past the declared Content-Length
// is refused with http.ErrContentLength (net/http semantics) and the stream
// is reset — the excess bytes never reach the wire.
func TestResponseExcessContentLength(t *testing.T) {
	errCh := make(chan error, 1)
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "4")
			_, _ = w.Write([]byte("hi"))
			_, err := w.Write([]byte("hop")) // 2+3 > 4
			errCh <- err
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	expectHeadersThenRST(t, peer, 1, http2.ErrCodeInternal)

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrContentLength) {
			t.Fatalf("handler Write error = %v, want http.ErrContentLength", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not observe the write error")
	}
}

// TestResponseExactContentLength: the well-behaved case still round-trips.
func TestResponseExactContentLength(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "5")
			_, _ = w.Write([]byte("hello"))
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	status, headers, body := peer.collectResponse(1)
	if status != 200 || string(body) != "hello" {
		t.Fatalf("got status %d body %q, want 200 %q", status, body, "hello")
	}
	if got := headers["content-length"]; len(got) != 1 || got[0] != "5" {
		t.Fatalf("content-length on wire = %v, want [5]", got)
	}
}

// TestResponseInvalidContentLengthDropped: a Content-Length that doesn't
// parse is stripped rather than forwarded (strict peers reject the whole
// message over a malformed value) and the response completes normally.
func TestResponseInvalidContentLengthDropped(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "banana")
			_, _ = w.Write([]byte("hi"))
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	status, headers, body := peer.collectResponse(1)
	if status != 200 || string(body) != "hi" {
		t.Fatalf("got status %d body %q, want 200 %q", status, body, "hi")
	}
	if got, ok := headers["content-length"]; ok {
		t.Fatalf("invalid content-length forwarded on wire: %v", got)
	}
}

// TestHeadResponseBodyDiscarded: body writes on a HEAD response are accepted
// and discarded, and the response goes out as a single HEADERS frame with
// END_STREAM — including the declared Content-Length, which is legitimate
// (and expected) on HEAD.
func TestHeadResponseBodyDiscarded(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "5")
			n, err := w.Write([]byte("hello"))
			if n != 5 || err != nil {
				t.Errorf("HEAD body write = (%d, %v), want (5, nil)", n, err)
			}
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "HEAD", ":path", "/")
	f := peer.readFrame()
	hf, ok := f.(*http2.HeadersFrame)
	if !ok || hf.StreamID != 1 {
		t.Fatalf("expected response HEADERS on stream 1, got %T", f)
	}
	if !hf.StreamEnded() {
		t.Fatal("HEAD response HEADERS should carry END_STREAM")
	}
	headers := peer.decodeHeaders(hf.HeaderBlockFragment())
	if got := headers["content-length"]; len(got) != 1 || got[0] != "5" {
		t.Fatalf("content-length on wire = %v, want [5]", got)
	}
	if extra := peer.readFrameWithin(150 * time.Millisecond); extra != nil {
		t.Fatalf("unexpected frame after HEAD response: %T", extra)
	}
}

// TestNoContentResponseBodyDiscarded: 204 must not carry a body on the wire
// regardless of what the handler writes.
func TestNoContentResponseBodyDiscarded(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
			_, _ = w.Write([]byte("should vanish"))
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	f := peer.readFrame()
	hf, ok := f.(*http2.HeadersFrame)
	if !ok || hf.StreamID != 1 || !hf.StreamEnded() {
		t.Fatalf("expected HEADERS+END_STREAM on stream 1, got %T (ended=%v)", f, ok && hf.StreamEnded())
	}
	headers := peer.decodeHeaders(hf.HeaderBlockFragment())
	if got := headers[":status"]; len(got) != 1 || got[0] != "204" {
		t.Fatalf(":status = %v, want [204]", got)
	}
	if extra := peer.readFrameWithin(150 * time.Millisecond); extra != nil {
		t.Fatalf("unexpected frame after 204 response: %T", extra)
	}
}
