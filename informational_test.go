package rhttp

import (
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// readResponseHeaders reads the next HEADERS frame for streamID (skipping
// WINDOW_UPDATEs) and returns its decoded fields and END_STREAM flag.
func readResponseHeaders(t *testing.T, peer *testPeer, streamID uint32) (map[string][]string, bool) {
	t.Helper()
	for {
		f := peer.readFrame()
		switch f := f.(type) {
		case *http2.HeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			return peer.decodeHeaders(f.HeaderBlockFragment()), f.StreamEnded()
		case *http2.WindowUpdateFrame:
		default:
			t.Fatalf("expected HEADERS on stream %d, got %T", streamID, f)
		}
	}
}

func wantStatus(t *testing.T, h map[string][]string, want string) {
	t.Helper()
	if got := h[":status"]; len(got) != 1 || got[0] != want {
		t.Fatalf(":status = %v, want [%s]", got, want)
	}
}

// TestEarlyHintsThenImplicit200: WriteHeader(103) sends an interim response
// and leaves the final status open, so a following Write gets an implicit
// 200 with its body (net/http semantics). The interim HEADERS must not carry
// END_STREAM — that would end the stream on a 1xx, a malformed response.
func TestEarlyHintsThenImplicit200(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Link", "</style.css>; rel=preload; as=style")
			w.WriteHeader(http.StatusEarlyHints)
			_, _ = w.Write([]byte("body"))
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	interim, ended := readResponseHeaders(t, peer, 1)
	wantStatus(t, interim, "103")
	if ended {
		t.Fatal("103 interim HEADERS carried END_STREAM")
	}
	if got := interim["link"]; len(got) != 1 {
		t.Fatalf("103 link header = %v, want one value", got)
	}

	status, _, body := peer.collectResponse(1)
	if status != http.StatusOK || string(body) != "body" {
		t.Fatalf("final response = %d %q, want 200 \"body\"", status, body)
	}
}

// TestEarlyHintsThenExplicitFinal: an explicit final WriteHeader after the
// interim one wins, and a Content-Length set before the 103 is kept off the
// interim response but declared on the final one.
func TestEarlyHintsThenExplicitFinal(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "4")
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("body"))
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	interim, _ := readResponseHeaders(t, peer, 1)
	wantStatus(t, interim, "103")
	if got := interim["content-length"]; got != nil {
		t.Fatalf("103 carried content-length %v", got)
	}

	status, headers, body := peer.collectResponse(1)
	if status != http.StatusCreated || string(body) != "body" {
		t.Fatalf("final response = %d %q, want 201 \"body\"", status, body)
	}
	if got := headers["content-length"]; len(got) != 1 || got[0] != "4" {
		t.Fatalf("final content-length = %v, want [4]", got)
	}
}

// TestEarlyHintsThenReturn: a handler that sends only a 103 and returns gets
// an empty final 200, not a stream ended on the interim response.
func TestEarlyHintsThenReturn(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	interim, ended := readResponseHeaders(t, peer, 1)
	wantStatus(t, interim, "103")
	if ended {
		t.Fatal("103 interim HEADERS carried END_STREAM")
	}
	final, ended := readResponseHeaders(t, peer, 1)
	wantStatus(t, final, "200")
	if !ended {
		t.Fatal("final empty 200 should carry END_STREAM")
	}
}

// TestInformationalAfterFinalIgnored: once the final response is on the wire,
// a 1xx WriteHeader is a no-op — no stray HEADERS mid-body.
func TestInformationalAfterFinalIgnored(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("a"))
			w.WriteHeader(http.StatusEarlyHints)
			_, _ = w.Write([]byte("b"))
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	status, _, body := peer.collectResponse(1)
	if status != http.StatusOK || string(body) != "ab" {
		t.Fatalf("response = %d %q, want 200 \"ab\"", status, body)
	}
	if extra := peer.readFrameWithin(150 * time.Millisecond); extra != nil {
		t.Fatalf("unexpected frame after response: %T", extra)
	}
}

// TestSwitchingProtocolsNotSent: RFC 9113 §8.6 forbids 101 on HTTP/2, so it
// is never put on the wire; the handler's response continues as if it had
// not been called.
func TestSwitchingProtocolsNotSent(t *testing.T) {
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusSwitchingProtocols)
			_, _ = w.Write([]byte("body"))
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, true, ":method", "GET", ":path", "/")
	status, _, body := peer.collectResponse(1)
	if status != http.StatusOK || string(body) != "body" {
		t.Fatalf("response = %d %q, want 200 \"body\"", status, body)
	}
}
