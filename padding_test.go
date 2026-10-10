package rhttp

import (
	"io"
	"net/http"
	"testing"

	"golang.org/x/net/http2"
)

// TestPaddedDataFlowControlCredit: a padded DATA frame counts its full
// payload (pad-length byte + data + padding) toward flow control per RFC
// 9113 §6.9.1, so the WINDOW_UPDATE refills must credit the full amount —
// crediting only the data bytes would slowly starve the sender's view of
// our receive window.
func TestPaddedDataFlowControlCredit(t *testing.T) {
	bodyCh := make(chan []byte, 1)
	peer, _, cleanup := newTestPeer(t, ServerOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			bodyCh <- b
			w.WriteHeader(http.StatusOK)
		}),
	})
	defer cleanup()

	peer.sendHeaders(1, false, ":method", "POST", ":path", "/")

	data := []byte("hello")
	pad := make([]byte, 10)
	// Full flow-controlled payload: 1 pad-length byte + 5 data + 10 padding.
	const wantCredit = 1 + 5 + 10
	if err := peer.framer.WriteDataPadded(1, true, data, pad); err != nil {
		t.Fatalf("write padded DATA: %v", err)
	}

	var connCredit, streamCredit uint32
	for {
		f := peer.readFrame()
		switch f := f.(type) {
		case *http2.WindowUpdateFrame:
			switch f.Header().StreamID {
			case 0:
				connCredit += f.Increment
			case 1:
				streamCredit += f.Increment
			}
		case *http2.HeadersFrame:
			if f.StreamID != 1 {
				continue
			}
			if !f.StreamEnded() {
				// Response body frames may follow; keep reading (the default
				// 200 handler ends on HEADERS though).
				continue
			}
			if connCredit != wantCredit {
				t.Fatalf("conn-level WINDOW_UPDATE credited %d, want %d (padding must count)", connCredit, wantCredit)
			}
			if streamCredit != wantCredit {
				t.Fatalf("stream-level WINDOW_UPDATE credited %d, want %d (padding must count)", streamCredit, wantCredit)
			}
			if got := <-bodyCh; string(got) != "hello" {
				t.Fatalf("handler read body %q, want %q (padding must not leak into the body)", got, "hello")
			}
			return
		case *http2.DataFrame:
			if f.StreamEnded() {
				t.Fatal("unexpected DATA END_STREAM before response HEADERS")
			}
		default:
			t.Fatalf("unexpected frame %T", f)
		}
	}
}
