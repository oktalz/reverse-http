package rhttp

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// encodeInPlace writes HPACK fields into the peer's encBuf and returns the
// underlying bytes. Re-encoding every iteration lets the encoder emit indexed
// references for repeat headers — without this, pre-encoded bytes always
// represent "literal-with-indexing" frames and the server-side decoder
// allocates a fresh string per literal value every iteration, masking the
// allocations we actually care about.
//
// The returned slice is valid only until the next call (encBuf is reused).
// Caller must hand the bytes to framer.WriteHeaders synchronously.
func encodeInPlace(p *testPeer, kv ...string) []byte {
	p.encBuf.Reset()
	for i := 0; i < len(kv); i += 2 {
		_ = p.enc.WriteField(hpack.HeaderField{Name: kv[i], Value: kv[i+1]})
	}
	return p.encBuf.Bytes()
}

// BenchmarkRoundTripMinimal: GET / → 200 with a 5-byte body and one response
// header. Smallest realistic request — captures the per-request overhead of
// the stream lifecycle, HPACK decode/encode, and response framing.
//
// Run with: go test -bench=BenchmarkRoundTrip -benchmem -benchtime=2s
func BenchmarkRoundTripMinimal(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello")
	})
	peer, _, cleanup := newTestPeer(b, ServerOptions{Handler: handler})
	defer cleanup()

	b.ResetTimer()
	b.ReportAllocs()

	var streamID uint32 = 1
	for i := 0; i < b.N; i++ {
		block := encodeInPlace(
			peer,
			":method", "GET",
			":scheme", "https",
			":authority", "example.com",
			":path", "/",
		)
		if err := peer.framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     true,
		}); err != nil {
			b.Fatalf("write HEADERS: %v", err)
		}
		drainResponse(b, peer, streamID)
		streamID += 2
	}
}

// BenchmarkRoundTripHeaders: same shape as Minimal but with a fuller header
// set on both sides. Exercises the per-connection canonical/lowercase caches
// — after the first iteration, every header name lookup is a map hit.
func BenchmarkRoundTripHeaders(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Request-Id", "abc123")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	peer, _, cleanup := newTestPeer(b, ServerOptions{Handler: handler})
	defer cleanup()

	b.ResetTimer()
	b.ReportAllocs()

	var streamID uint32 = 1
	for i := 0; i < b.N; i++ {
		block := encodeInPlace(
			peer,
			":method", "GET",
			":scheme", "https",
			":authority", "example.com",
			":path", "/api/v1/widgets",
			"user-agent", "bench/1.0",
			"accept", "application/json",
			"accept-encoding", "gzip",
			"x-request-id", "abc123",
		)
		if err := peer.framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     true,
		}); err != nil {
			b.Fatalf("write HEADERS: %v", err)
		}
		drainResponse(b, peer, streamID)
		streamID += 2
	}
}

// BenchmarkRoundTripWithBody: POST with a 1 KB body the handler discards.
// Exercises the bodyReader queue + flow-control refill path.
func BenchmarkRoundTripWithBody(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	peer, _, cleanup := newTestPeer(b, ServerOptions{Handler: handler})
	defer cleanup()

	body := make([]byte, 1024)

	b.ResetTimer()
	b.ReportAllocs()

	var streamID uint32 = 1
	for i := 0; i < b.N; i++ {
		block := encodeInPlace(
			peer,
			":method", "POST",
			":scheme", "https",
			":authority", "example.com",
			":path", "/ingest",
			"content-type", "application/octet-stream",
		)
		if err := peer.framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     false,
		}); err != nil {
			b.Fatalf("write HEADERS: %v", err)
		}
		if err := peer.framer.WriteData(streamID, true, body); err != nil {
			b.Fatalf("write DATA: %v", err)
		}
		drainResponse(b, peer, streamID)
		streamID += 2
	}
}

// BenchmarkConcurrentResponses fires `concurrency` requests back-to-back
// without waiting between them, then drains the responses. The handler writes
// a sizeable body so multiple goroutines actively contend on writeMu when
// serializing DATA frames onto the single framer.
//
// b.N counts iterations of the *batch*, so per-request cost is
// reported ns/op / concurrency. The interesting comparison is throughput
// (ns/op) and goroutine contention — capture the latter with
// `-blockprofile=/tmp/block.prof` and inspect with `pprof`.
func BenchmarkConcurrentResponses(b *testing.B) {
	for _, concurrency := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("c=%d", concurrency), func(b *testing.B) {
			// Response body sized to fit within the default 64 KiB send
			// window so we don't stall on flow control before the peer can
			// drain. The point is to make writeMu hold long enough that
			// concurrent handlers contend, not to test flow control.
			body := make([]byte, 8*1024)
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			})
			peer, _, cleanup := newTestPeer(b, ServerOptions{
				Handler:              handler,
				MaxConcurrentStreams: 1024,
			})
			defer cleanup()

			pending := make(map[uint32]struct{}, concurrency)
			var streamID uint32 = 1

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				for range concurrency {
					block := encodeInPlace(
						peer,
						":method", "GET",
						":scheme", "https",
						":authority", "example.com",
						":path", "/",
					)
					if err := peer.framer.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      streamID,
						BlockFragment: block,
						EndHeaders:    true,
						EndStream:     true,
					}); err != nil {
						b.Fatalf("write HEADERS: %v", err)
					}
					pending[streamID] = struct{}{}
					streamID += 2
				}
				drainResponses(b, peer, pending)
			}
		})
	}
}

// drainResponses reads frames until every streamID in `pending` has
// completed (END_STREAM seen). Deletes entries as they finish. Sends
// WINDOW_UPDATE so the server isn't flow-controlled while concurrent handlers
// race against writeMu.
func drainResponses(b *testing.B, p *testPeer, pending map[uint32]struct{}) {
	b.Helper()
	for len(pending) > 0 {
		f, err := p.framer.ReadFrame()
		if err != nil {
			b.Fatalf("read frame: %v", err)
		}
		switch ff := f.(type) {
		case *http2.HeadersFrame:
			if ff.StreamEnded() {
				delete(pending, ff.StreamID)
			}
		case *http2.DataFrame:
			// Refill the conn-level send window so subsequent batches don't
			// stall on flow control. Server has already credited the stream
			// window in its own WINDOW_UPDATE handler, but we — the peer —
			// must credit the conn window for our incoming DATA bytes.
			if n := len(ff.Data()); n > 0 {
				_ = p.framer.WriteWindowUpdate(0, uint32(n))
				_ = p.framer.WriteWindowUpdate(ff.StreamID, uint32(n))
			}
			if ff.StreamEnded() {
				delete(pending, ff.StreamID)
			}
		case *http2.WindowUpdateFrame, *http2.SettingsFrame:
			// ignore
		case *http2.PingFrame:
			if !ff.IsAck() {
				if err := p.framer.WritePing(true, ff.Data); err != nil {
					b.Fatalf("write PING ACK: %v", err)
				}
			}
		default:
			b.Fatalf("unexpected frame %T", f)
		}
	}
}

// drainResponse reads frames from the peer until END_STREAM on streamID. It
// intentionally avoids decoding headers or copying body bytes so the peer-side
// overhead in the benchmark is minimal (just framer reads, which reuse
// internal buffers after warmup).
func drainResponse(b *testing.B, p *testPeer, streamID uint32) {
	b.Helper()
	for {
		f, err := p.framer.ReadFrame()
		if err != nil {
			b.Fatalf("read frame: %v", err)
		}
		switch ff := f.(type) {
		case *http2.HeadersFrame:
			if ff.StreamID == streamID && ff.StreamEnded() {
				return
			}
		case *http2.DataFrame:
			if ff.StreamID == streamID && ff.StreamEnded() {
				return
			}
		case *http2.WindowUpdateFrame, *http2.SettingsFrame:
			// ignore — flow-control / settings churn
		case *http2.PingFrame:
			// Benchmarks run for many seconds across scaling steps and may
			// exceed pingInterval (30s default). Ack inbound PINGs so the
			// server's liveness watchdog doesn't tear down the conn mid-bench.
			if !ff.IsAck() {
				if err := p.framer.WritePing(true, ff.Data); err != nil {
					b.Fatalf("write PING ACK: %v", err)
				}
			}
		default:
			b.Fatalf("unexpected frame %T", f)
		}
	}
}
