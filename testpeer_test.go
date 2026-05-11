package rhttp

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// testPeer drives the "HAProxy side" of a reverse-http connection in tests.
// rhttp's serve() runs on one end of a loopback TCP pair; testPeer holds the
// other end and provides helpers to read/write H2 frames as the peer.
//
// Usage:
//
//	peer, _, cleanup := newTestPeer(t, ServerOptions{Handler: ...})
//	defer cleanup()
//	peer.sendHeaders(1, ":method", "GET", ":path", "/")
//	frame := peer.readFrame()
//	...
type testPeer struct {
	t      testing.TB
	conn   net.Conn
	framer *http2.Framer

	// HPACK codecs for the peer side. enc is used for outgoing HEADERS;
	// dec is used to decode HEADERS coming back from rhttp.
	enc    *hpack.Encoder
	encBuf bytes.Buffer
	dec    *hpack.Decoder

	// errCh receives serve()'s final error when rhttp exits.
	errCh   <-chan error
	serverC *connection
}

// newTestPeer creates an in-process TCP pair, starts rhttp's serve loop on one
// end, and returns a testPeer that owns the other end. The returned cleanup
// function closes both ends and waits for serve() to exit.
//
// The handshake is completed synchronously inside this function — by the time
// it returns, both sides have exchanged SETTINGS+ACKs and the peer is ready to
// send request frames.
func newTestPeer(t testing.TB, opts ServerOptions) (*testPeer, *connection, func()) {
	return newTestPeerShutdown(t, opts, nil)
}

// newTestPeerShutdown is newTestPeer with an optional shutdownCh wired into
// the server-side connection before serve starts. Tests that need to drive
// the Pool-style graceful shutdown path use this entrypoint.
func newTestPeerShutdown(t testing.TB, opts ServerOptions, shutdownCh <-chan struct{}) (*testPeer, *connection, func()) {
	t.Helper()
	if opts.Handler == nil {
		opts.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	// Loopback TCP pair gives both sides independent kernel send/recv buffers
	// — much friendlier than net.Pipe for tests that produce a few KB of
	// frame data before reading back.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		acceptCh <- acceptResult{c, err}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ar := <-acceptCh
	if ar.err != nil {
		t.Fatalf("accept: %v", ar.err)
	}
	_ = ln.Close()

	// clientConn is the rhttp side (it sent the preface as if it had dialed
	// out to the HAProxy gateway); ar.conn is the peer/gateway side.
	readyCh := make(chan struct{})
	serverC, errCh, err := startConnection(clientConn, opts, readyCh, shutdownCh)
	if err != nil {
		t.Fatalf("startConnection: %v", err)
	}

	peer := &testPeer{
		t:       t,
		conn:    ar.conn,
		framer:  http2.NewFramer(ar.conn, ar.conn),
		dec:     hpack.NewDecoder(4096, nil),
		errCh:   errCh,
		serverC: serverC,
	}
	peer.enc = hpack.NewEncoder(&peer.encBuf)

	peer.handshake()
	// Wait for serve to enter its main loop. startConnection's serve goroutine
	// closes readyCh after processing the peer's first SETTINGS frame.
	select {
	case <-readyCh:
	case <-time.After(2 * time.Second):
		t.Fatal("rhttp serve did not become ready within 2s")
	}

	cleanup := func() {
		_ = ar.conn.Close()
		_ = clientConn.Close()
		// Wait for serve to exit but don't fail the test on its error — most
		// tests deliberately close the conn to end the loop.
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
	}
	return peer, serverC, cleanup
}

// handshake drains rhttp's preface + initial SETTINGS, sends our SETTINGS, and
// reads rhttp's ACK of our SETTINGS. Mirrors what a gateway would do.
func (p *testPeer) handshake() {
	p.t.Helper()

	// 1. Read the H2 client preface that rhttp wrote in startConnection.
	pref := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(p.conn, pref); err != nil {
		p.t.Fatalf("read preface: %v", err)
	}
	if string(pref) != http2.ClientPreface {
		p.t.Fatalf("bad preface: %q", pref)
	}

	// 2. Read rhttp's SETTINGS frame.
	f := p.readFrame()
	if _, ok := f.(*http2.SettingsFrame); !ok {
		p.t.Fatalf("expected SETTINGS from rhttp, got %T", f)
	}

	// 3. Send our SETTINGS. Tests can override per-test by calling
	//    sendSettings explicitly before this point isn't possible, but they
	//    can issue further SETTINGS later.
	if err := p.framer.WriteSettings(); err != nil {
		p.t.Fatalf("write SETTINGS: %v", err)
	}

	// 4. ACK rhttp's SETTINGS.
	if err := p.framer.WriteSettingsAck(); err != nil {
		p.t.Fatalf("write SETTINGS ACK: %v", err)
	}

	// 5. Read rhttp's ACK of our SETTINGS (serve writes one before
	//    closing readyCh).
	f = p.readFrame()
	sf, ok := f.(*http2.SettingsFrame)
	if !ok || !sf.IsAck() {
		p.t.Fatalf("expected SETTINGS ACK, got %T (ack=%v)", f, ok && sf.IsAck())
	}
}

// readFrame blocks until the next frame from rhttp arrives, then returns it.
// On error or EOF, fails the test.
func (p *testPeer) readFrame() http2.Frame {
	p.t.Helper()
	f, err := p.framer.ReadFrame()
	if err != nil {
		p.t.Fatalf("readFrame: %v", err)
	}
	return f
}

// readFrameWithin is readFrame with a deadline; on timeout returns nil rather
// than failing. Useful for tests that assert "no frame arrives in N ms".
func (p *testPeer) readFrameWithin(d time.Duration) http2.Frame {
	p.t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(d))
	defer p.conn.SetReadDeadline(time.Time{})
	f, err := p.framer.ReadFrame()
	if err != nil {
		return nil
	}
	return f
}

// encodeHeaders HPACK-encodes name/value pairs into a header block fragment.
// Names are emitted as-is (lowercase per HPACK convention).
func (p *testPeer) encodeHeaders(kv ...string) []byte {
	p.t.Helper()
	if len(kv)%2 != 0 {
		p.t.Fatalf("encodeHeaders needs even args, got %d", len(kv))
	}
	p.encBuf.Reset()
	for i := 0; i < len(kv); i += 2 {
		_ = p.enc.WriteField(hpack.HeaderField{Name: kv[i], Value: kv[i+1]})
	}
	out := make([]byte, p.encBuf.Len())
	copy(out, p.encBuf.Bytes())
	return out
}

// sendHeaders sends a complete HEADERS frame (END_HEADERS=true) with the
// given pseudo+regular headers and the supplied END_STREAM flag.
func (p *testPeer) sendHeaders(streamID uint32, endStream bool, kv ...string) {
	p.t.Helper()
	block := p.encodeHeaders(kv...)
	if err := p.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     endStream,
	}); err != nil {
		p.t.Fatalf("write HEADERS: %v", err)
	}
}

// sendHeadersNoEnd sends HEADERS with END_HEADERS=false so a CONTINUATION
// frame is required to complete the block. The header block is split at the
// given byte offset; both pieces share the same stream id.
func (p *testPeer) sendHeadersNoEnd(streamID uint32, endStream bool, splitAt int, kv ...string) {
	p.t.Helper()
	block := p.encodeHeaders(kv...)
	if splitAt < 0 || splitAt > len(block) {
		splitAt = len(block) / 2
	}
	if err := p.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block[:splitAt],
		EndHeaders:    false,
		EndStream:     endStream,
	}); err != nil {
		p.t.Fatalf("write HEADERS (no END_HEADERS): %v", err)
	}
	if err := p.framer.WriteContinuation(streamID, true, block[splitAt:]); err != nil {
		p.t.Fatalf("write CONTINUATION: %v", err)
	}
}

// sendData writes a DATA frame on the given stream.
func (p *testPeer) sendData(streamID uint32, endStream bool, data []byte) {
	p.t.Helper()
	if err := p.framer.WriteData(streamID, endStream, data); err != nil {
		p.t.Fatalf("write DATA: %v", err)
	}
}

// decodeHeaders decodes a HEADERS frame's block fragment using the peer's
// decoder (which is a separate state machine from rhttp's encoder).
func (p *testPeer) decodeHeaders(block []byte) map[string][]string {
	p.t.Helper()
	fields, err := p.dec.DecodeFull(block)
	if err != nil {
		p.t.Fatalf("hpack decode: %v", err)
	}
	out := make(map[string][]string)
	for _, hf := range fields {
		out[hf.Name] = append(out[hf.Name], hf.Value)
	}
	return out
}

// collectResponse reads frames from rhttp until it sees END_STREAM on the
// given stream, returning the status, header map, and concatenated body. Any
// other unexpected frame type fails the test.
func (p *testPeer) collectResponse(streamID uint32) (status int, headers map[string][]string, body []byte) {
	p.t.Helper()
	body = []byte{}
	for {
		f := p.readFrame()
		switch f := f.(type) {
		case *http2.HeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			headers = p.decodeHeaders(f.HeaderBlockFragment())
			if v := headers[":status"]; len(v) > 0 {
				for _, c := range v[0] {
					status = status*10 + int(c-'0')
				}
			}
			if f.StreamEnded() {
				return status, headers, body
			}
		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}
			body = append(body, f.Data()...)
			if f.StreamEnded() {
				return status, headers, body
			}
		case *http2.WindowUpdateFrame:
			// Ignore — rhttp emits these in response to inbound DATA we
			// haven't yet sent. Some tests deliberately assert on them, in
			// which case they use readFrame directly.
		case *http2.SettingsFrame:
			// Spurious SETTINGS shouldn't happen, but pass through.
		default:
			p.t.Fatalf("unexpected frame while collecting response: %T", f)
		}
	}
}

// once is a tiny helper to ensure a sync.Once-like guard for cleanup paths
// in tests. The standard library's sync.Once already does this; only used
// inside multi-step test fixtures.
var _ = sync.Once{}

// newTestPool constructs a minimal *Pool suitable for tests that call dial
// directly without going through NewConnectionPool. Initialises the fields
// dial / serve will touch (ready, shutdownCh, conns, maintainers) so the
// test goroutine doesn't NPE.
func newTestPool() *Pool {
	p := &Pool{
		ready:      &sync.WaitGroup{},
		shutdownCh: make(chan struct{}),
		conns:      make(map[*connection]struct{}),
	}
	p.ready.Add(1)
	p.maintainers.Add(1)
	return p
}
