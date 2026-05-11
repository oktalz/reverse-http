package proxy

import (
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/oktalz/reverse-http/internal/h2"
)

// Worker is one attached reverse-http tunnel. Each Worker owns a single
// *h2.Conn and presents a stream-multiplexed transport for outbound public
// requests. Created by the proxy's tunnel-accept loop; removed when the
// underlying connection dies.
type Worker struct {
	conn *h2.Conn

	// cert is the leaf client certificate the worker presented during mTLS
	// (if any). Selectors / hooks may inspect it for identity/labelling.
	cert *x509.Certificate

	// streams maps the proxy-issued stream ID to the proxy-side wrapper so
	// the frame reader can route response HEADERS/DATA/RST to the goroutine
	// blocked on the request. streamsMu also serialises NewStreamID +
	// SendRequestHeaders so the framer sees IDs in strictly ascending order
	// (RFC 7540 §5.1.1 — opening a stream with an ID ≤ the highest seen is
	// PROTOCOL_ERROR).
	streams map[uint32]*clientStream

	remote net.Addr

	// shutdownCh fires when the proxy is shutting down or the underlying
	// tunnel has died; outstanding forwarders observe it to abort cleanly.
	shutdownCh chan struct{}

	// shutdownOnce guards close(shutdownCh) since detach can race with
	// Proxy.Shutdown.
	shutdownOnce sync.Once

	streamsMu sync.Mutex

	// inFlight is the count of currently-forwarding requests. Selectors
	// read this; the request forwarder increments before opening a stream
	// and decrements when the stream finishes. atomic for lock-free reads.
	inFlight atomic.Int64
}

// RemoteAddr returns the worker's network address.
func (w *Worker) RemoteAddr() net.Addr { return w.remote }

// Certificate returns the leaf client cert the worker presented during mTLS,
// or nil if the tunnel TLS config didn't require / verify a client cert.
// Inspect Subject.CommonName, SANs, etc. for routing or audit.
func (w *Worker) Certificate() *x509.Certificate { return w.cert }

// InFlight returns the current number of outbound streams being forwarded
// through this worker. Safe for concurrent reads.
func (w *Worker) InFlight() int64 { return w.inFlight.Load() }

// done returns a channel closed once the worker has been detached. Used by
// forwarders to bail on a torn-down tunnel.
func (w *Worker) done() <-chan struct{} { return w.shutdownCh }

// detach signals every in-flight forwarder to exit. Idempotent.
func (w *Worker) detach() {
	w.shutdownOnce.Do(func() {
		close(w.shutdownCh)
	})
}

// deregisterStream removes id from the map. Called when the forwarder
// goroutine exits.
func (w *Worker) deregisterStream(id uint32) {
	w.streamsMu.Lock()
	delete(w.streams, id)
	w.streamsMu.Unlock()
}

// getStream looks up the proxy-side stream wrapper by stream id. Returns nil
// if the stream was already deregistered.
func (w *Worker) getStream(id uint32) *clientStream {
	w.streamsMu.Lock()
	cs := w.streams[id]
	w.streamsMu.Unlock()
	return cs
}

// failAllStreams notifies every in-flight forwarder that the tunnel is gone.
//
// Iterates under streamsMu rather than snapshot-and-release: a forwarder's
// defer (deregisterStream + h2.Release) racing between snapshot and fail
// would read freed state. cs.fail is fast (close chan, cancel ctx) and
// doesn't re-enter streamsMu, so holding the lock through the loop is safe.
func (w *Worker) failAllStreams(err error) {
	w.streamsMu.Lock()
	defer w.streamsMu.Unlock()
	for _, cs := range w.streams {
		cs.fail(err)
	}
}

// openStream allocates a new outbound stream ID, registers a fresh
// clientStream under it, and returns the wrapper. The caller is responsible
// for emitting the HEADERS frame via Worker.conn.SendRequestHeaders so the
// framer sees the stream id in ascending order — that's why we hold
// streamsMu across both ID assignment and HEADERS send.
//
// initialWindow is the peer's current SETTINGS_INITIAL_WINDOW_SIZE; threaded
// onto the stream's send window at acquisition.
func (w *Worker) openStream(initialWindow int32, sendHeaders func(streamID uint32) error) (*clientStream, error) {
	w.streamsMu.Lock()
	defer w.streamsMu.Unlock()
	id := w.conn.NextStreamID()
	s := h2.Acquire(id, w.conn, initialWindow)
	w.conn.AddStream(s)
	cs := &clientStream{
		h2:     s,
		respCh: make(chan struct{}),
		worker: w,
	}
	w.streams[id] = cs
	if err := sendHeaders(id); err != nil {
		// Roll back: remove from registries and release the stream.
		delete(w.streams, id)
		w.conn.RemoveStream(id)
		h2.Release(s)
		return nil, err
	}
	return cs, nil
}

// clientStream is the proxy-side wrapper over an h2.Stream that an in-flight
// request forwarder owns. Holds response state filled in by the tunnel frame
// reader when response HEADERS arrive.
type clientStream struct {
	respErr error

	h2     *h2.Stream
	worker *Worker

	// respCh is closed when response HEADERS have been received (or the
	// stream failed). The forwarder selects on it to begin streaming the
	// response body. Wait should only be called once per stream.
	respCh chan struct{}

	respHeader http.Header

	// Filled in by the tunnel frame loop before closing respCh. Read by the
	// forwarder after the select returns.
	respStatus int

	respOnce sync.Once
}

// deliverHeaders is called by the tunnel frame reader on response HEADERS.
// status/header are taken from the decoded block.
func (cs *clientStream) deliverHeaders(status int, header http.Header) {
	cs.respOnce.Do(func() {
		cs.respStatus = status
		cs.respHeader = header
		close(cs.respCh)
	})
}

// fail is called when the stream is torn down before (or after) response
// HEADERS arrived — RST_STREAM, GOAWAY, or tunnel teardown. Subsequent calls
// are no-ops.
func (cs *clientStream) fail(err error) {
	cs.respOnce.Do(func() {
		cs.respErr = err
		close(cs.respCh)
	})
	cs.h2.FailBody(err)
}
