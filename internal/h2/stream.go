package h2

import (
	"context"
	"io"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
)

// streamPool pre-initialises cond and Header on first allocation so the hot
// acquire path never has to nil-check or allocate either.
var streamPool = sync.Pool{
	New: func() any {
		s := &Stream{}
		s.cond = sync.NewCond(&s.mu)
		s.Header = make(http.Header, 4)
		return s
	},
}

// Stream is the role-agnostic per-H2-stream state. Both worker and proxy use
// the same struct; only the surrounding lifecycle differs (worker spawns an
// http.Handler goroutine per peer-initiated stream, proxy creates streams as
// it forwards public requests outbound).
//
// All value fields are embedded to avoid per-request heap allocations when the
// stream is reused via the pool.
type Stream struct {
	// Ctx fires on RST_STREAM from peer, on conn teardown, and on graceful
	// shutdown so anything observing the stream (a handler, a forwarder
	// goroutine) can exit promptly. Cancel is non-nil for the stream's
	// lifetime.
	Ctx context.Context

	dataErr error // non-nil → Body.Read returns this error after draining queue

	cond *sync.Cond
	conn *Conn

	Cancel context.CancelFunc

	// Header is a per-stream reusable http.Header map. Worker side: response
	// headers being built by the handler. Proxy side: response headers
	// received from the peer. Cleared on acquire, preserved across pool
	// roundtrips so the map allocation is one-shot per stream slot.
	Header http.Header

	body bodyReader

	// Queue is the inbound DATA-frame chunk ring. PushData appends to the
	// tail; bodyReader.Read consumes from qHead. We never shift elements
	// (which is O(n)); when qHead grows past half the slice we compact lazily.
	queue []DataChunk
	qHead int

	mu sync.Mutex

	// SendWindow is the peer's flow control credit for this stream.
	// Initialised from peer's SETTINGS_INITIAL_WINDOW_SIZE; consumed by the
	// write path under Conn.Send.mu; refilled by peer WINDOW_UPDATE frames.
	SendWindow int32
	ID         uint32
	dataDone   bool
}

// Acquire pulls a Stream from the pool and initialises it for a fresh
// request/response. The caller wires the stream into its conn registry.
func Acquire(id uint32, conn *Conn, initialWindow int32) *Stream {
	s, _ := streamPool.Get().(*Stream)
	s.ID = id
	s.conn = conn
	s.queue = s.queue[:0]
	s.qHead = 0
	s.dataDone = false
	s.dataErr = nil
	s.SendWindow = initialWindow
	clear(s.Header)
	s.Ctx, s.Cancel = context.WithCancel(context.Background())
	s.body = bodyReader{stream: s}
	return s
}

// Release returns the stream to the pool. Cancels Ctx, drains and returns any
// queued DATA buffers, and zeroes out non-pool-survivable state.
func Release(s *Stream) {
	if s.Cancel != nil {
		s.Cancel()
		s.Ctx = nil
		s.Cancel = nil
	}
	s.body.returnBuf()
	for i := s.qHead; i < len(s.queue); i++ {
		if bp := s.queue[i].Bp; bp != nil {
			PutDataSlice(bp)
		}
		s.queue[i] = DataChunk{}
	}
	s.queue = s.queue[:0]
	s.qHead = 0
	s.conn = nil
	s.dataErr = nil
	// Preserve Header (cleared on acquire) so the per-stream map survives
	// the pool roundtrip and never re-allocates.
	streamPool.Put(s)
}

// Conn returns the connection this stream belongs to.
func (s *Stream) Conn() *Conn { return s.conn }

// Body returns the request/response body reader for this stream. The reader
// emits the bytes pushed by PushData in order, then EOF (or the failBody
// error). Safe to call once.
func (s *Stream) Body() io.ReadCloser { return &s.body }

// PushData is called by the frame-reading goroutine on inbound DATA. Non-
// blocking append.
//
// Signal is intentionally outside the lock: append happened under s.mu, so by
// the time any concurrent reader acquires the lock it either sees the new
// element (no Wait) or is already parked in Wait (and will be woken). Moving
// Signal into the critical section would only widen the lock for no gain.
func (s *Stream) PushData(chunk DataChunk) {
	s.mu.Lock()
	s.queue = append(s.queue, chunk)
	s.mu.Unlock()
	s.cond.Signal()
}

// CloseData signals end-of-body to the body reader. Idempotent.
func (s *Stream) CloseData() {
	s.mu.Lock()
	s.dataDone = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

// FailBody marks the body as failed with err — any pending Read returns err
// after draining whatever was already queued. Used on conn teardown and on
// RST_STREAM from the peer so the handler exits promptly instead of stalling
// on the queue cond. Also cancels Ctx so a handler doing a downstream call
// observes the failure even if it isn't currently in Read.
func (s *Stream) FailBody(err error) {
	s.mu.Lock()
	if s.dataErr == nil {
		s.dataErr = err
	}
	s.dataDone = true
	cancel := s.Cancel
	s.mu.Unlock()
	s.cond.Broadcast()
	if cancel != nil {
		cancel()
	}
}

// DataDone returns true once CloseData or FailBody has been called for this
// stream. Used by the worker frame loop to decide whether to emit
// RST_STREAM(NO_ERROR) after the handler returns without consuming the body.
func (s *Stream) DataDone() bool {
	s.mu.Lock()
	v := s.dataDone
	s.mu.Unlock()
	return v
}

// Reset emits an RST_STREAM with the given error code. Best-effort — if the
// connection is already broken the writer goroutine drops the intent.
func (s *Stream) Reset(code http2.ErrCode) {
	s.conn.SendRSTStream(s.ID, code)
}

// bodyReader reads inbound DATA from a stream's mutex+cond queue.
type bodyReader struct {
	stream *Stream
	bp     *[]byte // pool handle of current chunk
	buf    []byte  // remaining bytes from current chunk
}

func (r *bodyReader) Read(p []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		if len(r.buf) == 0 {
			r.returnBuf()
		}
		return n, nil
	}

	s := r.stream
	s.mu.Lock()
	for s.qHead == len(s.queue) && !s.dataDone {
		s.cond.Wait()
	}
	if s.qHead == len(s.queue) {
		err := s.dataErr
		s.mu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	chunk := s.queue[s.qHead]
	s.queue[s.qHead] = DataChunk{}
	s.qHead++
	// Compact lazily once the slice is mostly drained so the backing array
	// doesn't grow unbounded across a long stream of small DATA frames.
	if s.qHead > 8 && s.qHead*2 >= len(s.queue) {
		n := copy(s.queue, s.queue[s.qHead:])
		s.queue = s.queue[:n]
		s.qHead = 0
	}
	s.mu.Unlock()

	r.bp = chunk.Bp
	n := copy(p, chunk.Data)
	if n < len(chunk.Data) {
		r.buf = chunk.Data[n:]
	} else {
		r.returnBuf()
	}
	return n, nil
}

func (r *bodyReader) returnBuf() {
	if r.bp != nil {
		PutDataSlice(r.bp)
		r.bp = nil
	}
}

func (r *bodyReader) Close() error {
	r.returnBuf()
	s := r.stream
	s.mu.Lock()
	for i := s.qHead; i < len(s.queue); i++ {
		if bp := s.queue[i].Bp; bp != nil {
			PutDataSlice(bp)
		}
		s.queue[i] = DataChunk{}
	}
	s.queue = s.queue[:0]
	s.qHead = 0
	s.mu.Unlock()
	return nil
}
