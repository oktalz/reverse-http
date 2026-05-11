package h2

import (
	"sync"
	"time"
)

// Per RFC 7540 §6.9.2, both the connection and each stream begin with a flow
// control window of 65535. SETTINGS_INITIAL_WINDOW_SIZE only affects per-stream
// windows; the conn-level window stays at the spec default until WINDOW_UPDATE.
const DefaultInitialWindow int32 = 65535

// PingInterval is how long the frame reader waits in read-idle before
// emitting a PING. PingTimeout is how long it then waits for the PONG before
// declaring the connection dead. Declared as vars (rather than consts) so
// tests can shorten them.
var (
	PingInterval = 30 * time.Second
	PingTimeout  = 15 * time.Second
)

// SendCredit tracks how many bytes the peer has authorised us to send. There is
// one conn-level credit pool (ConnSendWindow) on the connection and one per
// stream (Stream.SendWindow); both must have positive credit before a DATA
// frame can be emitted, and a frame consumes from both. Updated by peer
// WINDOW_UPDATE frames and (for streams) by SETTINGS_INITIAL_WINDOW_SIZE
// deltas.
//
// All fields live behind mu so a peer can adjust the per-stream initial
// window for every active stream atomically with respect to in-flight writes.
type SendCredit struct {
	cond           *sync.Cond // initialised lazily; wakes writers when credit grows or conn dies
	mu             sync.Mutex
	ConnSendWindow int32 // conn-level credit towards peer
	PeerInitWindow int32 // most recent SETTINGS_INITIAL_WINDOW_SIZE from peer; default 65535
	dead           bool  // set on conn teardown to release all waiters with an error
}

func (sc *SendCredit) initCond() {
	if sc.cond == nil {
		sc.cond = sync.NewCond(&sc.mu)
	}
}

// Reserve waits for both conn and stream credit, then deducts up to want bytes
// from both windows. Returns the number of bytes the caller may now emit, or
// (0, true) if the connection has been torn down while waiting.
func (sc *SendCredit) Reserve(streamWindow *int32, want int32) (got int32, dead bool) {
	if want <= 0 {
		return 0, false
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.initCond()
	for {
		if sc.dead {
			return 0, true
		}
		avail := min(*streamWindow, sc.ConnSendWindow)
		if avail > 0 {
			if want < avail {
				avail = want
			}
			sc.ConnSendWindow -= avail
			*streamWindow -= avail
			return avail, false
		}
		sc.cond.Wait()
	}
}

// AddConn grows the conn-level send window by delta and wakes any blocked
// writers. Called when the peer sends a connection-level WINDOW_UPDATE.
func (sc *SendCredit) AddConn(delta int32) {
	sc.mu.Lock()
	sc.ConnSendWindow += delta
	if sc.cond != nil {
		sc.cond.Broadcast()
	}
	sc.mu.Unlock()
}

// AddStream grows the given stream's send window and wakes blocked writers.
// Called when the peer sends a stream-level WINDOW_UPDATE.
func (sc *SendCredit) AddStream(streamWindow *int32, delta int32) {
	sc.mu.Lock()
	*streamWindow += delta
	if sc.cond != nil {
		sc.cond.Broadcast()
	}
	sc.mu.Unlock()
}

// ApplyInitialWindowDelta is invoked when the peer's SETTINGS frame changes
// SETTINGS_INITIAL_WINDOW_SIZE. Per RFC 7540 §6.9.2, every existing stream's
// flow control window must be adjusted by the delta (new - old). The caller
// owns the slice of active stream send-window pointers.
func (sc *SendCredit) ApplyInitialWindowDelta(newSize int32, streamWindows []*int32) {
	sc.mu.Lock()
	delta := newSize - sc.PeerInitWindow
	sc.PeerInitWindow = newSize
	if delta != 0 {
		for _, sw := range streamWindows {
			*sw += delta
		}
		if sc.cond != nil {
			sc.cond.Broadcast()
		}
	}
	sc.mu.Unlock()
}

// InitialStreamWindow returns the current value of the peer's
// SETTINGS_INITIAL_WINDOW_SIZE, used to initialise newly-accepted streams.
func (sc *SendCredit) InitialStreamWindow() int32 {
	sc.mu.Lock()
	v := sc.PeerInitWindow
	sc.mu.Unlock()
	return v
}

// MarkDead wakes every blocked writer with a "conn dead" return, so handlers
// streaming responses can observe the failure instead of stalling on the cond.
func (sc *SendCredit) MarkDead() {
	sc.mu.Lock()
	sc.dead = true
	if sc.cond != nil {
		sc.cond.Broadcast()
	}
	sc.mu.Unlock()
}
