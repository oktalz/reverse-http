package h2

import (
	"bytes"
	"encoding/binary"
	"maps"
	"net"
	"net/http"
	"net/textproto"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Conn is one HTTP/2 connection over a net.Conn (typically *tls.Conn). It
// owns the framer, HPACK codecs, writer goroutine, ping/liveness state, flow
// control, and stream registry. Frame *dispatch* is role-specific and lives
// in the worker or proxy frame loop, but every shared primitive (Send*,
// ApplyPeerSettings, HEADERS/CONTINUATION decode, SETTINGS handshake) is here.
type Conn struct {
	// PING liveness — touched only by the frame reader (SendOrCheckPing and
	// HandlePingAck both run in the same goroutine), so no mutex is needed.
	pingDeadline time.Time
	// Transport is the underlying net.Conn. Owned for the life of the
	// h2.Conn — closed by Close.
	Transport net.Conn

	// writeErr is the writer goroutine's exit error; valid once writeDeadCh
	// is closed.
	writeErr error

	// Framer is the H2 framer wrapping Conn. ReadFrame is called only from
	// the role-specific frame loop; Write* must go through the writer
	// goroutine via the Send* helpers (or submit{,Async}).
	Framer *http2.Framer

	// HPACK codecs. The encoder is owned by the writer goroutine and the
	// decoder by the frame reader — both are single-writer state, no lock.
	enc *hpack.Encoder
	dec *hpack.Decoder

	// scratchHeader is the in-flight http.Header during HEADERS/CONTINUATION
	// decode. Populated by emitHeader (the decoder's emit callback). Single-
	// threaded — only the frame reader touches it, and a single header block
	// decodes atomically before the next decode begins.
	scratchHeader http.Header

	// canonNames maps lowercase HPACK header names to the canonical form used
	// as http.Header keys. Populated lazily by the HPACK emit callback; pre-
	// seeded with the well-known names so the first request on the connection
	// doesn't trigger textproto.CanonicalMIMEHeaderKey allocations. Owned by
	// the frame reader — no lock.
	canonNames map[string]string

	// lowerNames maps canonical handler-set header names (e.g. "Content-Type")
	// to their lowercase wire form. Populated lazily during HEADERS encode in
	// the writer goroutine; pre-seeded with the well-known response headers.
	// Single-writer (the writer goroutine owns it), so no lock is needed.
	lowerNames map[string]string

	// streams is the per-conn stream registry. streamsMu guards inserts,
	// deletes, and snapshots.
	streams map[uint32]*Stream

	// writeQ feeds the single dedicated writer goroutine. All framer writes
	// go through this channel; the writer is the only goroutine that touches
	// Framer / enc / encBuf / lowerNames after start.
	writeQ        chan *writeIntent
	writeShutdown chan struct{} // closed by teardown to wake a parked writer
	writeDeadCh   chan struct{} // closed when the writer goroutine exits

	// Header-block scratch. Pseudo-headers are stored in dedicated fields
	// so the emit callback doesn't case-switch on string content per header.
	scratchMethod    string
	scratchPath      string
	scratchAuthority string
	scratchStatus    string

	// CONTINUATION accumulator. RFC 7540 §6.10 requires that a HEADERS frame
	// without END_HEADERS be followed immediately by CONTINUATION frame(s)
	// for the same stream until END_HEADERS is set; no other frames are
	// permitted in between. We hold the partial header block here.
	contBlock []byte

	// Send tracks send-side flow control: conn-level credit, the peer's
	// initial-window setting, the dead-state cond. Stream-level credit lives
	// on Stream.SendWindow.
	Send SendCredit

	encBuf bytes.Buffer

	pingCounter uint64

	streamsMu sync.Mutex

	// maxFrameSize is the peer's MAX_FRAME_SIZE — updated by the frame reader
	// in ApplyPeerSettings, read by the write path in chunked DATA sends.
	// atomic.Uint32 closes a race the detector flags under high concurrency.
	maxFrameSize atomic.Uint32

	// LastStreamID is the highest peer-initiated stream ID accepted. Used as
	// the last-stream-id value on the GOAWAY frame sent during teardown
	// (RFC 9113 §6.8). Owned by the frame reader.
	LastStreamID uint32

	// nextStreamID is the next outbound stream ID to assign when this side
	// initiates a stream (proxy role). Stays at 0 for the worker which
	// never initiates. Owned by whichever goroutine calls NextStreamID
	// (proxy serialises stream opens via a separate mutex).
	nextStreamID uint32

	contStreamID uint32 // 0 when not in continuation
	pingData     [8]byte
	pingPending  bool

	contStreamEnded bool // END_STREAM flag from the originating HEADERS frame
}

// New wraps an established net.Conn in a Conn. Does NOT write the H2 client
// preface — that's the caller's job (the worker writes it before this call;
// the proxy reads the peer's preface before this call). Starts the writer
// goroutine and writes the initial SETTINGS frame.
func New(rwc net.Conn, maxConcurrentStreams uint32) (*Conn, error) {
	framer := http2.NewFramer(rwc, rwc)
	// Explicit read-frame cap. 16 KB is also x/net/http2's default, but
	// stating it here documents intent: we will refuse oversized frames
	// rather than buffer up to the protocol max of 16 MiB.
	framer.SetMaxReadFrameSize(16384)

	if maxConcurrentStreams == 0 {
		maxConcurrentStreams = DefaultMaxConcurrentStreams
	}
	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: maxConcurrentStreams},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: MaxHeaderListSize},
	); err != nil {
		return nil, err
	}

	c := &Conn{
		Transport:  rwc,
		Framer:     framer,
		dec:        hpack.NewDecoder(4096, nil),
		streams:    make(map[uint32]*Stream),
		canonNames: make(map[string]string, len(CommonCanonNames)+8),
		lowerNames: make(map[string]string, len(CommonLowerNames)+8),
	}
	c.maxFrameSize.Store(16384)
	maps.Copy(c.canonNames, CommonCanonNames)
	maps.Copy(c.lowerNames, CommonLowerNames)
	c.enc = hpack.NewEncoder(&c.encBuf)
	c.dec.SetEmitFunc(c.emitHeader)
	c.Send.ConnSendWindow = DefaultInitialWindow
	c.Send.PeerInitWindow = DefaultInitialWindow

	c.startWriter()
	return c, nil
}

// Close closes the underlying transport. The writer goroutine must already
// have been shut down (via ShutdownWriter) before calling — otherwise its
// next write may race with the conn close.
func (c *Conn) Close() error { return c.Transport.Close() }

// SetReadDeadline forwards to the underlying transport. Exposed so the
// pool-level shutdown path can wake a blocked frame reader by setting a
// past deadline.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.Transport.SetReadDeadline(t) }

// MaxFrameSize returns the peer's currently advertised SETTINGS_MAX_FRAME_SIZE.
// Used by the write path to chunk DATA payloads.
func (c *Conn) MaxFrameSize() uint32 {
	v := c.maxFrameSize.Load()
	if v == 0 {
		return 16384
	}
	return v
}

// NextStreamID returns the next outbound stream ID for this side. Used only
// by the proxy (which initiates streams toward workers); odd-numbered per
// RFC 7540 §5.1.1 because the proxy holds the H2 *client* role at the wire
// level after the worker sends the preface.
//
// In reverse-http the semantic roles are inverted relative to the wire roles:
// the side that sends the preface (worker) acts as the H2 *server* (responds
// to streams), while the side that accepts the preface (proxy) acts as the
// H2 *client* (initiates streams). Per RFC, the H2 *client* uses odd stream
// IDs.
func (c *Conn) NextStreamID() uint32 {
	if c.nextStreamID == 0 {
		c.nextStreamID = 1
	} else {
		c.nextStreamID += 2
	}
	return c.nextStreamID
}

// ---- stream registry ------------------------------------------------------

// AddStream registers s under its ID. Safe under streamsMu.
func (c *Conn) AddStream(s *Stream) {
	c.streamsMu.Lock()
	c.streams[s.ID] = s
	c.streamsMu.Unlock()
}

// GetStream returns the stream registered for id, or nil.
func (c *Conn) GetStream(id uint32) *Stream {
	c.streamsMu.Lock()
	s := c.streams[id]
	c.streamsMu.Unlock()
	return s
}

// RemoveStream deregisters id from the conn's stream map.
func (c *Conn) RemoveStream(id uint32) {
	c.streamsMu.Lock()
	delete(c.streams, id)
	c.streamsMu.Unlock()
}

// ActiveStreams returns the current number of registered streams. Exposed
// for tests that assert the stream registry drains.
func (c *Conn) ActiveStreams() int {
	c.streamsMu.Lock()
	n := len(c.streams)
	c.streamsMu.Unlock()
	return n
}

// FailAllStreams notifies every active stream that the conn is gone, so any
// goroutine blocked on Body.Read or on the send-credit cond exits with an
// error instead of hanging forever.
//
// Iterates under streamsMu rather than snapshot-and-release. Reason: a
// per-stream handler goroutine's defer calls RemoveStream + Release, which
// zeroes the Stream's fields. If FailAllStreams snapshotted outside the
// lock, a Release racing between snapshot and FailBody would read freed
// state. Holding the lock blocks RemoveStream until every FailBody is done.
// FailBody itself is fast (set dataErr, broadcast, cancel ctx) and doesn't
// re-enter streamsMu, so this widening is safe.
func (c *Conn) FailAllStreams(err error) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	for _, s := range c.streams {
		s.FailBody(err)
	}
}

// activeStreamWindows returns a snapshot of pointers to every live stream's
// SendWindow. Used by ApplyPeerSettings to apply an INITIAL_WINDOW_SIZE delta
// to every existing stream atomically.
func (c *Conn) activeStreamWindows() []*int32 {
	c.streamsMu.Lock()
	out := make([]*int32, 0, len(c.streams))
	for _, s := range c.streams {
		out = append(out, &s.SendWindow)
	}
	c.streamsMu.Unlock()
	return out
}

// ---- PING liveness --------------------------------------------------------

// SendOrCheckPing implements the read-idle watchdog: on the first idle tick,
// emit a PING with a freshly-generated opaque payload and arm a deadline; on
// subsequent ticks where a PING is still outstanding, treat an expired
// deadline as a dead connection.
//
// All ping state (pingPending, pingData, pingCounter, pingDeadline) is
// touched only from the frame reader goroutine — both this function and
// HandlePingAck — so no mutex is required.
func (c *Conn) SendOrCheckPing() error {
	if c.pingPending {
		if time.Now().After(c.pingDeadline) {
			return ErrPingTimeout
		}
		return nil
	}
	c.pingCounter++
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], c.pingCounter)
	c.pingPending = true
	c.pingData = data
	c.pingDeadline = time.Now().Add(PingTimeout)
	c.SendPing(false, data)
	return nil
}

// HandlePingAck clears the outstanding PING if its opaque payload matches.
// Mismatched ACKs are ignored (could be from a peer-initiated PING reply).
func (c *Conn) HandlePingAck(data [8]byte) {
	if c.pingPending && c.pingData == data {
		c.pingPending = false
	}
}

// ---- SETTINGS -------------------------------------------------------------

// ApplyPeerSettings reads relevant settings from a non-ACK SETTINGS frame
// and validates them against RFC 9113 §6.5.2:
//   - MAX_FRAME_SIZE: [16384, 16777215]; out-of-range → PROTOCOL_ERROR.
//   - INITIAL_WINDOW_SIZE: ≤ 2^31-1; larger → FLOW_CONTROL_ERROR. Adjusts
//     every existing stream's send window by the delta per §6.9.2.
//   - HEADER_TABLE_SIZE: bounds the HPACK encoder's dynamic table.
//   - ENABLE_PUSH: only 0 or 1 is legal; non-binary → PROTOCOL_ERROR.
func (c *Conn) ApplyPeerSettings(f *http2.SettingsFrame) error {
	return f.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingMaxFrameSize:
			if s.Val < 16384 || s.Val > 16777215 {
				return ErrBadSettings
			}
			c.maxFrameSize.Store(s.Val)
		case http2.SettingInitialWindowSize:
			if s.Val > 1<<31-1 {
				return ErrBadSettings
			}
			windows := c.activeStreamWindows()
			c.Send.ApplyInitialWindowDelta(int32(s.Val), windows)
		case http2.SettingHeaderTableSize:
			// The encoder is owned by the writer goroutine; route the size
			// change through the queue so it lands in-order with respect to
			// pending HEADERS frames.
			c.SendSetMaxDynamicTableSize(s.Val)
		case http2.SettingEnablePush:
			if s.Val > 1 {
				return ErrBadSettings
			}
		}
		return nil
	})
}

// ---- HEADERS / CONTINUATION decode ----------------------------------------

// DecodedHeaders carries the result of a complete HEADERS+CONTINUATION decode.
// The role-specific frame loop builds an http.Request (worker) or an
// http.Response (proxy) from it.
type DecodedHeaders struct {
	Header    http.Header
	Method    string
	Path      string
	Authority string
	Status    string
	StreamID  uint32
	EndStream bool
}

// StartHeaders begins processing a HEADERS frame. If END_HEADERS is set, the
// header block is decoded and DecodedHeaders is returned. Otherwise the
// partial block is held in connection state and completed by subsequent
// CONTINUATION frames; nil is returned with err nil — the caller continues
// reading frames and feeding ConsumeContinuation.
func (c *Conn) StartHeaders(f *http2.HeadersFrame) (*DecodedHeaders, error) {
	if f.StreamID > c.LastStreamID {
		c.LastStreamID = f.StreamID
	}
	if f.HeadersEnded() {
		return c.decodeBlock(f.StreamID, f.HeaderBlockFragment(), f.StreamEnded())
	}
	c.contStreamID = f.StreamID
	c.contStreamEnded = f.StreamEnded()
	c.contBlock = append(c.contBlock[:0], f.HeaderBlockFragment()...)
	return nil, nil
}

// InContinuation returns true when a HEADERS-without-END_HEADERS is in flight
// and only CONTINUATION frames for ContStreamID may follow.
func (c *Conn) InContinuation() bool {
	return c.contStreamID != 0
}

// ContStreamID returns the stream the current CONTINUATION sequence belongs
// to. Used by the role-specific frame loop to reject interleaved frames per
// RFC 7540 §6.10.
func (c *Conn) ContStreamID() uint32 { return c.contStreamID }

// ConsumeContinuation appends a CONTINUATION fragment to the accumulator
// and, when END_HEADERS arrives, decodes and returns the full block.
//
// Enforces MaxHeaderListSize against the *compressed* fragment length — a
// loose proxy for the post-decompression header list, but sufficient to stop
// a peer streaming CONTINUATION as a memory-exhaustion attack.
func (c *Conn) ConsumeContinuation(f *http2.ContinuationFrame) (*DecodedHeaders, error) {
	frag := f.HeaderBlockFragment()
	if uint32(len(c.contBlock))+uint32(len(frag)) > MaxHeaderListSize {
		return nil, ErrHeaderListTooLarge
	}
	c.contBlock = append(c.contBlock, frag...)
	if !f.HeadersEnded() {
		return nil, nil
	}
	streamID := c.contStreamID
	ended := c.contStreamEnded
	block := c.contBlock
	c.contStreamID = 0
	c.contStreamEnded = false
	c.contBlock = c.contBlock[:0]
	return c.decodeBlock(streamID, block, ended)
}

func (c *Conn) decodeBlock(streamID uint32, block []byte, streamEnded bool) (*DecodedHeaders, error) {
	header, _ := HeaderPool.Get().(http.Header)
	clear(header)

	c.scratchMethod = ""
	c.scratchPath = ""
	c.scratchAuthority = ""
	c.scratchStatus = ""
	c.scratchHeader = header

	if _, err := c.dec.Write(block); err != nil {
		c.scratchHeader = nil
		HeaderPool.Put(header)
		return nil, ErrHpackDecode
	}
	if err := c.dec.Close(); err != nil {
		c.scratchHeader = nil
		HeaderPool.Put(header)
		return nil, ErrHpackDecode
	}

	out := &DecodedHeaders{
		StreamID:  streamID,
		Method:    c.scratchMethod,
		Path:      c.scratchPath,
		Authority: c.scratchAuthority,
		Status:    c.scratchStatus,
		Header:    header,
		EndStream: streamEnded,
	}
	c.scratchHeader = nil
	return out, nil
}

// emitHeader is the HPACK decoder's emit callback. Bound once in New and
// invoked from within dec.Write during decodeBlock. Writes into the per-
// connection scratch fields (single-threaded use from the frame reader).
func (c *Conn) emitHeader(hf hpack.HeaderField) {
	switch hf.Name {
	case ":method":
		c.scratchMethod = hf.Value
	case ":path":
		c.scratchPath = hf.Value
	case ":authority":
		c.scratchAuthority = hf.Value
	case ":status":
		c.scratchStatus = hf.Value
	case ":scheme":
		// Ignore — neither worker nor proxy needs it.
	default:
		canon, ok := c.canonNames[hf.Name]
		if !ok {
			canon = textproto.CanonicalMIMEHeaderKey(hf.Name)
			c.canonNames[hf.Name] = canon
		}
		c.scratchHeader[canon] = append(c.scratchHeader[canon], hf.Value)
	}
}

// ---- write-side helpers used by frame readers -----------------------------

// HandleInboundData applies the conn-level + stream-level WINDOW_UPDATE
// refills mandated by RFC 9113 §6.9 and queues the bytes on the matching
// stream's body queue. If no stream is registered for streamID we emit
// RST_STREAM(STREAM_CLOSED) instead.
func (c *Conn) HandleInboundData(streamID uint32, data []byte, endStream bool) {
	n := uint32(len(data))
	s := c.GetStream(streamID)
	if n > 0 {
		c.SendWindowUpdate(0, n)
		if s != nil {
			c.SendWindowUpdate(streamID, n)
		}
	}
	if s == nil {
		if n > 0 {
			c.SendRSTStream(streamID, http2.ErrCodeStreamClosed)
		}
		return
	}
	if len(data) > 0 {
		buf, bp := GetDataSlice(len(data))
		copy(buf, data)
		s.PushData(DataChunk{Data: buf, Bp: bp})
	}
	if endStream {
		s.CloseData()
	}
}

// HandleWindowUpdate applies a WINDOW_UPDATE to either the conn-level or
// per-stream send window.
func (c *Conn) HandleWindowUpdate(streamID uint32, inc int32) {
	if streamID == 0 {
		c.Send.AddConn(inc)
		return
	}
	if s := c.GetStream(streamID); s != nil {
		c.Send.AddStream(&s.SendWindow, inc)
	}
}

// HandleRSTStream fails the matching stream's body with ErrStreamReset.
func (c *Conn) HandleRSTStream(streamID uint32) {
	if s := c.GetStream(streamID); s != nil {
		s.FailBody(ErrStreamReset)
	}
}

// ---- Read deadline helpers ------------------------------------------------

// SetIdleDeadline arms a read deadline pingInterval into the future. The
// frame reader uses this to detect read silence and trigger SendOrCheckPing.
func (c *Conn) SetIdleDeadline() {
	_ = c.Transport.SetReadDeadline(time.Now().Add(PingInterval))
}

// IsNetTimeout reports whether err is a net.Error timeout (so the caller can
// distinguish the read-idle deadline from a real I/O failure).
func IsNetTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}
