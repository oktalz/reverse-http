package h2

import (
	"net/http"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// All framer writes are funnelled through a single dedicated writer goroutine
// per connection, draining a buffered channel of writeIntent values. This
// eliminates writeMu contention that, under c=16 concurrent streams, the
// mutex profile showed costing ~30% of per-request latency.
//
// Trade-off: each frame write now requires a channel send + a goroutine
// wakeup instead of a mutex Lock/Unlock pair, so the uncontended single-
// stream path pays ~300 ns extra per frame. The crossover point with the
// previous mutex-based implementation is around c=2 in our benchmark; above
// that, the writer-goroutine design wins.

// writeKind identifies what kind of write an intent represents. Fields on
// writeIntent are mutually exclusive per kind — fields not relevant to the
// kind are ignored by the writer.
type writeKind uint8

const (
	wkSettingsAck writeKind = iota
	wkWindowUpdate
	wkPing
	wkRSTStream
	wkRespHeaders // status-only headers (worker response)
	wkReqHeaders  // method/path/authority headers (proxy outbound request)
	wkData
	wkSetMaxDynTab
	wkGoAway
)

// writeIntent is the unit of work submitted to the writer goroutine. Pooled
// to keep the hot path allocation-free.
type writeIntent struct {
	header    http.Header // wkRespHeaders / wkReqHeaders
	done      chan error  // nil = fire-and-forget; pooled buffered chan of cap 1
	method    string      // wkReqHeaders
	path      string      // wkReqHeaders
	authority string      // wkReqHeaders
	scheme    string      // wkReqHeaders
	data      []byte      // wkData
	status    int         // wkRespHeaders
	streamID  uint32
	increment uint32 // wkWindowUpdate
	val       uint32 // wkSetMaxDynTab
	code      http2.ErrCode
	pingData  [8]byte
	kind      writeKind
	isAck     bool // wkPing
	endStream bool // wkRespHeaders / wkReqHeaders / wkData
}

// writeQSize sits between "deep enough to absorb bursts" and "shallow enough
// that backpressure is felt before queue depth becomes pathological". 256 is
// well above the typical MaxConcurrentStreams default.
const writeQSize = 256

var intentPool = sync.Pool{
	New: func() any { return &writeIntent{} },
}

var donePool = sync.Pool{
	// Buffered cap=1 so the writer's send-on-done never blocks even if the
	// submitter has already given up (e.g., after detecting writeDeadCh).
	New: func() any { return make(chan error, 1) },
}

func acquireIntent() *writeIntent {
	// Two-value form mirrors the rest of the codebase's pool getters. The
	// assertion is effectively infallible — intentPool.New only constructs
	// *writeIntent — so the comma-ok is for the linter, not for runtime
	// safety.
	i, _ := intentPool.Get().(*writeIntent)
	return i
}

func releaseIntent(i *writeIntent) {
	i.header = nil
	i.data = nil
	i.done = nil
	*i = writeIntent{}
	intentPool.Put(i)
}

// startWriter initialises the writer queue and kicks off runWriter. Called
// once from New before any frame send.
func (c *Conn) startWriter() {
	c.writeQ = make(chan *writeIntent, writeQSize)
	c.writeShutdown = make(chan struct{})
	c.writeDeadCh = make(chan struct{})
	go c.runWriter()
}

// runWriter is the single writer goroutine. It owns the framer, the HPACK
// encoder, encBuf, and lowerNames — no other goroutine touches them. Exits
// when writeShutdown is closed or a framer write fails.
func (c *Conn) runWriter() {
	var loopErr error
	defer func() {
		if loopErr == nil {
			loopErr = ErrConnClosed
		}
		c.writeErr = loopErr
		close(c.writeDeadCh)
		// Drain any remaining buffered intents so submitters waiting on
		// done channels don't hang.
		for {
			select {
			case intent := <-c.writeQ:
				if intent.done != nil {
					intent.done <- loopErr
				}
				releaseIntent(intent)
			default:
				return
			}
		}
	}()

	for {
		select {
		case intent := <-c.writeQ:
			err := c.processIntent(intent)
			if intent.done != nil {
				intent.done <- err
			}
			releaseIntent(intent)
			if err != nil {
				loopErr = err
				return
			}
		case <-c.writeShutdown:
			return
		}
	}
}

// processIntent dispatches one intent to the framer. Runs only inside the
// writer goroutine — exclusive access to enc, encBuf, framer.
func (c *Conn) processIntent(intent *writeIntent) error {
	switch intent.kind {
	case wkSettingsAck:
		return c.Framer.WriteSettingsAck()

	case wkWindowUpdate:
		return c.Framer.WriteWindowUpdate(intent.streamID, intent.increment)

	case wkPing:
		return c.Framer.WritePing(intent.isAck, intent.pingData)

	case wkRSTStream:
		return c.Framer.WriteRSTStream(intent.streamID, intent.code)

	case wkData:
		return c.Framer.WriteData(intent.streamID, intent.endStream, intent.data)

	case wkRespHeaders:
		return c.encodeAndWriteResponseHeaders(intent.streamID, intent.status, intent.header, intent.endStream)

	case wkReqHeaders:
		return c.encodeAndWriteRequestHeaders(intent.streamID, intent.method, intent.scheme, intent.authority, intent.path, intent.header, intent.endStream)

	case wkSetMaxDynTab:
		c.enc.SetMaxDynamicTableSize(intent.val)
		return nil

	case wkGoAway:
		// streamID carries the last-stream-id; code carries the error code.
		return c.Framer.WriteGoAway(intent.streamID, intent.code, nil)
	}
	return nil
}

// forbiddenForwardHeaders are connection-specific headers RFC 9113 §8.2.2
// forbids on H2. Filtered before HPACK encoding in both request and response
// directions; strict peers (HAProxy) reject the message otherwise.
func forbiddenForwardHeader(lk string) bool {
	switch lk {
	case "connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding":
		return true
	}
	return false
}

// encodeAndWriteResponseHeaders writes a response HEADERS frame (worker side).
// Encoder dynamic-table updates are atomic w.r.t. other HEADERS on the same
// connection because processIntent runs serially.
func (c *Conn) encodeAndWriteResponseHeaders(streamID uint32, status int, header http.Header, endStream bool) error {
	c.encBuf.Reset()
	_ = c.enc.WriteField(hpack.HeaderField{Name: ":status", Value: StatusString(status)})
	c.encodeRegularHeaders(header)
	return c.Framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: c.encBuf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	})
}

// encodeAndWriteRequestHeaders writes a request HEADERS frame (proxy side
// initiating an outbound request toward the worker).
func (c *Conn) encodeAndWriteRequestHeaders(streamID uint32, method, scheme, authority, path string, header http.Header, endStream bool) error {
	c.encBuf.Reset()
	_ = c.enc.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	if scheme == "" {
		scheme = "https"
	}
	_ = c.enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	if authority != "" {
		_ = c.enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	}
	_ = c.enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	c.encodeRegularHeaders(header)
	return c.Framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: c.encBuf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	})
}

func (c *Conn) encodeRegularHeaders(header http.Header) {
	for k, vv := range header {
		lk, ok := c.lowerNames[k]
		if !ok {
			lk = ToLower(k)
			c.lowerNames[k] = lk
		}
		if forbiddenForwardHeader(lk) {
			continue
		}
		for _, v := range vv {
			_ = c.enc.WriteField(hpack.HeaderField{Name: lk, Value: v})
		}
	}
}

// submit blocks until the writer processes the intent (synchronous) and
// returns the framer's error. The intent is released back to the pool here;
// callers must not retain it.
func (c *Conn) submit(intent *writeIntent) error {
	done, _ := donePool.Get().(chan error)
	intent.done = done
	defer func() {
		select {
		case <-done:
		default:
		}
		donePool.Put(done)
	}()

	select {
	case c.writeQ <- intent:
	case <-c.writeDeadCh:
		releaseIntent(intent)
		return c.writeErr
	}

	select {
	case err := <-done:
		return err
	case <-c.writeDeadCh:
		select {
		case err := <-done:
			return err
		default:
			return c.writeErr
		}
	}
}

// submitAsync enqueues the intent without waiting. For fire-and-forget frames
// — SETTINGS_ACK, WINDOW_UPDATE, PING (incl. ACK), RST_STREAM,
// SetMaxDynTab — where the caller doesn't need to observe the result.
func (c *Conn) submitAsync(intent *writeIntent) {
	select {
	case c.writeQ <- intent:
	case <-c.writeDeadCh:
		releaseIntent(intent)
	}
}

// ---- convenience constructors ---------------------------------------------

// SendSettingsAck enqueues an empty SETTINGS frame with the ACK flag. Fire-
// and-forget; framer write errors surface via WriteErr/the conn teardown
// path.
func (c *Conn) SendSettingsAck() {
	i := acquireIntent()
	i.kind = wkSettingsAck
	c.submitAsync(i)
}

// SendWindowUpdate refills the peer's send window by inc on streamID (or 0
// for conn-level).
func (c *Conn) SendWindowUpdate(streamID, inc uint32) {
	i := acquireIntent()
	i.kind = wkWindowUpdate
	i.streamID = streamID
	i.increment = inc
	c.submitAsync(i)
}

// SendPing emits a PING frame with the given opaque payload. ack=true emits
// the response to a peer PING; ack=false starts a liveness round-trip whose
// PONG we expect to receive.
func (c *Conn) SendPing(ack bool, data [8]byte) {
	i := acquireIntent()
	i.kind = wkPing
	i.isAck = ack
	i.pingData = data
	c.submitAsync(i)
}

// SendRSTStream emits an RST_STREAM with the given error code on streamID.
func (c *Conn) SendRSTStream(streamID uint32, code http2.ErrCode) {
	i := acquireIntent()
	i.kind = wkRSTStream
	i.streamID = streamID
	i.code = code
	c.submitAsync(i)
}

// SendSetMaxDynamicTableSize updates the HPACK encoder's max dynamic table
// size, routed through the writer goroutine so it lands in-order with any
// pending HEADERS frames.
func (c *Conn) SendSetMaxDynamicTableSize(v uint32) {
	i := acquireIntent()
	i.kind = wkSetMaxDynTab
	i.val = v
	c.submitAsync(i)
}

// SendData emits a DATA frame on streamID. Synchronous — returns the framer's
// error (or the writer's exit error if the writer goroutine has died).
func (c *Conn) SendData(streamID uint32, data []byte, endStream bool) error {
	i := acquireIntent()
	i.kind = wkData
	i.streamID = streamID
	i.data = data
	i.endStream = endStream
	return c.submit(i)
}

// SendResponseHeaders emits a HEADERS frame carrying :status (worker side).
// Synchronous.
func (c *Conn) SendResponseHeaders(streamID uint32, status int, header http.Header, endStream bool) error {
	i := acquireIntent()
	i.kind = wkRespHeaders
	i.streamID = streamID
	i.status = status
	i.header = header
	i.endStream = endStream
	return c.submit(i)
}

// SendRequestHeaders emits a HEADERS frame carrying :method/:scheme/:authority/:path
// (proxy side initiating an outbound stream). Synchronous.
func (c *Conn) SendRequestHeaders(streamID uint32, method, scheme, authority, path string, header http.Header, endStream bool) error {
	i := acquireIntent()
	i.kind = wkReqHeaders
	i.streamID = streamID
	i.method = method
	i.scheme = scheme
	i.authority = authority
	i.path = path
	i.header = header
	i.endStream = endStream
	return c.submit(i)
}

// SendGoAway is synchronous so the conn-teardown path can be sure the GOAWAY
// frame actually made it onto the wire before the writer goroutine exits and
// the underlying conn is closed.
func (c *Conn) SendGoAway(lastStreamID uint32, code http2.ErrCode) error {
	i := acquireIntent()
	i.kind = wkGoAway
	i.streamID = lastStreamID
	i.code = code
	return c.submit(i)
}

// ShutdownWriter signals the writer goroutine to exit and waits for it to do
// so. Called by conn-teardown paths after issuing a final GOAWAY.
func (c *Conn) ShutdownWriter() {
	close(c.writeShutdown)
	<-c.writeDeadCh
}

// WriteErr returns the writer goroutine's exit error (valid only after
// writeDeadCh is closed).
func (c *Conn) WriteErr() error { return c.writeErr }
