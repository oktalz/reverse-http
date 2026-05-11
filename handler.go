package rhttp

import (
	"github.com/oktalz/reverse-http/internal/h2"
	"golang.org/x/net/http2"
)

// serve reads frames from the worker side of the reverse connection and
// dispatches them. Shared frame logic (SETTINGS / PING / WINDOW_UPDATE /
// RST_STREAM / GOAWAY / DATA / CONTINUATION) goes through h2.Conn methods;
// HEADERS is worker-specific (each completed header block spawns a goroutine
// running the configured http.Handler).
func serve(c *connection, readyCh chan struct{}) error {
	defer func() {
		// Wake any handler goroutines blocked on the send window before the
		// connection goes away — they should see a "conn dead" error rather
		// than spinning forever on the cond.
		c.Send.MarkDead()
		c.FailAllStreams(h2.ErrConnClosed)
		// Best-effort GOAWAY so the peer learns the last-stream-id it can
		// expect to be processed.
		_ = c.SendGoAway(c.LastStreamID, http2.ErrCodeNo)
		c.ShutdownWriter()
		_ = c.Close()
	}()

	// Wait for the peer's initial SETTINGS before declaring the conn ready;
	// otherwise our SETTINGS_INITIAL_WINDOW_SIZE / MAX_FRAME_SIZE could be
	// stale when the first stream is accepted.
	for {
		f, err := c.Framer.ReadFrame()
		if err != nil {
			return err
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		if err := c.ApplyPeerSettings(sf); err != nil {
			return err
		}
		c.SendSettingsAck()
		break
	}

	close(readyCh)

	for {
		// Pool.Shutdown signals teardown by closing shutdownCh AND calling
		// SetReadDeadline(now). Check it on every iteration so a quiet conn
		// still exits promptly.
		select {
		case <-c.shutdownCh:
			return nil
		default:
		}
		c.SetIdleDeadline()
		f, err := c.Framer.ReadFrame()
		if err != nil {
			if h2.IsNetTimeout(err) {
				select {
				case <-c.shutdownCh:
					return nil
				default:
				}
				if err := c.SendOrCheckPing(); err != nil {
					return err
				}
				continue
			}
			return err
		}

		// Per RFC 7540 §6.10, once a HEADERS without END_HEADERS has been
		// received, only CONTINUATION frames for the same stream are
		// allowed until END_HEADERS arrives. Anything else is a
		// connection-level PROTOCOL_ERROR.
		if c.InContinuation() {
			cf, ok := f.(*http2.ContinuationFrame)
			if !ok || cf.Header().StreamID != c.ContStreamID() {
				return h2.ErrContInterleaved
			}
			decoded, err := c.ConsumeContinuation(cf)
			if err != nil {
				return err
			}
			if decoded != nil {
				c.dispatchInboundHeaders(decoded)
			}
			continue
		}

		if err := c.handleFrame(f); err != nil {
			return err
		}
	}
}

// handleFrame dispatches a single framer frame outside CONTINUATION state.
func (c *connection) handleFrame(f http2.Frame) error {
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if f.IsAck() {
			return nil
		}
		if err := c.ApplyPeerSettings(f); err != nil {
			return err
		}
		c.SendSettingsAck()
		return nil

	case *http2.WindowUpdateFrame:
		c.HandleWindowUpdate(f.Header().StreamID, int32(f.Increment))
		return nil

	case *http2.HeadersFrame:
		// Existing streams shouldn't see a second HEADERS frame in this
		// library (no trailers support); ignore to stay forgiving.
		if c.GetStream(f.StreamID) != nil {
			return nil
		}
		decoded, err := c.StartHeaders(f)
		if err != nil {
			return err
		}
		if decoded != nil {
			c.dispatchInboundHeaders(decoded)
		}
		return nil

	case *http2.DataFrame:
		c.HandleInboundData(f.Header().StreamID, f.Data(), f.StreamEnded())
		return nil

	case *http2.PingFrame:
		if f.IsAck() {
			c.HandlePingAck(f.Data)
			return nil
		}
		c.SendPing(true, f.Data)
		return nil

	case *http2.GoAwayFrame:
		return h2.ErrGoaway

	case *http2.RSTStreamFrame:
		c.HandleRSTStream(f.Header().StreamID)
		return nil
	}
	return nil
}

// dispatchInboundHeaders takes a complete decoded HEADERS block and starts a
// worker-side stream goroutine to run the http.Handler. The decoded.Header
// map returns to the pool after the request is served (see serveStream).
func (c *connection) dispatchInboundHeaders(decoded *h2.DecodedHeaders) {
	s := h2.Acquire(decoded.StreamID, c.Conn, c.Send.InitialStreamWindow())
	c.AddStream(s)
	if decoded.EndStream {
		s.CloseData()
	}
	go c.serveStream(s, decoded)
}
