package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/oktalz/reverse-http/internal/h2"
	"golang.org/x/net/http2"
)

// clientPreface is the HTTP/2 client connection preface (RFC 7540 §3.5) the
// worker writes immediately after its TLS handshake completes.
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// acceptTunnel completes the worker-side handshake on rwc and runs the
// tunnel's frame loop until the connection drops. Registers the Worker with
// the Proxy on attach and deregisters on exit. Returns once the loop exits.
//
// The caller has already done the TLS handshake — rwc is a *tls.Conn with
// ALPN h2 negotiated and (per the proxy's TLS config) any client-cert
// verification completed.
func (p *Proxy) acceptTunnel(rwc net.Conn) {
	defer func() { _ = rwc.Close() }()

	// 1. Read the worker's H2 client connection preface. In reverse-http the
	//    semantic roles are inverted relative to the wire roles: the worker
	//    (TCP client) sends the preface, but at the protocol level the
	//    *proxy* will be the one initiating streams.
	pref := make([]byte, len(clientPreface))
	if _, err := io.ReadFull(rwc, pref); err != nil {
		p.logger().Debug("rhttp/proxy: tunnel preface read failed", "err", err)
		return
	}
	if string(pref) != clientPreface {
		p.logger().Debug("rhttp/proxy: tunnel sent bad preface")
		return
	}

	// 2. Wrap in h2.Conn (writes initial SETTINGS, starts the writer
	//    goroutine).
	h2c, err := h2.New(rwc, p.opts.MaxConcurrentStreams)
	if err != nil {
		p.logger().Debug("rhttp/proxy: h2 setup failed", "err", err)
		return
	}

	w := &Worker{
		conn:       h2c,
		streams:    make(map[uint32]*clientStream),
		remote:     rwc.RemoteAddr(),
		shutdownCh: make(chan struct{}),
	}
	if tlsConn, ok := rwc.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			w.cert = state.PeerCertificates[0]
		}
	}

	if err := p.attach(w); err != nil {
		// Proxy shutting down; drop the tunnel cleanly.
		_ = h2c.SendGoAway(0, http2.ErrCodeNo)
		h2c.ShutdownWriter()
		return
	}
	defer p.detach(w)

	if err := serveTunnel(w, p); err != nil && !errors.Is(err, h2.ErrGoaway) {
		p.logger().Debug("rhttp/proxy: tunnel ended", "err", err, "remote", w.remote)
	}
}

// serveTunnel runs the proxy-side frame loop for one Worker. Shared frame
// handling (SETTINGS / PING / WINDOW_UPDATE / RST_STREAM / GOAWAY / DATA /
// CONTINUATION) goes through h2.Conn methods; HEADERS dispatches *responses*
// to in-flight forwarders by looking up the matching clientStream.
func serveTunnel(w *Worker, p *Proxy) error {
	c := w.conn
	defer func() {
		c.Send.MarkDead()
		w.failAllStreams(h2.ErrConnClosed)
		c.FailAllStreams(h2.ErrConnClosed)
		// Best-effort GOAWAY; LastStreamID stays 0 since the proxy never
		// accepts peer-initiated streams.
		_ = c.SendGoAway(0, http2.ErrCodeNo)
		c.ShutdownWriter()
		w.detach()
	}()

	// Wait for the peer's initial SETTINGS before serving.
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

	for {
		select {
		case <-p.shutdownCh:
			return nil
		default:
		}
		c.SetIdleDeadline()
		f, err := c.Framer.ReadFrame()
		if err != nil {
			if h2.IsNetTimeout(err) {
				select {
				case <-p.shutdownCh:
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
				deliverResponse(w, decoded)
			}
			continue
		}

		if err := handleProxyFrame(w, p, f); err != nil {
			return err
		}
	}
}

// handleProxyFrame dispatches one frame outside CONTINUATION state.
func handleProxyFrame(w *Worker, _ *Proxy, f http2.Frame) error {
	c := w.conn
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
		decoded, err := c.StartHeaders(f)
		if err != nil {
			return err
		}
		if decoded != nil {
			deliverResponse(w, decoded)
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
		id := f.Header().StreamID
		if cs := w.getStream(id); cs != nil {
			cs.fail(h2.ErrStreamReset)
		}
		c.HandleRSTStream(id)
		return nil
	}
	return nil
}

// deliverResponse finds the clientStream for decoded.StreamID and hands the
// response headers off. If no clientStream is registered (stream timed out,
// already deregistered), we RST_STREAM the orphan.
func deliverResponse(w *Worker, decoded *h2.DecodedHeaders) {
	cs := w.getStream(decoded.StreamID)
	if cs == nil {
		w.conn.SendRSTStream(decoded.StreamID, http2.ErrCodeStreamClosed)
		h2.HeaderPool.Put(decoded.Header)
		return
	}
	status, _ := strconv.Atoi(decoded.Status)
	cs.deliverHeaders(status, decoded.Header)
	if decoded.EndStream {
		cs.h2.CloseData()
	}
}
