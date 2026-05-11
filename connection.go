package rhttp

import (
	"crypto/tls"
	"crypto/x509"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/oktalz/reverse-http/internal/h2"
)

// ServerOptions holds the configuration for the reverse HTTP/2 connection
// pool that this worker maintains toward the proxy.
type ServerOptions struct {
	TLSCert    tls.Certificate
	Handler    http.Handler
	CACertPool *x509.CertPool
	// SNIServerName is the Server Name Indication for TLS — the hostname
	// the worker expects in the proxy's certificate. Optional: when empty,
	// tls.Dial auto-derives it from the host part of Addr, which is the
	// right answer whenever you dial the proxy by its hostname. Set it
	// explicitly only when Addr is an IP (auto-derive would give an IP
	// SAN check that fails on the usual hostname-only cert) or when the
	// proxy presents a cert for a different name than the one in Addr.
	SNIServerName string
	// Addr is the proxy address to connect to.
	Addr string
	// NBConn is the number of connections to establish.
	NBConn int
	// MaxConcurrentStreams is the value advertised to the peer in
	// SETTINGS_MAX_CONCURRENT_STREAMS — i.e. the cap on how many streams the
	// peer can multiplex simultaneously on each tunnel. Zero means use the
	// default of 100. Raising it grows the per-tunnel multiplexing budget
	// (more concurrent SSE/long-polls before the pool needs more tunnels) at
	// the cost of more goroutines per tunnel and a larger blast radius if
	// the tunnel dies.
	MaxConcurrentStreams uint32
}

// connection is the worker's per-tunnel wrapper around an *h2.Conn. The
// embedded Conn provides every shared HTTP/2 primitive (framer, codecs,
// writer goroutine, ping, flow control); this struct adds the bits specific
// to the worker role (the http.Handler dispatched per inbound stream and
// the pool-level shutdown signal).
type connection struct {
	*h2.Conn
	handler    http.Handler
	pool       *Pool
	shutdownCh <-chan struct{}
}

// maintainConnection keeps a single connection slot alive, reconnecting on
// failure until the pool is shut down.
//
// Adds 0–500ms of jitter to the 1s base delay so a mass drop (proxy restart)
// doesn't have every slot reconnect in lockstep one second later — the
// thundering herd would just be repeated against the recovering proxy.
func maintainConnection(opts ServerOptions, p *Pool) {
	defer p.maintainers.Done()
	once := &sync.Once{}
	for {
		select {
		case <-p.shutdownCh:
			// Even if we never reached a successful dial, release the Ready
			// waiter so callers don't hang on pool.Ready().Wait() after
			// Shutdown returns.
			once.Do(p.ready.Done)
			return
		default:
		}
		_ = dial(opts, p, once)
		select {
		case <-p.shutdownCh:
			once.Do(p.ready.Done)
			return
		case <-time.After(time.Second + rand.N(500*time.Millisecond)):
		}
	}
}

// dial establishes one reverse HTTP/2 connection and serves until it drops.
// Always over TLS with ALPN h2 and a client certificate.
func dial(opts ServerOptions, p *Pool, once *sync.Once) error {
	conf := &tls.Config{
		RootCAs:      opts.CACertPool,
		NextProtos:   []string{"h2"},
		ServerName:   opts.SNIServerName,
		Certificates: []tls.Certificate{opts.TLSCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsConn, err := tls.Dial("tcp", opts.Addr, conf)
	if err != nil {
		return err
	}
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	if state := tlsConn.ConnectionState(); state.NegotiatedProtocol != "h2" {
		_ = tlsConn.Close()
		return h2.ErrALPN
	}

	// Disable Nagle on the underlying TCP socket. HTTP/2 emits small framed
	// writes (response headers, flushes, PINGs); with Nagle on, the kernel
	// can hold these for up to 40ms hoping to coalesce.
	if tcp, ok := tlsConn.NetConn().(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	readyCh := make(chan struct{})
	conn, errCh, err := startConnection(tlsConn, opts, readyCh, p.shutdownCh)
	if err != nil {
		return err
	}
	conn.pool = p
	p.registerConn(conn)
	defer p.deregisterConn(conn)

	<-readyCh
	once.Do(func() {
		p.ready.Done()
	})

	return <-errCh
}

// startConnection wraps an already-established net.Conn in a worker
// connection: writes the H2 client preface, hands off to h2.New (which sends
// initial SETTINGS and starts the writer goroutine), then launches the
// frame-reading loop in a goroutine. readyCh is closed once the peer's
// initial SETTINGS have been processed.
//
// shutdownCh is the optional pool-level shutdown signal — when closed, serve
// exits gracefully (sending GOAWAY) on its next loop iteration. Pass nil
// when driving the connection from tests without a Pool.
func startConnection(rwc net.Conn, opts ServerOptions, readyCh chan struct{}, shutdownCh <-chan struct{}) (*connection, <-chan error, error) {
	// The worker is the TCP dialer, so it writes the H2 client preface.
	// (In reverse-http the semantic roles are inverted relative to the wire
	// roles: the worker serves responses, but at the wire it's the client.)
	if _, err := rwc.Write([]byte(clientPreface)); err != nil {
		return nil, nil, err
	}

	h2c, err := h2.New(rwc, opts.MaxConcurrentStreams)
	if err != nil {
		return nil, nil, err
	}

	c := &connection{
		Conn:       h2c,
		handler:    opts.Handler,
		shutdownCh: shutdownCh,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(c, readyCh)
	}()

	return c, errCh, nil
}

// clientPreface is the HTTP/2 client connection preface (RFC 7540 §3.5).
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
