package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
)

// Options configures a Proxy.
type Options struct {
	// TunnelTLSConfig is the TLS configuration for the worker-facing
	// listener. Required. The proxy adds "h2" to NextProtos automatically
	// if missing. Workers are authenticated entirely by the TLS layer
	// (per the proxy's ClientAuth / ClientCAs setup) — any client cert
	// that chains to ClientCAs is accepted; finer-grained gating (e.g. CN
	// allow-list) belongs in OnWorkerAttach or a Selector.
	TunnelTLSConfig *tls.Config

	// Selector picks a worker for each public request. Optional; default
	// is LeastInFlight.
	Selector Selector

	// Logger is used for tunnel-level diagnostics (attach/detach, dropped
	// peers, protocol errors). Per-request failures surface to the public
	// caller via standard HTTP responses. Optional; defaults to a discard
	// logger so the proxy is silent unless wired up.
	Logger *slog.Logger

	// OnWorkerAttach is invoked, if non-nil, after a worker has completed
	// its handshake and is ready to receive requests. The Worker pointer is
	// valid until OnWorkerDetach fires. Run on a tunnel-accept goroutine;
	// the hook should not block.
	OnWorkerAttach func(*Worker)

	// OnWorkerDetach is invoked when a worker's tunnel has been torn down.
	// In-flight requests on it have already been failed.
	OnWorkerDetach func(*Worker)

	// MaxConcurrentStreams advertised in SETTINGS_MAX_CONCURRENT_STREAMS to
	// each attached worker. Zero means use the h2-default of 100. Caps how
	// many concurrent forwards a single worker can host before the proxy
	// pushes back (subsequent requests still land on that worker if it's
	// the only one — capacity becomes serialisation rather than rejection).
	MaxConcurrentStreams uint32
}

// Proxy is the reverse-http server. It accepts mTLS HTTP/2 tunnel
// connections from workers (ListenAndServeTunnels) and exposes a public-
// side handler (Handler / ListenAndServePublic) that forwards requests
// over those tunnels.
//
// A Proxy is safe for concurrent use after New returns.
type Proxy struct {
	selector       Selector
	tunnelListener net.Listener

	log *slog.Logger

	shutdownCh chan struct{}

	opts Options

	// workers is the attached set, kept in attach order. Slice rather than
	// map so snapshotWorkers returns a stable ordering — round-robin and
	// least-in-flight tie-breaking become deterministic, and the Selector
	// contract is easier to reason about. Worker count per proxy is in the
	// tens (one slot per worker process), so the O(n) detach scan is cheap.
	workers []*Worker

	tunnelAccepts sync.WaitGroup

	workersMu sync.RWMutex

	shutdownOnce sync.Once

	tunnelListenerMu sync.Mutex
}

// New constructs a Proxy from opts. Returns an error if mandatory fields are
// missing.
func New(opts Options) (*Proxy, error) {
	if opts.TunnelTLSConfig == nil {
		return nil, errors.New("rhttp/proxy: TunnelTLSConfig is required")
	}
	if opts.Selector == nil {
		opts.Selector = LeastInFlight()
	}
	p := &Proxy{
		opts:       opts,
		selector:   opts.Selector,
		shutdownCh: make(chan struct{}),
	}
	if opts.Logger != nil {
		p.log = opts.Logger
	} else {
		p.log = slog.New(slog.DiscardHandler)
	}
	return p, nil
}

// logger returns the proxy's slog.Logger (never nil).
func (p *Proxy) logger() *slog.Logger { return p.log }

// Workers returns a snapshot of currently-attached workers. The slice itself
// is freshly allocated; callers may retain it. Worker fields are safe for
// concurrent read by selectors and inspection code.
func (p *Proxy) Workers() []*Worker {
	return p.snapshotWorkers()
}

func (p *Proxy) snapshotWorkers() []*Worker {
	p.workersMu.RLock()
	out := make([]*Worker, len(p.workers))
	copy(out, p.workers)
	p.workersMu.RUnlock()
	return out
}

// attach registers a freshly-handshaked worker. Returns an error if the
// proxy is shutting down.
func (p *Proxy) attach(w *Worker) error {
	select {
	case <-p.shutdownCh:
		return errors.New("rhttp/proxy: shutting down")
	default:
	}
	p.workersMu.Lock()
	p.workers = append(p.workers, w)
	p.workersMu.Unlock()
	p.log.Debug("rhttp/proxy: worker attached", "remote", w.remote)
	if p.opts.OnWorkerAttach != nil {
		p.opts.OnWorkerAttach(w)
	}
	return nil
}

// detach removes w from the worker set. Idempotent.
func (p *Proxy) detach(w *Worker) {
	p.workersMu.Lock()
	var present bool
	for i, x := range p.workers {
		if x == w {
			p.workers = append(p.workers[:i], p.workers[i+1:]...)
			present = true
			break
		}
	}
	p.workersMu.Unlock()
	if !present {
		return
	}
	p.log.Debug("rhttp/proxy: worker detached", "remote", w.remote)
	if p.opts.OnWorkerDetach != nil {
		p.opts.OnWorkerDetach(w)
	}
}

// Handler returns an http.Handler that forwards each request to a selected
// worker. Mount it on any net/http server / mux / TLS listener you prefer.
// For a turnkey public listener, use ListenAndServePublic.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.forward)
}

// ListenAndServeTunnels binds addr (typically host:port like ":8443") and
// accepts worker tunnels over TLS. Blocks until Shutdown is called or the
// listener returns an error. The listener's TLS config is opts.TunnelTLSConfig
// with "h2" ensured in NextProtos.
func (p *Proxy) ListenAndServeTunnels(addr string) error {
	cfg := cloneAndEnsureH2(p.opts.TunnelTLSConfig)
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return err
	}
	return p.runTunnelAccept(ln)
}

// ServeTunnelListener accepts tunnels on a pre-built listener. Useful when
// the caller wants to control bind options, listener wrapping, or supply a
// non-TCP transport. The listener must yield *tls.Conn with ALPN h2
// negotiated; pass a net.Listener wrapped with tls.NewListener if you're
// terminating elsewhere.
func (p *Proxy) ServeTunnelListener(ln net.Listener) error {
	return p.runTunnelAccept(ln)
}

func (p *Proxy) runTunnelAccept(ln net.Listener) error {
	p.tunnelListenerMu.Lock()
	p.tunnelListener = ln
	p.tunnelListenerMu.Unlock()
	defer func() {
		p.tunnelListenerMu.Lock()
		if p.tunnelListener == ln {
			p.tunnelListener = nil
		}
		p.tunnelListenerMu.Unlock()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.shutdownCh:
				return nil
			default:
			}
			if isTemporary(err) {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		// Pre-flight the TLS handshake so a slow / malicious client can't
		// pin a goroutine for the whole tunnel lifetime before we even know
		// it speaks h2. Done in the accept goroutine to keep the accept
		// loop responsive.
		p.tunnelAccepts.Add(1)
		go func(c net.Conn) {
			defer p.tunnelAccepts.Done()
			if tlsConn, ok := c.(*tls.Conn); ok {
				_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := tlsConn.Handshake(); err != nil {
					_ = c.Close()
					return
				}
				_ = tlsConn.SetDeadline(time.Time{})
				if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
					_ = c.Close()
					return
				}
			}
			p.acceptTunnel(c)
		}(conn)
	}
}

// ListenAndServePublic binds addr and serves p.Handler() under tlsConfig
// (pass nil for plain HTTP, e.g. behind a TLS terminator). Blocks until
// Shutdown or a listener error.
func (p *Proxy) ListenAndServePublic(addr string, tlsConfig *tls.Config) error {
	srv := &http.Server{
		Addr:      addr,
		Handler:   p.Handler(),
		TLSConfig: tlsConfig,
		BaseContext: func(_ net.Listener) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				<-p.shutdownCh
				cancel()
			}()
			return ctx
		},
	}
	if tlsConfig != nil {
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}

// Shutdown stops accepting new tunnels, fails in-flight forwards on every
// attached worker (so their public callers see a clean 502), and waits for
// accept goroutines to exit. Returns ctx.Err() if the deadline trips first.
// Safe to call multiple times.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.shutdownOnce.Do(func() {
		close(p.shutdownCh)
		// Close the tunnel listener (if any) so Accept exits.
		p.tunnelListenerMu.Lock()
		ln := p.tunnelListener
		p.tunnelListenerMu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
		// Tear down every attached worker so in-flight forwards observe a
		// dead tunnel and exit instead of stalling on response cond.
		for _, w := range p.snapshotWorkers() {
			_ = w.conn.SetReadDeadline(time.Now())
		}
	})

	done := make(chan struct{})
	go func() {
		p.tunnelAccepts.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// cloneAndEnsureH2 returns a TLS config equivalent to cfg with "h2" present
// in NextProtos. Workers refuse to attach without h2 ALPN; missing it would
// just hang the handshake.
func cloneAndEnsureH2(cfg *tls.Config) *tls.Config {
	out := cfg.Clone()
	if slices.Contains(out.NextProtos, "h2") {
		return out
	}
	out.NextProtos = append(out.NextProtos, "h2")
	return out
}

func isTemporary(err error) bool {
	type tempError interface {
		Temporary() bool
	}
	if te, ok := err.(tempError); ok {
		return te.Temporary()
	}
	return false
}
