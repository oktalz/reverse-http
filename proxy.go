package rhttp

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"

	"github.com/oktalz/reverse-http/internal/proxy"
)

// ProxyOptions configures a Proxy (the server-side counterpart to the
// reverse-http worker established by NewConnectionPool).
type ProxyOptions struct {
	// TunnelTLSConfig is the TLS configuration for the worker-facing
	// listener. Required.
	//
	// Mandatory shape:
	//
	//   - Certificates / GetCertificate set so workers can verify the proxy.
	//   - ClientAuth set to tls.RequireAndVerifyClientCert.
	//   - ClientCAs populated with the CA(s) that signed legitimate worker
	//     certs.
	//
	// "h2" is added to NextProtos automatically if missing. Worker
	// authentication is performed entirely by the TLS layer: any client
	// cert that chains to ClientCAs is accepted. Finer-grained gating
	// (CN allow-lists, OU matching, external lookup) belongs in
	// OnWorkerAttach or in your Selector — inspect Worker.Certificate().
	TunnelTLSConfig *tls.Config

	// Selector picks a worker for each public request. Optional; default
	// is least-in-flight. Use ProxyRoundRobin() for plain round-robin,
	// ProxySelectorFunc for ad-hoc logic, or implement ProxySelector
	// yourself.
	Selector ProxySelector

	// Logger receives tunnel-level diagnostic events (attach/detach,
	// protocol errors). Per-request failures still surface to the public
	// caller via the HTTP response. Optional; default is silent.
	Logger *slog.Logger

	// OnWorkerAttach / OnWorkerDetach run on tunnel-accept goroutines as
	// workers come and go. Optional. Should not block.
	OnWorkerAttach func(*ProxyWorker)
	OnWorkerDetach func(*ProxyWorker)

	// MaxConcurrentStreams advertised to each worker tunnel. Zero means
	// the H2 default (100).
	MaxConcurrentStreams uint32
}

// ProxySelector picks the worker that a given public request should be
// forwarded to. Returning nil produces a 503 to the public caller.
//
// Implementations must tolerate an empty workers slice. The slice is a
// snapshot — do not retain it past the Pick call.
type ProxySelector interface {
	Pick(req *http.Request, workers []*ProxyWorker) *ProxyWorker
}

// ProxySelectorFunc adapts an ordinary function to ProxySelector.
type ProxySelectorFunc func(req *http.Request, workers []*ProxyWorker) *ProxyWorker

// Pick implements ProxySelector.
func (f ProxySelectorFunc) Pick(req *http.Request, workers []*ProxyWorker) *ProxyWorker {
	return f(req, workers)
}

// ProxyLeastInFlight returns the default selector — pick the attached
// worker with the fewest currently-in-flight forwards.
func ProxyLeastInFlight() ProxySelector { return wrapSelector(proxy.LeastInFlight()) }

// ProxyRoundRobin returns a selector that picks workers in round-robin
// order. Counter is shared across the returned selector instance; build a
// fresh one per Proxy if you want isolated state.
func ProxyRoundRobin() ProxySelector { return wrapSelector(proxy.RoundRobin()) }

// ProxyWorker represents one attached reverse-http tunnel.
type ProxyWorker struct {
	w *proxy.Worker
}

// RemoteAddr returns the worker's network address.
func (pw *ProxyWorker) RemoteAddr() net.Addr { return pw.w.RemoteAddr() }

// CommonName returns the worker certificate's Subject CN (empty if no
// client cert was presented). Convenience around Certificate().
func (pw *ProxyWorker) CommonName() string {
	if c := pw.w.Certificate(); c != nil {
		return c.Subject.CommonName
	}
	return ""
}

// Certificate returns the leaf client certificate the worker presented
// during mTLS. nil if the tunnel TLS config didn't require / verify a
// client cert. Selectors and hooks may inspect this for routing.
func (pw *ProxyWorker) Certificate() any { return pw.w.Certificate() }

// InFlight returns the number of currently-active outbound streams on this
// worker's tunnel. Selectors typically consult this.
func (pw *ProxyWorker) InFlight() int64 { return pw.w.InFlight() }

// Proxy is the reverse-http server. It accepts mTLS HTTP/2 tunnel
// connections from workers and exposes Handler / ListenAndServePublic for
// the public side.
type Proxy struct {
	p *proxy.Proxy
}

// NewProxy constructs a Proxy. ListenAndServeTunnels must be called to
// start accepting workers; Handler / ListenAndServePublic exposes the
// public side. Both are safe for concurrent use.
func NewProxy(opts ProxyOptions) (*Proxy, error) {
	innerOpts := proxy.Options{
		TunnelTLSConfig:      opts.TunnelTLSConfig,
		Logger:               opts.Logger,
		MaxConcurrentStreams: opts.MaxConcurrentStreams,
	}
	if opts.Selector != nil {
		innerOpts.Selector = unwrapSelector(opts.Selector)
	}
	if opts.OnWorkerAttach != nil {
		hook := opts.OnWorkerAttach
		innerOpts.OnWorkerAttach = func(w *proxy.Worker) { hook(&ProxyWorker{w: w}) }
	}
	if opts.OnWorkerDetach != nil {
		hook := opts.OnWorkerDetach
		innerOpts.OnWorkerDetach = func(w *proxy.Worker) { hook(&ProxyWorker{w: w}) }
	}
	inner, err := proxy.New(innerOpts)
	if err != nil {
		return nil, err
	}
	return &Proxy{p: inner}, nil
}

// Handler returns an http.Handler that forwards each request to a worker
// chosen by the configured Selector. Mount on any net/http server.
func (p *Proxy) Handler() http.Handler { return p.p.Handler() }

// ListenAndServeTunnels binds addr and accepts worker tunnels. Blocks until
// Shutdown or a listener error. The TLS config is ProxyOptions.TunnelTLSConfig
// with "h2" ensured in NextProtos.
func (p *Proxy) ListenAndServeTunnels(addr string) error {
	return p.p.ListenAndServeTunnels(addr)
}

// ServeTunnelListener accepts tunnels on a pre-built listener. The listener
// must yield *tls.Conn with ALPN h2 negotiated.
func (p *Proxy) ServeTunnelListener(ln net.Listener) error {
	return p.p.ServeTunnelListener(ln)
}

// ListenAndServePublic is a turnkey public listener — binds addr and serves
// Handler() under tlsConfig (pass nil for plain HTTP, e.g. behind a TLS
// terminator). Blocks until Shutdown or a listener error.
func (p *Proxy) ListenAndServePublic(addr string, tlsConfig *tls.Config) error {
	return p.p.ListenAndServePublic(addr, tlsConfig)
}

// Workers returns a snapshot of attached workers. Slice is freshly-allocated;
// safe to retain.
func (p *Proxy) Workers() []*ProxyWorker {
	inner := p.p.Workers()
	out := make([]*ProxyWorker, len(inner))
	for i, w := range inner {
		out[i] = &ProxyWorker{w: w}
	}
	return out
}

// Shutdown stops accepting new tunnels, tears down attached ones (so in-flight
// public requests fail cleanly), and waits for accept goroutines to exit.
// Returns ctx.Err() if the deadline trips first. Safe to call multiple times.
func (p *Proxy) Shutdown(ctx context.Context) error { return p.p.Shutdown(ctx) }

// ---- adapter glue between the public ProxySelector and the internal one --

type selectorAdapter struct {
	inner proxy.Selector
}

func (a *selectorAdapter) Pick(req *http.Request, workers []*ProxyWorker) *ProxyWorker {
	inner := make([]*proxy.Worker, len(workers))
	for i, w := range workers {
		inner[i] = w.w
	}
	picked := a.inner.Pick(req, inner)
	if picked == nil {
		return nil
	}
	for _, w := range workers {
		if w.w == picked {
			return w
		}
	}
	return nil
}

func wrapSelector(s proxy.Selector) ProxySelector {
	return &selectorAdapter{inner: s}
}

func unwrapSelector(s ProxySelector) proxy.Selector {
	if a, ok := s.(*selectorAdapter); ok {
		return a.inner
	}
	return proxy.SelectorFunc(func(req *http.Request, inner []*proxy.Worker) *proxy.Worker {
		wrapped := make([]*ProxyWorker, len(inner))
		for i, w := range inner {
			wrapped[i] = &ProxyWorker{w: w}
		}
		picked := s.Pick(req, wrapped)
		if picked == nil {
			return nil
		}
		return picked.w
	})
}
