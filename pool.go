package rhttp

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrMTLSRequired is returned by NewConnectionPool when the worker's own
// certificate is missing. The library deliberately refuses to run without
// it: an exposed reverse-http worker without client-certificate
// authentication accepts arbitrary HTTP requests from any peer that can
// reach the proxy port, which is almost certainly not what you want.
//
// CACertPool, in contrast, is *optional*: a nil pool falls back to the
// host's system root CAs, which is the right choice when the proxy uses a
// publicly-trusted certificate (e.g. Let's Encrypt). Set it explicitly
// only when the proxy presents a cert signed by an internal/self-signed
// CA that isn't in the OS trust store.
var ErrMTLSRequired = errors.New("rhttp: TLSCert (worker identity) is required for mTLS")

// Pool is the handle returned by NewConnectionPool. It exposes a Ready
// WaitGroup that signals when every slot has completed its first successful
// dial, and a Shutdown method for graceful teardown.
type Pool struct {
	ready *sync.WaitGroup

	shutdownCh chan struct{}

	conns map[*connection]struct{}

	// maintainers tracks live maintainConnection goroutines so Shutdown can
	// block (with ctx) until they've all exited.
	maintainers sync.WaitGroup

	shutdownOnce sync.Once

	// connsMu protects conns. Each maintainConnection goroutine registers
	// its current *connection when it dials successfully and deregisters
	// when serve returns.
	connsMu sync.Mutex
}

// Ready returns a WaitGroup that completes once every slot in the pool has
// reached at least one successful dial + handshake. Useful as a startup gate
// — typical usage is `pool.Ready().Wait()` before announcing readiness.
func (p *Pool) Ready() *sync.WaitGroup { return p.ready }

// Shutdown stops accepting new work and tears down live connections. Returns
// once every maintainConnection goroutine has exited or ctx fires, whichever
// comes first. Safe to call multiple times; subsequent calls return ctx.Err()
// (or nil if everything had already drained on the first call).
func (p *Pool) Shutdown(ctx context.Context) error {
	p.shutdownOnce.Do(func() {
		close(p.shutdownCh)
		// Force-close every live conn so its serve loop exits via
		// ReadFrame error. Each serve's defer sends GOAWAY first if it can.
		p.connsMu.Lock()
		conns := make([]*connection, 0, len(p.conns))
		for c := range p.conns {
			conns = append(conns, c)
		}
		p.connsMu.Unlock()
		for _, c := range conns {
			_ = c.SetReadDeadline(time.Now())
		}
	})

	done := make(chan struct{})
	go func() {
		p.maintainers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Pool) registerConn(c *connection) {
	p.connsMu.Lock()
	p.conns[c] = struct{}{}
	p.connsMu.Unlock()
}

func (p *Pool) deregisterConn(c *connection) {
	p.connsMu.Lock()
	delete(p.conns, c)
	p.connsMu.Unlock()
}

// NewConnectionPool creates a pool of reverse HTTP/2 connections to the proxy
// and returns a *Pool. Call pool.Ready().Wait() to gate on first-connection
// readiness; call pool.Shutdown(ctx) to drain.
//
// Required:
//
//   - opts.TLSCert: a valid certificate + private key pair — the worker's
//     identity that the proxy verifies. Returns ErrMTLSRequired if absent.
//   - opts.Addr: the proxy's "host:port".
//   - opts.Handler: the http.Handler that incoming reverse requests run on.
//
// Optional:
//
//   - opts.CACertPool: nil falls back to the system root CAs (correct for
//     proxies whose server cert is publicly trusted, e.g. Let's Encrypt).
//   - opts.SNIServerName, opts.NBConn, opts.MaxConcurrentStreams: tuning.
func NewConnectionPool(opts ServerOptions) (*Pool, error) {
	if err := validateOptions(&opts); err != nil {
		return nil, err
	}
	if opts.NBConn == 0 {
		opts.NBConn = 1
	}
	p := &Pool{
		ready:      &sync.WaitGroup{},
		shutdownCh: make(chan struct{}),
		conns:      make(map[*connection]struct{}),
	}
	p.ready.Add(opts.NBConn)
	p.maintainers.Add(opts.NBConn)

	for i := 0; i < opts.NBConn; i++ {
		go maintainConnection(opts, p)
	}

	return p, nil
}

// validateOptions enforces the mandatory inputs. Anything we can sanity-check
// before we start spawning dial goroutines we do here, so misconfiguration
// surfaces as an immediate error rather than a silent reconnect loop.
func validateOptions(opts *ServerOptions) error {
	if opts.Addr == "" {
		return errors.New("rhttp: ServerOptions.Addr is required")
	}
	if opts.Handler == nil {
		return errors.New("rhttp: ServerOptions.Handler is required")
	}
	if len(opts.TLSCert.Certificate) == 0 || opts.TLSCert.PrivateKey == nil {
		return ErrMTLSRequired
	}
	return nil
}
