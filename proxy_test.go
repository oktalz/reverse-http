package rhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// proxyFixture bundles a running Proxy + one attached worker + the public-
// side httptest.Server. Tests build it via newProxyFixture and call its
// methods to exercise the round-trip.
type proxyFixture struct {
	ca       *testCA
	proxy    *Proxy
	pool     *Pool
	tunnelLn net.Listener
	tunnelWG sync.WaitGroup
	public   *httptest.Server
}

// Close tears everything down with a generous deadline. Safe to call once.
func (f *proxyFixture) Close() {
	if f.public != nil {
		f.public.Close()
	}
	if f.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = f.pool.Shutdown(ctx)
		cancel()
	}
	if f.proxy != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = f.proxy.Shutdown(ctx)
		cancel()
	}
	if f.tunnelLn != nil {
		_ = f.tunnelLn.Close()
	}
	// Don't fail the test if the tunnel-accept goroutine takes a moment
	// to unwind; Shutdown's WaitGroup already covered that path.
	doneCh := make(chan struct{})
	go func() {
		f.tunnelWG.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
	}
}

// proxyFixtureOpts tweaks the fixture for individual tests. Zero values
// inherit sensible defaults.
type proxyFixtureOpts struct {
	handler        http.Handler
	selector       ProxySelector
	onWorkerAttach func(*ProxyWorker)
	nbConn         int
}

// newProxyFixture builds: a CA, server+client certs, a Proxy listening on a
// fresh loopback TLS port, an httptest.Server fronting Proxy.Handler(), and
// a worker pool dialled in. Returns once the worker has attached.
func newProxyFixture(t *testing.T, fopts proxyFixtureOpts) *proxyFixture {
	t.Helper()
	if fopts.handler == nil {
		fopts.handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "ok")
		})
	}
	if fopts.nbConn == 0 {
		fopts.nbConn = 1
	}

	ca := newCA(t)

	serverPEM, serverKeyPEM := ca.issue(t, "127.0.0.1", true)
	serverCert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	clientPEM, clientKeyPEM := ca.issue(t, "rhttp-worker", false)
	clientCert, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	attachedCh := make(chan struct{}, fopts.nbConn+1)
	hook := fopts.onWorkerAttach
	tunnelTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}
	proxy, err := NewProxy(ProxyOptions{
		TunnelTLSConfig: tunnelTLS,
		Selector:        fopts.selector,
		OnWorkerAttach: func(w *ProxyWorker) {
			if hook != nil {
				hook(w)
			}
			attachedCh <- struct{}{}
		},
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	// Pre-build the tunnel listener so we know the bind address before the
	// worker starts dialling.
	tunnelLn, err := tls.Listen("tcp", "127.0.0.1:0", tunnelTLS)
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	f := &proxyFixture{
		ca:       ca,
		proxy:    proxy,
		tunnelLn: tunnelLn,
	}
	f.tunnelWG.Go(func() {
		_ = proxy.ServeTunnelListener(tunnelLn)
	})

	// httptest.Server fronts the proxy's public Handler. Plain HTTP/1.1 is
	// fine — the proxy's job is to forward across the tunnel, not to be the
	// public TLS terminator.
	f.public = httptest.NewServer(proxy.Handler())

	// Bring up the worker pool. Uses the worker cert against the proxy's
	// CA. Use 127.0.0.1 (also in the SANs) for the dial host.
	host, port, err := net.SplitHostPort(tunnelLn.Addr().String())
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	pool, err := NewConnectionPool(ServerOptions{
		Addr:          net.JoinHostPort(host, port),
		SNIServerName: "127.0.0.1",
		TLSCert:       clientCert,
		CACertPool:    caPool,
		Handler:       fopts.handler,
		NBConn:        fopts.nbConn,
	})
	if err != nil {
		t.Fatalf("NewConnectionPool: %v", err)
	}
	f.pool = pool
	pool.Ready().Wait()

	// Wait for the attach hook to fire — pool.Ready() means the worker
	// completed its TLS handshake, but the proxy still needs to read the
	// preface and finish setup before forwarding can succeed.
	for i := 0; i < fopts.nbConn; i++ {
		select {
		case <-attachedCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("worker %d did not attach within 5s", i)
		}
	}

	return f
}

// TestProxyBasicRoundTrip: GET → 200 with a body, end-to-end through a
// Proxy + one worker.
func TestProxyBasicRoundTrip(t *testing.T) {
	var hits atomic.Int32
	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("X-Test", "yes")
			w.WriteHeader(200)
			_, _ = fmt.Fprintf(w, "hello %s", r.URL.Path)
		}),
	})
	defer f.Close()

	resp, err := http.Get(f.public.URL + "/world")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Test"); got != "yes" {
		t.Fatalf("X-Test = %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello /world" {
		t.Fatalf("body = %q", body)
	}
	if hits.Load() != 1 {
		t.Fatalf("handler hits = %d, want 1", hits.Load())
	}
}

// TestProxyPostBody: a POST body round-trips intact through the proxy.
func TestProxyPostBody(t *testing.T) {
	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(200)
			_, _ = w.Write(body)
		}),
	})
	defer f.Close()

	payload := strings.Repeat("ab", 32*1024) // 64 KB — exceeds default initial window for at least one DATA frame
	resp, err := http.Post(f.public.URL+"/echo", "application/octet-stream", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != payload {
		t.Fatalf("echoed body length %d != %d", len(body), len(payload))
	}
}

// TestProxyConcurrentRequests: many concurrent requests against one worker
// all succeed. Stresses stream-id allocation, stream-registry concurrency,
// and the per-tunnel flow-control machinery.
func TestProxyConcurrentRequests(t *testing.T) {
	var hits atomic.Int32
	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "ok")
		}),
	})
	defer f.Close()

	const n = 50
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range n {
		wg.Go(func() {
			resp, err := http.Get(f.public.URL + "/")
			if err != nil {
				failures.Add(1)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				failures.Add(1)
				return
			}
			_, _ = io.ReadAll(resp.Body)
		})
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d/%d requests failed", failures.Load(), n)
	}
	if hits.Load() != int32(n) {
		t.Fatalf("handler hits = %d, want %d", hits.Load(), n)
	}
}

// TestProxyNoWorker: with zero workers attached, public requests return 503.
func TestProxyNoWorker(t *testing.T) {
	ca := newCA(t)
	serverPEM, serverKeyPEM := ca.issue(t, "127.0.0.1", true)
	serverCert, _ := tls.X509KeyPair(serverPEM, serverKeyPEM)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)
	proxy, err := NewProxy(ProxyOptions{
		TunnelTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2"},
		},
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = proxy.Shutdown(ctx)
		cancel()
	}()

	srv := httptest.NewServer(proxy.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// TestProxyWorkerSelector: with multiple workers attached, a custom selector
// can pin requests to a specific worker. Distinct client-cert CNs let the
// selector match by identity rather than attach order — so the test stays
// deterministic regardless of which pool finishes its handshake first.
func TestProxyWorkerSelector(t *testing.T) {
	var workerA, workerB atomic.Int32

	selectorFn := ProxySelectorFunc(func(_ *http.Request, workers []*ProxyWorker) *ProxyWorker {
		for _, w := range workers {
			if w.CommonName() == "worker-A" {
				return w
			}
		}
		return nil
	})

	caF := newCA(t)
	serverPEM, serverKeyPEM := caF.issue(t, "127.0.0.1", true)
	serverCert, _ := tls.X509KeyPair(serverPEM, serverKeyPEM)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caF.certPEM)
	tunnelTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}

	attachedCh := make(chan *ProxyWorker, 4)
	proxy, err := NewProxy(ProxyOptions{
		TunnelTLSConfig: tunnelTLS,
		Selector:        selectorFn,
		OnWorkerAttach:  func(w *ProxyWorker) { attachedCh <- w },
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = proxy.Shutdown(ctx)
		cancel()
	}()
	tunnelLn, err := tls.Listen("tcp", "127.0.0.1:0", tunnelTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tunnelLn.Close()
	go func() { _ = proxy.ServeTunnelListener(tunnelLn) }()

	publicSrv := httptest.NewServer(proxy.Handler())
	defer publicSrv.Close()

	makePool := func(cn, tag string, counter *atomic.Int32) *Pool {
		clientPEM, clientKeyPEM := caF.issue(t, cn, false)
		clientCert, _ := tls.X509KeyPair(clientPEM, clientKeyPEM)
		pool, err := NewConnectionPool(ServerOptions{
			Addr:          tunnelLn.Addr().String(),
			SNIServerName: "127.0.0.1",
			TLSCert:       clientCert,
			CACertPool:    caPool,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				counter.Add(1)
				w.WriteHeader(200)
				_, _ = io.WriteString(w, tag)
			}),
		})
		if err != nil {
			t.Fatalf("NewConnectionPool(%s): %v", tag, err)
		}
		pool.Ready().Wait()
		return pool
	}
	poolA := makePool("worker-A", "A", &workerA)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = poolA.Shutdown(ctx)
		cancel()
	}()
	poolB := makePool("worker-B", "B", &workerB)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = poolB.Shutdown(ctx)
		cancel()
	}()
	// Wait for both attaches before firing requests.
	<-attachedCh
	<-attachedCh

	const n = 10
	for i := range n {
		resp, err := http.Get(publicSrv.URL + "/")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "A" {
			t.Fatalf("request %d served by %q, want A", i, body)
		}
	}
	if workerA.Load() != int32(n) {
		t.Fatalf("workerA hits = %d, want %d", workerA.Load(), n)
	}
	if workerB.Load() != 0 {
		t.Fatalf("workerB hits = %d, want 0 (selector pinned to worker-A)", workerB.Load())
	}
}

// TestProxyWorkerDetach: when the worker pool shuts down, in-flight requests
// see a 502 (rather than hanging forever).
func TestProxyWorkerDetach(t *testing.T) {
	handlerStarted := make(chan struct{})
	handlerBlock := make(chan struct{})
	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(handlerStarted)
			select {
			case <-handlerBlock:
			case <-r.Context().Done():
			}
			w.WriteHeader(200)
		}),
	})
	defer f.Close()

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.Get(f.public.URL + "/")
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started")
	}

	// Shut down the worker pool. The proxy's in-flight request must return
	// promptly — the exact shape depends on a race between the worker's
	// ctx-cancelled handler completing a default 200 vs the conn-teardown
	// path reaching the proxy first:
	//
	//   - 5xx (BadGateway): the proxy noticed the tunnel die before any
	//     response headers arrived.
	//   - 200 with empty body: the worker's handler observed r.Context()
	//     cancellation, exited without writing, and the worker's net/http
	//     default of 200 reached the proxy before the conn closed.
	//   - transport error: the public-side connection was dropped mid-read.
	//
	// All three are correct outcomes; what's NOT acceptable is a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = f.pool.Shutdown(ctx)
	cancel()

	select {
	case resp := <-respCh:
		_ = resp.Body.Close()
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not return within 3s after worker detach")
	}

	// Unblock the handler so its goroutine exits before we tear the
	// fixture down (avoids -race noise).
	close(handlerBlock)
}

// TestProxyShutdownDrains: Proxy.Shutdown returns within ctx.
func TestProxyShutdownDrains(t *testing.T) {
	f := newProxyFixture(t, proxyFixtureOpts{})
	// Don't defer f.Close — we test Shutdown directly.

	// Quick sanity request to confirm we're actually serving.
	resp, err := http.Get(f.public.URL + "/")
	if err != nil {
		t.Fatalf("warmup GET: %v", err)
	}
	_ = resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := f.proxy.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("Shutdown took too long: %v", elapsed)
	}

	// Cleanup the rest.
	f.public.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	_ = f.pool.Shutdown(ctx2)
	cancel2()
	_ = f.tunnelLn.Close()
}
