package rhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProxySSEStreaming proves the proxy doesn't buffer the response body.
// The handler emits a chunk, signals "sent", then blocks waiting for the test
// to ack. The test reads the chunk from the public side under a deadline; if
// the proxy were buffering, Read would block until the handler returns —
// which it can't, because it needs the test's ack. The deadline catches that.
func TestProxySSEStreaming(t *testing.T) {
	const n = 3
	chunkSent := make(chan int, n)
	chunkAcked := make(chan int, n)

	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			flusher, _ := w.(http.Flusher)
			for i := range n {
				_, _ = fmt.Fprintf(w, "data: tick %d\n\n", i)
				if flusher != nil {
					flusher.Flush()
				}
				chunkSent <- i
				<-chunkAcked
			}
		}),
	})
	defer func() {
		// Unblock any stuck handler iteration before tearing the fixture
		// down — avoids a goroutine leak the race detector would flag.
		for range n {
			select {
			case chunkAcked <- 0:
			default:
			}
		}
		f.Close()
	}()

	resp, err := http.Get(f.public.URL + "/sse")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	buf := make([]byte, 1024)
	var got bytes.Buffer
	for i := range n {
		// Wait for the handler to emit chunk i. The handler then parks on
		// chunkAcked.
		select {
		case <-chunkSent:
		case <-time.After(2 * time.Second):
			t.Fatalf("handler did not emit chunk %d", i)
		}

		// Read must return promptly — if the proxy had buffered, the read
		// would block until the handler returns, but the handler can't
		// return until we ack, which we haven't done.
		readCh := make(chan int, 1)
		go func() {
			n, _ := resp.Body.Read(buf)
			readCh <- n
		}()
		select {
		case nb := <-readCh:
			_, _ = got.Write(buf[:nb])
		case <-time.After(2 * time.Second):
			t.Fatalf("read for chunk %d did not return — response is buffered", i)
		}
		chunkAcked <- i
	}

	rest, _ := io.ReadAll(resp.Body)
	_, _ = got.Write(rest)
	for i := range n {
		want := fmt.Sprintf("data: tick %d", i)
		if !strings.Contains(got.String(), want) {
			t.Errorf("missing chunk %q", want)
		}
	}
}

// TestProxyContextCancellation: the public caller's req.Context() cancel
// propagates across the tunnel as RST_STREAM, and the worker handler's
// req.Context().Done() fires.
func TestProxyContextCancellation(t *testing.T) {
	handlerStarted := make(chan struct{})
	handlerSawCancel := make(chan struct{})
	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(handlerStarted)
			select {
			case <-r.Context().Done():
				close(handlerSawCancel)
			case <-time.After(5 * time.Second):
			}
			// Don't write a response — the handler observed cancellation
			// and is exiting.
			_ = w
		}),
	})
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.public.URL+"/slow", nil)

	errCh := make(chan error, 1)
	go func() {
		_, err := http.DefaultClient.Do(req)
		errCh <- err
	}()

	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("worker handler never started")
	}

	cancel()

	select {
	case <-handlerSawCancel:
	case <-time.After(2 * time.Second):
		t.Fatal("worker handler did not observe context cancellation")
	}

	// Drain the client goroutine — it errored when ctx fired.
	<-errCh
}

// TestProxyLargeResponse round-trips a 2 MB response body through the proxy.
// Exercises multi-DATA-frame send, flow control / WINDOW_UPDATE refills on
// the worker → proxy direction, and chunked Write on the public side.
func TestProxyLargeResponse(t *testing.T) {
	const size = 2 * 1024 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(size))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		}),
	})
	defer f.Close()

	resp, err := http.Get(f.public.URL + "/big")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(body) != size {
		t.Fatalf("body size = %d, want %d", len(body), size)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("body mismatch")
	}
}

// TestProxyLargeRequest round-trips a 1 MB request body through the proxy
// and echoes it back. Exercises multi-DATA-frame send on the proxy → worker
// direction.
func TestProxyLargeRequest(t *testing.T) {
	const size = 1024 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte((i*7 + 3) % 251)
	}

	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(got)
		}),
	})
	defer f.Close()

	resp, err := http.Post(f.public.URL+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, payload) {
		t.Fatalf("echoed body mismatch (len %d vs %d)", len(body), len(payload))
	}
}

// TestProxyPublicPeerCancelMidResponse: when the public caller drops the
// connection mid-response, the proxy sends RST_STREAM toward the worker so
// the worker handler observes r.Context().Done() and stops producing.
func TestProxyPublicPeerCancelMidResponse(t *testing.T) {
	handlerStarted := make(chan struct{})
	handlerCancelled := make(chan struct{})

	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("first chunk\n"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			close(handlerStarted)
			select {
			case <-r.Context().Done():
				close(handlerCancelled)
			case <-time.After(5 * time.Second):
			}
		}),
	})
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.public.URL+"/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}

	// Read the first chunk so we know the response is in flight.
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if n == 0 {
		t.Fatal("expected first chunk before cancel")
	}

	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never reached parked state")
	}

	cancel()
	_ = resp.Body.Close()

	select {
	case <-handlerCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("worker handler did not observe peer cancellation")
	}
}

// TestProxyHopByHopHeaderStripping: hop-by-hop request headers
// (Connection, Keep-Alive, Proxy-Connection, Te, Trailer, Transfer-Encoding,
// Upgrade, Proxy-Authenticate/Authorization) are dropped before the request
// is forwarded to the worker. End-to-end headers pass through.
func TestProxyHopByHopHeaderStripping(t *testing.T) {
	headerSeen := make(map[string][]string)
	var mu sync.Mutex
	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			maps.Copy(headerSeen, r.Header)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}),
	})
	defer f.Close()

	req, _ := http.NewRequest(http.MethodGet, f.public.URL+"/h", nil)
	req.Header.Set("X-End-To-End", "preserved")
	req.Header.Set("X-Trace-Id", "abc-123")
	req.Header.Set("Proxy-Authorization", "should-be-stripped")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Upgrade", "websocket")
	// Connection is filtered by Go's http client before send, so we can't
	// reliably test it from this side. Same for Transfer-Encoding /
	// Keep-Alive on outbound requests. The proxy's filter is documented
	// belt-and-suspenders against future clients that don't strip them.

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if got := headerSeen["X-End-To-End"]; len(got) == 0 || got[0] != "preserved" {
		t.Errorf("X-End-To-End = %v, want [preserved]", got)
	}
	if got := headerSeen["X-Trace-Id"]; len(got) == 0 || got[0] != "abc-123" {
		t.Errorf("X-Trace-Id = %v, want [abc-123]", got)
	}
	for _, hop := range []string{"Proxy-Authorization", "Te", "Upgrade"} {
		if got := headerSeen[hop]; len(got) > 0 {
			t.Errorf("hop-by-hop header %q leaked to worker: %v", hop, got)
		}
	}
}

// TestProxyHostAndPathPassthrough: the public Host and request URI reach the
// worker handler as req.Host and req.URL.Path / req.URL.RawQuery.
func TestProxyHostAndPathPassthrough(t *testing.T) {
	type seen struct {
		host  string
		path  string
		query string
	}
	gotCh := make(chan seen, 1)
	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotCh <- seen{host: r.Host, path: r.URL.Path, query: r.URL.RawQuery}
			w.WriteHeader(http.StatusOK)
		}),
	})
	defer f.Close()

	req, _ := http.NewRequest(http.MethodGet, f.public.URL+"/api/v1/resource?id=42&kind=fast", nil)
	req.Host = "tenant.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case s := <-gotCh:
		if s.host != "tenant.example.com" {
			t.Errorf("Host = %q, want tenant.example.com", s.host)
		}
		if s.path != "/api/v1/resource" {
			t.Errorf("path = %q", s.path)
		}
		if s.query != "id=42&kind=fast" {
			t.Errorf("query = %q", s.query)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler never received the request")
	}
}

// ─── multi-worker fixtures ────────────────────────────────────────────────

// multiWorkerFixture sets up a Proxy with N attached workers, each with a
// distinct client-cert CN and an independent http.Handler. The fixture is
// useful for testing selector behavior.
type multiWorkerFixture struct {
	ca       *testCA
	proxy    *Proxy
	tunnelLn net.Listener
	tunnelWG sync.WaitGroup
	public   *httptest.Server
	pools    []*Pool
}

func (f *multiWorkerFixture) Close() {
	if f.public != nil {
		f.public.Close()
	}
	for _, p := range f.pools {
		if p != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = p.Shutdown(ctx)
			cancel()
		}
	}
	if f.proxy != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = f.proxy.Shutdown(ctx)
		cancel()
	}
	if f.tunnelLn != nil {
		_ = f.tunnelLn.Close()
	}
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

type workerSpec struct {
	handler http.Handler
	cn      string
}

func newMultiWorkerFixture(t *testing.T, selector ProxySelector, specs []workerSpec) *multiWorkerFixture {
	t.Helper()
	ca := newCA(t)
	serverPEM, serverKeyPEM := ca.issue(t, "127.0.0.1", true)
	serverCert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)
	tunnelTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}

	attachedCh := make(chan struct{}, len(specs))
	proxy, err := NewProxy(ProxyOptions{
		TunnelTLSConfig: tunnelTLS,
		Selector:        selector,
		OnWorkerAttach:  func(_ *ProxyWorker) { attachedCh <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	tunnelLn, err := tls.Listen("tcp", "127.0.0.1:0", tunnelTLS)
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	f := &multiWorkerFixture{
		ca:       ca,
		proxy:    proxy,
		tunnelLn: tunnelLn,
	}
	f.tunnelWG.Go(func() {
		_ = proxy.ServeTunnelListener(tunnelLn)
	})

	f.public = httptest.NewServer(proxy.Handler())

	for _, s := range specs {
		clientPEM, clientKeyPEM := ca.issue(t, s.cn, false)
		clientCert, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
		if err != nil {
			t.Fatalf("client keypair %s: %v", s.cn, err)
		}
		pool, err := NewConnectionPool(ServerOptions{
			Addr:          tunnelLn.Addr().String(),
			SNIServerName: "127.0.0.1",
			TLSCert:       clientCert,
			CACertPool:    caPool,
			Handler:       s.handler,
		})
		if err != nil {
			t.Fatalf("NewConnectionPool %s: %v", s.cn, err)
		}
		pool.Ready().Wait()
		f.pools = append(f.pools, pool)
	}

	for i := range specs {
		select {
		case <-attachedCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("worker %d (%s) did not attach within 5s", i, specs[i].cn)
		}
	}
	return f
}

// TestProxyRoundRobinDistribution: with two workers attached and a
// round-robin selector, 2N concurrent requests are split evenly (±1) between
// them. Sequential issuing keeps the counter advance deterministic.
func TestProxyRoundRobinDistribution(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	f := newMultiWorkerFixture(t, ProxyRoundRobin(), []workerSpec{
		{cn: "worker-A", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hitsA.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "A")
		})},
		{cn: "worker-B", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hitsB.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "B")
		})},
	})
	defer f.Close()

	const n = 20
	for range n {
		resp, err := http.Get(f.public.URL + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}

	a, b := hitsA.Load(), hitsB.Load()
	if a+b != n {
		t.Fatalf("hits A=%d B=%d sum=%d, want %d", a, b, a+b, n)
	}
	// RoundRobin should produce exactly n/2 each over sequential issuing.
	if a < n/2-1 || a > n/2+1 {
		t.Errorf("round-robin imbalance: A=%d B=%d (each ~%d)", a, b, n/2)
	}
}

// TestProxyLeastInFlightDistribution: default selector spreads concurrent
// requests across workers. Both workers should receive at least one request.
// We don't assert exact balance (the selector is best-effort under racy
// in-flight counter reads), only that the load isn't dumped on one worker.
func TestProxyLeastInFlightDistribution(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	// Both handlers block briefly so concurrent requests pile up and the
	// least-in-flight signal becomes meaningful.
	slowHandler := func(counter *atomic.Int64) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			counter.Add(1)
			time.Sleep(30 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		})
	}
	f := newMultiWorkerFixture(t, nil /* default LeastInFlight */, []workerSpec{
		{cn: "worker-A", handler: slowHandler(&hitsA)},
		{cn: "worker-B", handler: slowHandler(&hitsB)},
	})
	defer f.Close()

	const n = 20
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range n {
		wg.Go(func() {
			resp, err := http.Get(f.public.URL + "/")
			if err != nil {
				failures.Add(1)
				return
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		})
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d/%d requests failed", failures.Load(), n)
	}

	a, b := hitsA.Load(), hitsB.Load()
	if a+b != n {
		t.Fatalf("hits A=%d B=%d sum=%d, want %d", a, b, a+b, n)
	}
	if a == 0 || b == 0 {
		t.Fatalf("least-in-flight should spread load: A=%d B=%d", a, b)
	}
}

// TestProxyResponseHeaderPassthrough: response headers set by the worker
// reach the public caller verbatim (including casing on retrieval, set-cookie
// multi-value, etc.).
func TestProxyResponseHeaderPassthrough(t *testing.T) {
	f := newProxyFixture(t, proxyFixtureOpts{
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Custom", "ok")
			w.Header().Add("Set-Cookie", "a=1")
			w.Header().Add("Set-Cookie", "b=2")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	})
	defer f.Close()

	resp, err := http.Get(f.public.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Custom"); got != "ok" {
		t.Errorf("X-Custom = %q", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 2 {
		t.Errorf("Set-Cookie values = %v (want 2)", cookies)
	}
}
