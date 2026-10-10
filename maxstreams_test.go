package rhttp

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestProxyRespectsWorkerMaxConcurrentStreams: the proxy must never open more
// concurrent streams on a tunnel than the worker advertised in
// SETTINGS_MAX_CONCURRENT_STREAMS — strict peers (HAProxy) refuse the excess
// stream and count a glitch against the connection. With a single saturated
// tunnel the request is refused with 503 (backpressure), not forced through.
func TestProxyRespectsWorkerMaxConcurrentStreams(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	f := newProxyFixture(t, proxyFixtureOpts{
		maxStreams: 1,
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, "ok")
		}),
	})
	defer f.Close()
	defer close(release)

	type result struct {
		resp *http.Response
		body string
		err  error
	}
	res1 := make(chan result, 1)
	go func() {
		resp, err := http.Get(f.public.URL)
		var body string
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			body = string(b)
		}
		res1 <- result{resp, body, err}
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first request never reached the worker")
	}

	// Tunnel is now at its advertised limit (1). The next request must be
	// refused with 503 rather than opening a second stream.
	resp2, err := http.Get(f.public.URL)
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over-limit request: status %d (body %q), want 503", resp2.StatusCode, b2)
	}
	if !strings.Contains(string(b2), "concurrent-stream limit") {
		t.Fatalf("over-limit response body %q lacks the capacity error", b2)
	}

	// Release the first request; it must complete untouched.
	release <- struct{}{}
	select {
	case r := <-res1:
		if r.err != nil || r.resp.StatusCode != 200 || r.body != "ok" {
			t.Fatalf("first request: err=%v status=%v body=%q, want 200 %q",
				r.err, r.resp, r.body, "ok")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first request did not complete after release")
	}
}

// TestLeastInFlightSkipsSaturatedTunnels: with two tunnels of capacity 1, a
// request arriving while the first tunnel is saturated must land on the
// second instead of being refused.
func TestLeastInFlightSkipsSaturatedTunnels(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	f := newProxyFixture(t, proxyFixtureOpts{
		nbConn:     2,
		maxStreams: 1,
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, "ok")
		}),
	})
	defer f.Close()
	defer close(release)

	type result struct {
		status int
		body   string
		err    error
	}
	res1 := make(chan result, 1)
	go func() {
		resp, err := http.Get(f.public.URL)
		if err != nil {
			res1 <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		res1 <- result{resp.StatusCode, string(b), nil}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first request never reached a worker")
	}

	// First tunnel is saturated; the second request must be routed to the
	// other tunnel and complete while the first is still blocked.
	res2 := make(chan result, 1)
	go func() {
		resp, err := http.Get(f.public.URL)
		if err != nil {
			res2 <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		res2 <- result{resp.StatusCode, string(b), nil}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("second request was not routed to the free tunnel")
	}

	// Both handlers are now in flight; release them and both must succeed.
	release <- struct{}{}
	release <- struct{}{}
	for i, ch := range []chan result{res1, res2} {
		select {
		case r := <-ch:
			if r.err != nil || r.status != 200 || r.body != "ok" {
				t.Fatalf("request %d: err=%v status=%d body=%q, want 200 %q", i+1, r.err, r.status, r.body, "ok")
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("request %d did not complete", i+1)
		}
	}
}
