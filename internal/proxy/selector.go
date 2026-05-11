// Package proxy implements the server-side counterpart to the reverse-http
// worker (package rhttp). It accepts mTLS HTTP/2 tunnel connections from
// workers and dispatches inbound public HTTP requests over those tunnels,
// returning the worker's responses back to the public caller.
//
// The wire format is the IETF reverse-HTTP draft: workers act as TCP clients
// but at the HTTP/2 level the proxy is the side that *initiates* streams
// (odd-numbered IDs, per RFC 7540 §5.1.1). Each public request becomes one
// outbound stream toward a worker, picked by the configured Selector.
package proxy

import (
	"net/http"
	"sync/atomic"
)

// Selector picks the worker that a given public request should be forwarded
// to. Implementations must tolerate a nil-or-empty workers slice (in which
// case they return nil; the caller surfaces 503).
//
// The slice is a snapshot — implementations may not retain it past the
// Pick call. Worker fields read by selectors are safe for concurrent read.
type Selector interface {
	Pick(req *http.Request, workers []*Worker) *Worker
}

// SelectorFunc adapts an ordinary function to the Selector interface.
type SelectorFunc func(req *http.Request, workers []*Worker) *Worker

// Pick implements Selector.
func (f SelectorFunc) Pick(req *http.Request, workers []*Worker) *Worker {
	return f(req, workers)
}

// LeastInFlight returns a Selector that picks the worker with the fewest
// currently-active outbound streams. Ties broken by lowest worker index
// (deterministic). Default if Options.Selector is nil.
func LeastInFlight() Selector {
	return SelectorFunc(leastInFlightPick)
}

func leastInFlightPick(_ *http.Request, workers []*Worker) *Worker {
	if len(workers) == 0 {
		return nil
	}
	var best *Worker
	var bestN int64 = -1
	for _, w := range workers {
		n := w.inFlight.Load()
		if best == nil || n < bestN {
			best = w
			bestN = n
		}
	}
	return best
}

// RoundRobin returns a Selector that picks workers in round-robin order. The
// counter is shared across calls — supply a fresh selector per Proxy if you
// want isolated state.
func RoundRobin() Selector {
	var seq atomic.Uint64
	return SelectorFunc(func(_ *http.Request, workers []*Worker) *Worker {
		if len(workers) == 0 {
			return nil
		}
		i := seq.Add(1) - 1
		return workers[int(i%uint64(len(workers)))]
	})
}
