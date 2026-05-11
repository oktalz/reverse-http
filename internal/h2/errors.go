// Package h2 holds the role-agnostic HTTP/2 plumbing shared by the
// reverse-http worker (top-level package rhttp) and the reverse-http proxy
// (internal/proxy). Both sides operate on the same wire format and need
// identical framer / HPACK / flow-control / writer-goroutine / PING-liveness
// behavior; only the frame-dispatch loop and stream lifecycle differ. Anything
// duplicated between the two sides lives here.
package h2

import "errors"

// Package-level error vars — hoisted out of hot paths so each occurrence is a
// pointer comparison rather than a fresh errors.errorString allocation.
var (
	ErrConnClosed         = errors.New("rhttp/h2: connection closed")
	ErrContInterleaved    = errors.New("rhttp/h2: frame interleaved with CONTINUATION")
	ErrGoaway             = errors.New("rhttp/h2: received GOAWAY")
	ErrStreamReset        = errors.New("rhttp/h2: stream reset by peer")
	ErrHpackDecode        = errors.New("rhttp/h2: hpack decode failed")
	ErrPingTimeout        = errors.New("rhttp/h2: PING timeout")
	ErrALPN               = errors.New("rhttp/h2: peer did not negotiate ALPN h2")
	ErrHeaderListTooLarge = errors.New("rhttp/h2: header list exceeded SETTINGS_MAX_HEADER_LIST_SIZE")
	ErrBadSettings        = errors.New("rhttp/h2: peer sent invalid SETTINGS value")
)

// MaxHeaderListSize is the cap we advertise via SETTINGS_MAX_HEADER_LIST_SIZE
// and enforce locally during CONTINUATION accumulation. Without this cap, a
// peer can stream CONTINUATION frames indefinitely and force unbounded growth
// of the accumulator. 1 MiB is well above any reasonable request-header block
// and well below what would matter for OOM.
const MaxHeaderListSize uint32 = 1 << 20

// DefaultMaxConcurrentStreams matches the value most H2 servers advertise
// (Go's net/http2 transport defaults to 100). Used when callers pass zero.
const DefaultMaxConcurrentStreams uint32 = 100
