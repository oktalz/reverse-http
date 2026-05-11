package rhttp

import (
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"

	"github.com/oktalz/reverse-http/internal/h2"
	"golang.org/x/net/http2"
)

// serveStream is the worker's per-stream goroutine: it builds an http.Request
// from the decoded HEADERS block + h2.Stream body, runs the configured
// http.Handler under panic recovery, and cleans up. The h2.Stream is
// registered before this function is called and is removed on exit.
func (c *connection) serveStream(s *h2.Stream, decoded *h2.DecodedHeaders) {
	// Cleanup defer runs LAST.
	defer func() {
		c.RemoveStream(s.ID)
		h2.HeaderPool.Put(decoded.Header)
		h2.Release(s)
	}()
	// Panic-recovery defer runs FIRST. A panic in a handler is contained
	// here and surfaced to the peer as 500 (or RST_STREAM(INTERNAL_ERROR)
	// if response headers were already on the wire). The connection stays
	// usable for subsequent streams.
	rw := responseWriter{stream: s, conn: c.Conn}
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error(
				"rhttp: panic serving stream",
				"stream_id", s.ID,
				"panic", rec,
				"stack", string(debug.Stack()),
			)
			if !rw.wroteHeaders {
				rw.status = http.StatusInternalServerError
				_ = rw.writeHeaders(true)
			} else {
				s.Reset(http2.ErrCodeInternal)
			}
		}
	}()

	uri, ok := parseRequestURI(decoded.Path)
	if !ok {
		s.Reset(http2.ErrCodeProtocol)
		return
	}

	body := s.Body()
	req := &http.Request{
		Method:     decoded.Method,
		URL:        uri,
		RequestURI: decoded.Path,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     decoded.Header,
		Host:       decoded.Authority,
		Body:       body,
	}
	req = req.WithContext(s.Ctx)

	c.handler.ServeHTTP(&rw, req)

	// Close out our half of the stream (END_STREAM on response side).
	if rw.err == nil {
		_ = rw.endStream()
	}
	// If the peer hasn't finished sending the request body, tell them to
	// stop rather than waiting indefinitely for END_STREAM (RFC 7540 §8.1).
	if !s.DataDone() && rw.err == nil {
		s.Reset(http2.ErrCodeNo)
	}
	// Unblock anything still waiting on the body.
	s.CloseData()
}

// parseRequestURI is a minimal zero-alloc URL parser for HTTP/2 :path values.
// Returns a freshly-allocated *url.URL or (nil, false) on malformed paths.
func parseRequestURI(raw string) (*url.URL, bool) {
	if raw == "" || (raw[0] != '/' && raw != "*") {
		return nil, false
	}
	u := &url.URL{}
	path := raw
	if before, after, ok := strings.Cut(raw, "?"); ok {
		u.RawQuery = after
		path = before
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return nil, false
	}
	if decoded != path {
		u.RawPath = path
		u.Path = decoded
	} else {
		u.Path = path
	}
	return u, true
}
