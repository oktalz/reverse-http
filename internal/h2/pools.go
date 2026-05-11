package h2

import (
	"net/http"
	"strconv"
	"sync"
)

// DataChunk pairs a data slice with its pool handle for zero-alloc return.
type DataChunk struct {
	Bp   *[]byte // pool handle; nil if not from pool
	Data []byte
}

// statusStrings is a precomputed table of status code → string so the HEADERS
// encode path doesn't allocate through strconv on every response.
var statusStrings [600]string

func init() {
	for i := range statusStrings {
		statusStrings[i] = strconv.Itoa(i)
	}
}

// StatusString returns the decimal string for an HTTP status code without
// allocating for codes in [0, 600).
func StatusString(code int) string {
	if code >= 0 && code < len(statusStrings) {
		return statusStrings[code]
	}
	return strconv.Itoa(code)
}

// ToLower returns s unchanged if it is already lowercase, avoiding an allocation.
// Used as a fallback when the per-connection lowercase cache misses.
func ToLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := make([]byte, len(s))
			copy(b, s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// dataPool buffers DATA-frame payloads so the inbound copy doesn't allocate
// for the common case (≤ 16 KB chunks).
var dataPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 16384)
		return &b
	},
}

// GetDataSlice returns a byte slice of length n drawn from dataPool, plus the
// pool handle the caller passes back via PutDataSlice once consumed.
func GetDataSlice(n int) ([]byte, *[]byte) {
	bp, _ := dataPool.Get().(*[]byte)
	if cap(*bp) < n {
		*bp = make([]byte, n)
	}
	return (*bp)[:n], bp
}

// PutDataSlice returns a pool handle obtained from GetDataSlice.
func PutDataSlice(bp *[]byte) {
	if bp != nil {
		dataPool.Put(bp)
	}
}

// HeaderPool issues http.Header maps for one-shot request/response header
// builds. Maps are cleared by the caller before reuse.
var HeaderPool = sync.Pool{
	New: func() any { return make(http.Header, 8) },
}

// CommonCanonNames is the set of header names we pre-intern on every new
// connection so the very first request doesn't allocate a canonical string per
// header. Subsequent requests on the same connection hit the per-connection
// cache and never compute textproto.CanonicalMIMEHeaderKey again.
var CommonCanonNames = map[string]string{
	"accept":            "Accept",
	"accept-encoding":   "Accept-Encoding",
	"accept-language":   "Accept-Language",
	"authorization":     "Authorization",
	"cache-control":     "Cache-Control",
	"content-encoding":  "Content-Encoding",
	"content-length":    "Content-Length",
	"content-type":      "Content-Type",
	"cookie":            "Cookie",
	"host":              "Host",
	"if-modified-since": "If-Modified-Since",
	"if-none-match":     "If-None-Match",
	"origin":            "Origin",
	"range":             "Range",
	"referer":           "Referer",
	"user-agent":        "User-Agent",
	"x-forwarded-for":   "X-Forwarded-For",
	"x-forwarded-proto": "X-Forwarded-Proto",
	"x-real-ip":         "X-Real-Ip",
	"x-request-id":      "X-Request-Id",
}

// CommonLowerNames is the response-side mirror of CommonCanonNames: handlers
// typically set headers in canonical form, and HPACK needs lowercase on the
// wire. Pre-interning the common ones means the warm path is a map hit.
var CommonLowerNames = map[string]string{
	"Content-Type":           "content-type",
	"Content-Length":         "content-length",
	"Content-Encoding":       "content-encoding",
	"Cache-Control":          "cache-control",
	"Date":                   "date",
	"Etag":                   "etag",
	"Expires":                "expires",
	"Last-Modified":          "last-modified",
	"Location":               "location",
	"Server":                 "server",
	"Set-Cookie":             "set-cookie",
	"Vary":                   "vary",
	"X-Request-Id":           "x-request-id",
	"X-Content-Type-Options": "x-content-type-options",
}
