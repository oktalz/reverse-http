package rhttp

import (
	"errors"
	"net/http"

	"github.com/oktalz/reverse-http/internal/h2"
)

// errConnDead is returned from Write when the underlying connection has been
// torn down while a handler was blocked on flow control.
var errConnDead = errors.New("rhttp: connection closed")

// responseWriter implements http.ResponseWriter and http.Flusher for a
// worker-side HTTP/2 stream.
type responseWriter struct {
	err          error // first transport-level error from Write/Flush/writeHeaders
	stream       *h2.Stream
	conn         *h2.Conn
	status       int
	wroteHeaders bool
}

func (rw *responseWriter) Header() http.Header {
	// h2.Stream.Header is pre-allocated by the pool and cleared on acquire.
	return rw.stream.Header
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.status = statusCode
}

// Flush sends a zero-length DATA frame so any buffered response bytes leave
// the process immediately. http.Flusher's interface has no error return, so
// any failure is latched on the responseWriter and surfaced from the next
// Write.
func (rw *responseWriter) Flush() {
	if rw.err != nil {
		return
	}
	if !rw.wroteHeaders {
		if err := rw.writeHeaders(false); err != nil {
			rw.err = err
			return
		}
	}
	if err := rw.conn.SendData(rw.stream.ID, nil, false); err != nil {
		rw.err = err
	}
}

func (rw *responseWriter) writeHeaders(endStream bool) error {
	if rw.wroteHeaders {
		return nil
	}
	rw.wroteHeaders = true
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	err := rw.conn.SendResponseHeaders(rw.stream.ID, rw.status, rw.stream.Header, endStream)
	if err != nil {
		rw.err = err
	}
	return err
}

// Write emits DATA frames respecting both the conn-level and per-stream send
// windows (RFC 7540 §6.9). When credit runs out we block in Send.Reserve
// until a WINDOW_UPDATE arrives or the conn is torn down.
func (rw *responseWriter) Write(p []byte) (int, error) {
	if rw.err != nil {
		return 0, rw.err
	}
	if !rw.wroteHeaders {
		if err := rw.writeHeaders(false); err != nil {
			return 0, err
		}
	}
	if len(p) == 0 {
		return 0, nil
	}

	maxFrame := int32(rw.conn.MaxFrameSize())
	if maxFrame <= 0 {
		maxFrame = 16384
	}

	total := 0
	for len(p) > 0 {
		want := min(int32(len(p)), maxFrame)
		got, dead := rw.conn.Send.Reserve(&rw.stream.SendWindow, want)
		if dead {
			rw.err = errConnDead
			return total, errConnDead
		}
		chunk := p[:got]
		p = p[got:]

		if err := rw.conn.SendData(rw.stream.ID, chunk, false); err != nil {
			rw.err = err
			return total, err
		}
		total += int(got)
	}
	return total, nil
}

// endStream sends the final END_STREAM signal. If the handler never wrote
// any headers, we emit a HEADERS frame with END_STREAM (an empty 200
// response); otherwise we emit an empty DATA frame with END_STREAM.
func (rw *responseWriter) endStream() error {
	if !rw.wroteHeaders {
		return rw.writeHeaders(true)
	}
	err := rw.conn.SendData(rw.stream.ID, nil, true)
	if err != nil {
		rw.err = err
	}
	return err
}
