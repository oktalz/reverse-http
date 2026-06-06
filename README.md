# reverse-http

> ⚠️ **Alpha — subject to change.** This library is in early development. The API, behavior, and on-the-wire details may change without notice between releases. Not recommended for production use.

A Go implementation of [Reverse HTTP](https://github.com/haproxy/wiki/wiki/Reverse-HTTP) ([IETF draft](https://www.ietf.org/archive/id/draft-bt-httpbis-reverse-http-01.html)) — both sides of the protocol.

- **Worker** (`NewConnectionPool`) — dials a proxy over TLS, speaks HTTP/2, and serves incoming requests *back over the same connection* using a raw `http2.Framer`. A service behind NAT or a firewall can accept public traffic without inbound connectivity while reusing the standard `net/http` handler interface.
- **Proxy / server** (`NewProxy`) — accepts inbound mTLS HTTP/2 tunnels from workers and forwards public HTTP requests across them. A drop-in Go equivalent of the HAProxy `rhttp@` backend; usable when you don't want HAProxy in the picture.

Module: `github.com/oktalz/reverse-http`

## Why

- No inbound ports on the application host — only an outbound TLS connection to the proxy.
- Mutual TLS authenticates the worker to the proxy.
- One connection pool, many concurrent streams (HTTP/2 multiplexing).
- Auto-reconnect with jittered backoff; PING-based liveness.
- Standard `net/http.Handler`: `http.Flusher`, `req.Context()`, panic recovery — works the way you'd expect.
- Graceful shutdown: `pool.Shutdown(ctx)` sends GOAWAY and drains in-flight requests within your deadline.

## Install

```sh
go get github.com/oktalz/reverse-http
```

Requires Go 1.25+.

## Worker usage

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "log"
    "net/http"
    "os"

    rhttp "github.com/oktalz/reverse-http"
)

func main() {
    cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
    if err != nil {
        log.Fatal(err)
    }

    // CA that signed the proxy's server cert — used to verify HAProxy.
    // Skip this whole block (leave CACertPool nil below) when the proxy
    // uses a publicly-trusted cert and you're happy verifying it against
    // the host's system root CAs.
    caPEM, err := os.ReadFile("proxy-ca.crt")
    if err != nil {
        log.Fatal(err)
    }
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caPEM)

    mux := http.NewServeMux()
    mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("hello from behind the proxy\n"))
    })

    pool, err := rhttp.NewConnectionPool(rhttp.ServerOptions{
        Addr:          "proxy.example.com:443",
        SNIServerName: "proxy.example.com",
        TLSCert:       cert,
        CACertPool:    caPool,
        Handler:       mux,
        NBConn:        4,
    })
    if err != nil {
        log.Fatal(err) // e.g. ErrMTLSRequired when TLSCert is missing
    }

    pool.Ready().Wait() // blocks until each slot has completed its first dial
    log.Println("worker connected; serving reverse traffic")

    // Graceful shutdown:
    //   ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    //   defer cancel()
    //   _ = pool.Shutdown(ctx)
    select {} // block; pool reconnects internally on drop
}
```

### ServerOptions

| Field                  | Purpose                                                                                                                                                          |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Addr`                 | `host:port` of the reverse-HTTP proxy. **Required.**                                                                                                              |
| `Handler`              | `http.Handler` invoked for each incoming reverse request. **Required.**                                                                                           |
| `TLSCert`              | Client certificate presented to the proxy (mTLS). **Required** — `NewConnectionPool` returns `ErrMTLSRequired` if absent.                                         |
| `CACertPool`           | Roots used to verify the proxy's certificate. **Optional**: nil falls back to the host's system root CAs (correct for publicly-trusted proxy certs like LE).      |
| `SNIServerName`        | TLS SNI / `ServerName` sent in ClientHello. **Optional**: empty lets `tls.Dial` auto-derive from the host part of `Addr`. Set explicitly when `Addr` is an IP, when the cert is for a different name than the dial host, or for multi-tenant SNI-cert selection. |
| `NBConn`               | Number of parallel reverse connections to maintain. Default 1.                                                                                                    |
| `MaxConcurrentStreams` | `SETTINGS_MAX_CONCURRENT_STREAMS` advertised per tunnel. Default 100.                                                                                             |

### Pool API

`NewConnectionPool` returns a `*Pool`:

| Method                       | Behavior                                                                                                                                                                                                                |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pool.Ready() *sync.WaitGroup` | Completes once every slot has had at least one successful dial + handshake. Use as a startup gate before announcing readiness.                                                                                          |
| `pool.Shutdown(ctx) error`   | Stops accepting new requests, signals each live connection's serve loop to exit (which sends `GOAWAY(last-stream-id, NO_ERROR)` before closing), and waits for every `maintainConnection` goroutine to exit or `ctx` to fire. Safe to call multiple times; returns `ctx.Err()` if the deadline trips before drainage completes. |

```go
pool, err := rhttp.NewConnectionPool(opts)
if err != nil { log.Fatal(err) }

pool.Ready().Wait()              // ready to serve

// ...later, on SIGTERM:
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
if err := pool.Shutdown(ctx); err != nil {
    log.Printf("shutdown: %v", err) // ctx.Err() if drain timed out
}
```

### Handler behavior

The `http.ResponseWriter` and `*http.Request` your handler receives behave like a standard `net/http` server:

- **`http.Flusher`** — cast `w.(http.Flusher).Flush()` for SSE / chunked streaming. A zero-length DATA frame is sent immediately so the client sees the bytes flushed so far.
- **`req.Context()`** — fires (`context.Canceled`) when the peer sends `RST_STREAM`, when the connection dies, or when `Pool.Shutdown` tears the conn down. Use it for downstream call cancellation:
  ```go
  resp, err := http.NewRequestWithContext(r.Context(), "GET", upstream, nil)
  ```
- **Panic recovery** — a panic in a handler is caught per request, logged via the default `slog` logger as a structured Error event (fields: `stream_id`, `panic`, `stack`; redirect or reformat with `slog.SetDefault(...)`), and surfaced as a `500 Internal Server Error` (or `RST_STREAM(INTERNAL_ERROR)` if the response headers were already on the wire). The connection stays usable for subsequent streams.
- **Forbidden response headers** — `Connection`, `Keep-Alive`, `Upgrade`, `Transfer-Encoding`, `Proxy-Connection` are filtered before HPACK encoding per RFC 9113 §8.2.2. HAProxy rejects them otherwise.
- **No `SetWriteDeadline`** — intentionally not implemented. The underlying TCP conn is shared across every stream on a tunnel; a per-handler deadline would silently affect every other in-flight request. Use `req.Context()` deadlines instead.

### Streaming responses (SSE, chunked output)

The `ResponseWriter` returned to your handler implements `http.Flusher`, so server-sent events and chunked streaming work as usual:

```go
mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    flusher := w.(http.Flusher)

    for i := 0; i < 15; i++ {
        fmt.Fprintf(w, "data: tick %d\n\n", i)
        flusher.Flush()
        time.Sleep(200 * time.Millisecond)
    }
})
```

### Reading a request body (POST)

```go
mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    w.Header().Set("Content-Type", "application/octet-stream")
    w.Write(body)
})
```

## Proxy / server usage

The library also ships a Go-native proxy that can replace HAProxy for the reverse-http role. It accepts mTLS+h2 tunnel connections from workers and exposes the public side as an `http.Handler` (mount it anywhere) or via `ListenAndServePublic` (turnkey).

```go
package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "log"
    "os"

    rhttp "github.com/oktalz/reverse-http"
)

func main() {
    serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatal(err)
    }
    workersCA, err := os.ReadFile("workers-ca.crt")
    if err != nil {
        log.Fatal(err)
    }
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(workersCA)

    p, err := rhttp.NewProxy(rhttp.ProxyOptions{
        TunnelTLSConfig: &tls.Config{
            Certificates: []tls.Certificate{serverCert},
            ClientAuth:   tls.RequireAndVerifyClientCert,
            ClientCAs:    caPool,
            MinVersion:   tls.VersionTLS12,
            NextProtos:   []string{"h2"},
        },
        // Selector picks a worker per public request. Default is least-in-flight.
        // Use rhttp.ProxyRoundRobin() or a custom rhttp.ProxySelector if you want
        // sticky routing, per-tenant pinning, etc.
        // Selector: rhttp.ProxyRoundRobin(),
    })
    if err != nil {
        log.Fatal(err)
    }

    // Worker-facing listener (mTLS, ALPN h2):
    go func() { log.Fatal(p.ListenAndServeTunnels(":8443")) }()

    // Public-facing listener — turnkey path. Pass nil for plain HTTP behind a
    // separate TLS terminator, or pass a *tls.Config to terminate here.
    log.Fatal(p.ListenAndServePublic(":443", nil))

    // Graceful shutdown:
    //   ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    //   defer cancel()
    //   _ = p.Shutdown(ctx)
    _ = context.Background()
}
```

### ProxyOptions

| Field                  | Purpose                                                                                                                                                                                                                                                                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `TunnelTLSConfig`      | TLS config for the worker-facing listener. **Required.** Set `Certificates` (server cert) and `ClientAuth: RequireAndVerifyClientCert` + `ClientCAs` (the CA that signed legitimate worker certs). `h2` is added to `NextProtos` automatically if missing.                                                                                       |
| `Selector`             | `ProxySelector` that picks a worker per public request. **Optional**: default is least-in-flight. Helpers: `ProxyLeastInFlight()`, `ProxyRoundRobin()`, `ProxySelectorFunc`.                                                                                                                                                                     |
| `Logger`               | `*slog.Logger` for tunnel diagnostics (attach/detach, protocol errors). Per-request failures still surface to the public caller as 5xx. **Optional**: nil = silent.                                                                                                                                                                              |
| `OnWorkerAttach` / `OnWorkerDetach` | Hooks fired as workers come and go. **Optional**. Inspect `Worker.Certificate()` / `.CommonName()` for identity-driven gating beyond what TLS does.                                                                                                                                                                          |
| `MaxConcurrentStreams` | Advertised to each worker in `SETTINGS_MAX_CONCURRENT_STREAMS`. Zero = H2 default (100).                                                                                                                                                                                                                                                          |

### Proxy public-side options

| Method                         | Behaviour                                                                                                                                              |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `p.Handler() http.Handler`     | Bare handler — mount on any `net/http` server / mux / TLS listener you prefer. Most flexible.                                                          |
| `p.ListenAndServePublic(addr, tlsConfig)` | Turnkey listener. `tlsConfig == nil` serves plain HTTP (behind a separate TLS terminator).                                                  |
| `p.ListenAndServeTunnels(addr)` | Bind addr and accept worker tunnels over TLS. Blocks until `Shutdown`.                                                                                |
| `p.ServeTunnelListener(ln)`     | Accept tunnels on a pre-built `net.Listener` (must yield `*tls.Conn` with ALPN `h2`).                                                                 |
| `p.Workers() []*ProxyWorker`    | Snapshot of attached workers — inspect for monitoring / admin endpoints.                                                                              |
| `p.Shutdown(ctx) error`         | Stop accepting new tunnels, fail in-flight forwards on attached workers (5xx to public), wait for accept goroutines to exit. Idempotent.              |

### Worker auth model

Workers are authenticated entirely by the TLS layer: any client cert chaining to `ClientCAs` is accepted. There is no built-in CN allow-list. Use `OnWorkerAttach` or a `ProxySelector` if you want finer-grained gating — both have access to `Worker.Certificate()` (the full `*x509.Certificate`) and `Worker.CommonName()`. This is intentional: the CA bundle is the trust boundary, and per-deployment identity policy belongs in your code, not a config flag.

### Selector

`ProxySelector.Pick(req, workers)` runs per public request. Returning `nil` produces a 503. Built-in helpers:

- `ProxyLeastInFlight()` — pick the worker with the fewest currently-in-flight forwards. **Default.**
- `ProxyRoundRobin()` — strict round-robin.
- `ProxySelectorFunc(f)` — adapt any function.

A typical custom selector pins requests to a specific worker (sticky routing, per-tenant slicing):

```go
sel := rhttp.ProxySelectorFunc(func(req *http.Request, workers []*rhttp.ProxyWorker) *rhttp.ProxyWorker {
    tenant := req.Header.Get("X-Tenant")
    for _, w := range workers {
        if w.CommonName() == "worker-"+tenant {
            return w
        }
    }
    return nil // → 503
})
```

## How it works

1. Each pool slot dials the proxy over TLS with ALPN `h2`. `TCP_NODELAY` is set on the underlying socket so small framed writes (headers, flushes, PINGs) aren't held by Nagle.
2. After the handshake, the client writes the HTTP/2 client preface and a `SETTINGS` frame advertising `MAX_CONCURRENT_STREAMS` (default 100) and `MAX_HEADER_LIST_SIZE` (1 MiB) — but does **not** open streams itself.
3. The proxy initiates streams *toward* the client (one per inbound request).
4. The library decodes HEADERS/DATA frames, builds a `*http.Request` with a per-request context, and dispatches to your `Handler`.
5. The handler's writes are funnelled through a single dedicated writer goroutine per connection — so concurrent streams don't serialise on a write mutex.

Idle connections are kept alive with PING frames (`pingInterval = 30s`, `pingTimeout = 15s`); on drop the slot reconnects after a 1.0–1.5 s jittered backoff to avoid thundering-herd reconnects on proxy restart. The peer's `SETTINGS_MAX_FRAME_SIZE`, `INITIAL_WINDOW_SIZE`, and `HEADER_TABLE_SIZE` are honored; out-of-spec values are rejected with `PROTOCOL_ERROR` / `FLOW_CONTROL_ERROR`.

## Certificates (mandatory mTLS)

The library refuses to start without mutual TLS. Without client-cert
authentication, an exposed reverse-http proxy port would accept HTTP
traffic from anyone who can reach it — that's almost never what you want.
`NewConnectionPool` returns `ErrMTLSRequired` if you forget the worker
identity or the CA bundle.

You need three PEM files on **each side** of the tunnel:

| Worker (this library) needs | Purpose |
| --- | --- |
| `client.crt` + `client.key` (`ServerOptions.TLSCert`) | The worker's identity. The proxy verifies it against its CA bundle. **Required.** |
| `proxy-ca.pem` (`ServerOptions.CACertPool`) | Trust root for the proxy's server cert. **Optional** — nil falls back to the host's system root CAs, which is correct when the proxy uses a publicly-trusted cert (e.g. Let's Encrypt). Set explicitly when the proxy uses a self-signed / internal-CA cert. |

| HAProxy (the proxy) needs | Purpose |
| --- | --- |
| `server.pem` (`bind ssl crt ...`) | HAProxy's server cert + key (one file: cert PEM followed by key PEM). Workers verify this. |
| `workers-ca.crt` (`bind ca-file ... verify required`) | Trust root for client certs. Any client cert not chaining here is rejected during TLS handshake. |

### Two CAs, two different jobs

`proxy-ca.pem` and `workers-ca.crt` are both "CAs", but they serve
**opposite directions of the handshake** and are usually not the same
file. Mixing them up produces a TLS verification failure that looks
mysterious in logs.

| Direction | Who verifies whom | CA needed | Lives where |
| --- | --- | --- | --- |
| Worker → HAProxy | Worker checks HAProxy's server cert | CA that signed **HAProxy's server cert** | On the worker, passed as `CACertPool` / `--rhttp-ca` |
| HAProxy → Worker | HAProxy checks the worker's client cert | CA that signed **worker certs** | On HAProxy, named in `bind ... ca-file` |

If you run HAProxy with a Let's Encrypt cert (typical for a public-facing
proxy) and your worker certs are minted by your own internal CA (typical,
since LE doesn't issue client-auth certs), the two CAs are different
files and they should stay that way:

- The worker's `--rhttp-ca` is the **Let's Encrypt issuer chain** for
  the proxy's hostname.
- HAProxy's `bind ca-file` is the **internal workers CA** produced by
  `gen-certs.sh`.

Only in a self-contained setup where one internal CA signs everything
(both the HAProxy server cert and every worker cert) are the two CA
files literally the same PEM. That setup is fine for closed networks
but rare in production; if you're using LE for your public hostname,
you're in the two-CA case by default.

A minimal worker setup:

```go
cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
if err != nil { log.Fatal(err) }

caPEM, err := os.ReadFile("proxy-ca.pem")
if err != nil { log.Fatal(err) }
caPool := x509.NewCertPool()
caPool.AppendCertsFromPEM(caPEM)

pool, err := rhttp.NewConnectionPool(rhttp.ServerOptions{
    Addr:          "proxy.example.com:8443",
    SNIServerName: "proxy.example.com",
    TLSCert:       cert,      // worker identity
    CACertPool:    caPool,    // verify the proxy
    Handler:       mux,
    NBConn:        4,
})
if err != nil { log.Fatal(err) }   // ErrMTLSRequired etc.
```

And the matching HAProxy bind line (full config in
[`examples/haproxy/haproxy.cfg`](examples/haproxy/haproxy.cfg)):

```
bind 0.0.0.0:8443 ssl crt /etc/haproxy/server.pem \
    ca-file /etc/haproxy/workers-ca.crt verify required \
    alpn h2 idle-ping 1m

acl is_worker ssl_c_s_dn(CN) -m str worker.example
tcp-request session attach-srv app/workers if is_worker
tcp-request session reject unless is_worker
```

### Generating a tiny in-house PKI

For a small fleet, a one-off CA + per-worker cert is fine. The repo ships
a helper script at [`examples/pki/gen-certs.sh`](examples/pki/gen-certs.sh) that
mints a CA on first run and one client cert per worker name:

```sh
./examples/pki/gen-certs.sh                       # CA + cert with CN "rhttp-worker"
./examples/pki/gen-certs.sh worker-1 worker-2     # two named worker certs (same CA)
./examples/pki/gen-certs.sh -d ./pki worker-1     # custom output dir
```

Re-running the script reuses the existing `workers-ca.crt`+`workers-ca.key`
in the output directory — so adding another worker later is a single
command, and the HAProxy `ca-file` never has to be updated.

Output files (in `./rhttp-certs/` by default):

| File | Purpose | Where it goes |
| --- | --- | --- |
| `workers-ca.crt` | CA public cert | Copy to HAProxy box (e.g. `/etc/haproxy/workers-ca.crt`). Referenced from the `bind` line via `ca-file ... verify required`. |
| `workers-ca.key` | CA private key | **Keep offline**. Only this script needs it; don't ship to either server. Back it up like a password. |
| `<worker>.crt` | Worker client cert | Copy to the worker box. Pass as `TLSCert` (or `--rhttp-cert`). |
| `<worker>.key` | Worker private key | Copy to the worker box. `chmod 600`. Pass as the key half of `TLSCert` (or `--rhttp-key`). |

The HAProxy *server* cert (what workers verify HAProxy with) is a
separate concern — typically Let's Encrypt or whatever already serves
your public site. The worker passes that LE issuer chain via
`ServerOptions.CACertPool`; it's unrelated to the CA generated above.

## HAProxy configuration

A complete minimal recommended config is in
[`examples/haproxy/haproxy.cfg`](examples/haproxy/haproxy.cfg). The four lines specific
to the reverse-http backend (besides the mTLS bind line above):

```
backend app
    http-reuse always              # multiplex streams across workers
    retries 5
    retry-on all-retryable-errors  # swallow the brief idle-pool race
    server workers rhttp@ idle-ping 20s
```

Requires HAProxy **≥ 3.4-dev10** for the
[mux-h2 fix](https://github.com/haproxy/haproxy/commit/a0541f5d21) that
keeps reverse H2 tunnels alive across stream lifecycles.

## Tests

The package ships with both **protocol unit tests** (no external process —
an in-memory `testPeer` drives the rhttp serve loop directly) and **HAProxy
end-to-end tests** that spin up a real HAProxy in front of an rhttp pool
and exercise the recommended config under realistic traffic.

```sh
go test ./...                                      # unit suite (~7s)
go test -race ./...                                # with the race detector

HAPROXY_BIN=/path/to/haproxy go test ./...         # also runs e2e suite (~9s)
go test -run TestHAProxy -v ./...                  # just the e2e tests
```

The e2e tests are auto-skipped when HAProxy isn't on `PATH` (or via
`HAPROXY_BIN`), and they skip cleanly with an explanatory message when the
HAProxy on the box is too old to know about `rhttp@` / `attach-srv` /
`idle-ping`.

Unit-suite coverage (39 tests, ~85% of statements):

- Send-side flow control (`reserve`, `addConn`, `addStream`,
  `applyInitialWindowDelta`, `markDead`, concurrent reservations).
- Request/response round-trips and header canonicalisation.
- Forbidden response-header filtering (RFC 9113 §8.2.2).
- `HEADERS` + `CONTINUATION` reassembly and protocol violations.
- `WINDOW_UPDATE` emission on inbound `DATA`.
- Send flow control with a peer-advertised tiny initial window.
- `PING` liveness timeout and ACK clearing.
- `GOAWAY` and `RST_STREAM` from the peer.
- Concurrent streams + stream-registry cleanup.
- Handler returning without draining the request body (`RST_STREAM` emit).
- Streaming SSE-style responses with `Flush()` (the `http.Flusher` cast).
- `MaxConcurrentStreams` option appears in the `SETTINGS` frame.
- Send credit released on connection close (no goroutine hang).
- `req.Context()` cancellation on `RST_STREAM` and on conn close.
- Handler panic recovery — 500 response, log emitted, conn keeps serving.
- `GOAWAY(last-stream-id, NO_ERROR)` emitted on graceful teardown.
- `Pool.Shutdown(ctx)` drains live conns and respects ctx deadline.

Benchmarks (`-bench BenchmarkRoundTrip -benchmem -benchtime=1s`) sit at
~11 allocs/req for a minimal GET and ~17 allocs/req for an 8-request-header
+ 3-response-header request, after warm-up of HPACK / sync.Pool / name
caches. The per-request `req.WithContext` clone is responsible for ~3 of
those allocs — the cost of proper `req.Context()` support. A concurrent
throughput benchmark `BenchmarkConcurrentResponses` covers c=1, 4, 16, 64.

HAProxy e2e coverage (7 tests):

- Basic round-trip through the recommended config.
- Concurrent burst (20 simultaneous through 4 tunnels).
- 1 MB response and 1 MB request body each end-to-end intact.
- Long-lived SSE delivers each flushed chunk.
- Concurrent in-flight POSTs with non-trivial bodies.
- Config validation of `retry-on all-retryable-errors`.

## License

ISC — see [LICENSE](LICENSE).
