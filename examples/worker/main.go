// Minimal reverse-http worker.
//
// Pairs with examples/haproxy/haproxy.cfg and certs minted by
// examples/pki/gen-certs.sh. The worker dials the HAProxy tunnel
// listener over mTLS and serves /hello + /events back through the
// tunnel — public traffic reaches us via HAProxy's :443 frontend.
//
//	cd examples/pki && ./gen-certs.sh        # mint workers-ca + rhttp-worker cert
//	# start haproxy with examples/haproxy/haproxy.cfg pointing at the certs
//	go run ./examples/worker \
//	    -addr proxy.example.com:8443 \
//	    -cert rhttp-certs/rhttp-worker.crt \
//	    -key  rhttp-certs/rhttp-worker.key \
//	    -ca   path/to/proxy-server-ca.pem
//
// curl https://proxy.example.com/hello → "hello from behind the proxy".
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	rhttp "github.com/oktalz/reverse-http"
)

func main() {
	var (
		addr    = flag.String("addr", "localhost:8443", "proxy host:port to dial")
		sni     = flag.String("sni", "", "TLS SNI server name (default: derived from -addr)")
		certPEM = flag.String("cert", "rhttp-certs/rhttp-worker.crt", "worker client cert (PEM)")
		keyPEM  = flag.String("key", "rhttp-certs/rhttp-worker.key", "worker client key (PEM)")
		caPEM   = flag.String("ca", "", "CA that signed the proxy's server cert (PEM); empty = use system roots")
		nbConn  = flag.Int("conns", 2, "number of tunnel connections to maintain")
	)
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certPEM, *keyPEM)
	if err != nil {
		log.Fatalf("load worker cert: %v", err)
	}

	var caPool *x509.CertPool
	if *caPEM != "" {
		pem, err := os.ReadFile(*caPEM)
		if err != nil {
			log.Fatalf("read proxy CA: %v", err)
		}
		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(pem) {
			log.Fatalf("proxy CA file %s contained no certs", *caPEM)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "hello from behind the proxy")
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, flushherOK := w.(http.Flusher)
		if !flushherOK {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}
		for i := range 5 {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			_, _ = fmt.Fprintf(w, "data: tick %d\n\n", i)
			flusher.Flush()
			time.Sleep(500 * time.Millisecond)
		}
	})

	pool, err := rhttp.NewConnectionPool(rhttp.ServerOptions{
		Addr:          *addr,
		SNIServerName: *sni,
		TLSCert:       cert,
		CACertPool:    caPool,
		Handler:       mux,
		NBConn:        *nbConn,
	})
	if err != nil {
		log.Fatalf("new pool: %v", err)
	}

	pool.Ready().Wait()
	log.Printf("worker connected to %s; serving reverse traffic", *addr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
