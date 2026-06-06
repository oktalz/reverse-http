// Minimal reverse-http proxy — a Go-native drop-in replacement for the
// HAProxy frontend in examples/haproxy/haproxy.cfg.
//
// Two listeners:
//
//   - -tunnel-addr (default :8443): mTLS HTTP/2, workers attach here.
//     Clients must present a cert chaining to -workers-ca.
//   - -public-addr (default :8080): public HTTP. Each request is forwarded
//     across one of the attached worker tunnels (default selector: least
//     in-flight).
//
//	cd examples/pki && ./gen-certs.sh        # mint workers-ca + a worker cert
//	# also need a server cert for this proxy:
//	openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
//	    -subj /CN=localhost -keyout server.key -out server.crt
//	go run ./examples/proxy \
//	    -cert server.crt -key server.key \
//	    -workers-ca rhttp-certs/workers-ca.crt
//
// Pair with `go run ./examples/worker -addr localhost:8443 -ca server.crt …`
// then `curl http://localhost:8080/hello`.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	rhttp "github.com/oktalz/reverse-http"
)

func main() {
	var (
		tunnelAddr = flag.String("tunnel-addr", ":8443", "worker-facing mTLS listener")
		publicAddr = flag.String("public-addr", ":8080", "public HTTP listener")
		certPEM    = flag.String("cert", "server.crt", "proxy server cert (PEM)")
		keyPEM     = flag.String("key", "server.key", "proxy server key (PEM)")
		workersCA  = flag.String("workers-ca", "rhttp-certs/workers-ca.crt", "CA that signed worker client certs")
	)
	flag.Parse()

	serverCert, err := tls.LoadX509KeyPair(*certPEM, *keyPEM)
	if err != nil {
		log.Fatalf("load server cert: %v", err)
	}
	caPEM, err := os.ReadFile(*workersCA)
	if err != nil {
		log.Fatalf("read workers CA: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("workers CA file %s contained no certs", *workersCA)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	p, err := rhttp.NewProxy(rhttp.ProxyOptions{
		TunnelTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
			MinVersion:   tls.VersionTLS12,
		},
		Logger: logger,
		OnWorkerAttach: func(w *rhttp.ProxyWorker) {
			logger.Info("worker attached", "cn", w.CommonName(), "addr", w.RemoteAddr())
		},
		OnWorkerDetach: func(w *rhttp.ProxyWorker) {
			logger.Info("worker detached", "cn", w.CommonName())
		},
	})
	if err != nil {
		log.Fatalf("new proxy: %v", err)
	}

	go func() {
		log.Printf("tunnel listener on %s (mTLS)", *tunnelAddr)
		if err := p.ListenAndServeTunnels(*tunnelAddr); err != nil {
			log.Fatalf("tunnel listener: %v", err)
		}
	}()
	go func() {
		log.Printf("public listener on %s", *publicAddr)
		if err := p.ListenAndServePublic(*publicAddr, nil); err != nil {
			log.Fatalf("public listener: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
