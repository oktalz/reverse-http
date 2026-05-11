package rhttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// genUnitTestCert mints a quick self-signed cert+key for tests that just
// need to satisfy "TLSCert is set" — the validation tests below don't
// actually drive a network connection, so anything that parses is fine.
func genUnitTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unit-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}

// TestNewConnectionPoolRejectsMissingCert: a worker cert is mandatory —
// the library refuses to run without one rather than silently dialling
// out as an anonymous client.
func TestNewConnectionPoolRejectsMissingCert(t *testing.T) {
	_, pool := genUnitTestCert(t)
	_, err := NewConnectionPool(ServerOptions{
		Addr:       "127.0.0.1:1",
		Handler:    http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}),
		CACertPool: pool,
		// TLSCert deliberately omitted.
	})
	if !errors.Is(err, ErrMTLSRequired) {
		t.Fatalf("err = %v, want ErrMTLSRequired", err)
	}
}

// TestValidateOptionsAcceptsNilCA: a nil CACertPool is allowed — it tells
// rhttp to fall back to the host's system root CAs, which is the right
// behaviour for proxies whose server cert is publicly trusted (LE etc.).
func TestValidateOptionsAcceptsNilCA(t *testing.T) {
	cert, _ := genUnitTestCert(t)
	opts := ServerOptions{
		Addr:    "127.0.0.1:1",
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}),
		TLSCert: cert,
	}
	if err := validateOptions(&opts); err != nil {
		t.Fatalf("validateOptions error: %v", err)
	}
}

// TestNewConnectionPoolRejectsMissingAddr / MissingHandler: required-fields
// guarded so misconfiguration fails fast at startup rather than producing
// a silent reconnect loop.
func TestNewConnectionPoolRejectsMissingAddr(t *testing.T) {
	cert, pool := genUnitTestCert(t)
	_, err := NewConnectionPool(ServerOptions{
		Handler:    http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}),
		TLSCert:    cert,
		CACertPool: pool,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNewConnectionPoolRejectsMissingHandler(t *testing.T) {
	cert, pool := genUnitTestCert(t)
	_, err := NewConnectionPool(ServerOptions{
		Addr:       "127.0.0.1:1",
		TLSCert:    cert,
		CACertPool: pool,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
