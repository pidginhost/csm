package webui

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func withCertValidity(t *testing.T, d time.Duration) {
	t.Helper()
	old := selfSignedValidity
	selfSignedValidity = d
	t.Cleanup(func() { selfSignedValidity = old })
}

// The generated certificate was valid for a year and never replaced, so a
// daemon on the same host for a year served an expired certificate.
func TestEnsureTLSCertRenewsItsOwnCertificateBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "webui.crt"), filepath.Join(dir, "webui.key")
	withCertValidity(t, 10*24*time.Hour)
	if err := EnsureTLSCert(certPath, keyPath, "host.example.com"); err != nil {
		t.Fatal(err)
	}
	withCertValidity(t, 365*24*time.Hour)
	if err := EnsureTLSCert(certPath, keyPath, "host.example.com"); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(readCert(t, certPath).NotAfter); left < 300*24*time.Hour {
		t.Fatalf("certificate expiring in 10 days was not renewed (%s left)", left.Round(time.Hour))
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("renewed certificate and key do not match: %v", err)
	}
}

func TestEnsureTLSCertKeepsAFreshCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "webui.crt"), filepath.Join(dir, "webui.key")
	if err := EnsureTLSCert(certPath, keyPath, "host.example.com"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(certPath)
	if err := EnsureTLSCert(certPath, keyPath, "host.example.com"); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(certPath); !bytes.Equal(before, after) {
		t.Fatal("a fresh certificate was replaced")
	}
}

// A certificate the operator installed is never replaced, even near expiry.
func TestEnsureTLSCertLeavesOperatorCertificates(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ops.crt"), filepath.Join(dir, "ops.key")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{Organization: []string{"Example Ops"}, CommonName: "host.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(5 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureTLSCert(certPath, keyPath, "host.example.com"); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(certPath); !bytes.Equal(after, certPEM) {
		t.Fatal("an operator certificate was replaced")
	}
}

// The listener picks up a renewed or replaced certificate without a restart.
func TestCertReloaderServesTheCurrentFile(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "webui.crt"), filepath.Join(dir, "webui.key")
	if err := EnsureTLSCert(certPath, keyPath, "host.example.com"); err != nil {
		t.Fatal(err)
	}
	reloader, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if rmErr := os.Remove(certPath); rmErr != nil {
		t.Fatal(rmErr)
	}
	if genErr := EnsureTLSCert(certPath, keyPath, "host.example.com"); genErr != nil {
		t.Fatal(genErr)
	}
	second, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("the reloader kept serving the replaced certificate")
	}
}
