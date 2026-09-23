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
	"errors"
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

func TestTLSRenewalFailurePreservesTheWorkingPair(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	if err := os.Mkdir(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(certDir, "webui.crt"), filepath.Join(dir, "webui.key")
	withCertValidity(t, 10*24*time.Hour)
	if err := EnsureTLSCert(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// CI may run as root, which can write through directory permissions.
	originalWrite := writeTLSFile
	writeTLSFile = func(path string, data []byte) error {
		if path == certPath {
			return errors.New("certificate storage unavailable")
		}
		return originalWrite(path, data)
	}
	t.Cleanup(func() { writeTLSFile = originalWrite })
	if err = EnsureTLSCert(certPath, keyPath); err == nil {
		t.Fatal("renewal ignored the certificate write failure")
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("failed renewal replaced the working private key")
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Errorf("failed renewal broke the pair: %v", err)
	}
}

func TestTLSRenewalRequiresASelfSignature(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "webui.crt"), filepath.Join(dir, "webui.key")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{selfSignedOrganization}},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	// Self-issued names do not imply a self-signed certificate.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	before := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = os.WriteFile(certPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = EnsureTLSCert(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("self-issued operator certificate was replaced")
	}
}

func TestCertReloaderRetainsPairDuringOperatorReplacement(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "webui.crt"), filepath.Join(dir, "webui.key")
	nextCert, nextKey := filepath.Join(dir, "next.crt"), filepath.Join(dir, "next.key")
	for _, pair := range [][2]string{{certPath, keyPath}, {nextCert, nextKey}} {
		if err := EnsureTLSCert(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
		for _, path := range pair {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("TLS file permissions = %o, want 600", info.Mode().Perm())
			}
		}
	}
	reloader, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(nextKey, keyPath); err != nil {
		t.Fatal(err)
	}
	intermediate, err := reloader.GetCertificate(nil)
	if err != nil || intermediate != first {
		t.Fatal("reloader discarded the working pair during replacement")
	}
	if err = os.Rename(nextCert, certPath); err != nil {
		t.Fatal(err)
	}
	second, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("reloader did not recover after replacement completed")
	}
}

func TestTLSRenewalReportsMalformedCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "webui.crt")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid certificate")})
	if err := os.WriteFile(certPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renewTLSCert(certPath, filepath.Join(dir, "webui.key")); err == nil {
		t.Fatal("malformed certificate was silently accepted")
	}
	after, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, after) {
		t.Fatal("malformed operator certificate was overwritten")
	}
}
