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
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/integrity"
)

// selfSignedValidity is how long a generated certificate is valid; a var so
// tests can generate one close to expiry.
var selfSignedValidity = 365 * 24 * time.Hour

// renewBefore is how close to expiry a generated certificate is replaced.
const renewBefore = 30 * 24 * time.Hour

// selfSignedOrganization marks the certificates EnsureTLSCert generates.
const selfSignedOrganization = "CSM Security Monitor"

// EnsureTLSCert generates a self-signed ECDSA P-256 certificate if the cert
// and key files don't exist, and replaces one it generated earlier when it
// expires within renewBefore. Any other certificate, such as one the
// operator installed, is left alone. Includes localhost and the server
// hostname in the certificate SANs.
func EnsureTLSCert(certPath, keyPath string, extraNames ...string) error {
	if fileExists(certPath) && fileExists(keyPath) && !ownCertExpiring(certPath) {
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Use first extra name (hostname) as CN, fall back to localhost
	cn := "localhost"
	if len(extraNames) > 0 && extraNames[0] != "" {
		cn = extraNames[0]
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{selfSignedOrganization},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              buildDNSNames(extraNames),
		IPAddresses:           buildIPList(extraNames),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}
	// Replace each file by rename, key first. A server reading the pair in
	// between sees a new key with the old certificate, which does not load,
	// and keeps serving what it had.
	if err := writeFileReplace(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	if err := writeFileReplace(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})); err != nil {
		return fmt.Errorf("writing cert: %w", err)
	}
	return nil
}

// ownCertExpiring reports whether certPath holds a certificate EnsureTLSCert
// generated (self-signed, selfSignedOrganization) that expires within
// renewBefore. Anything unreadable or foreign is not ours to replace.
func ownCertExpiring(certPath string) bool {
	// #nosec G304 -- certPath is derived from config-owned statePath.
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != selfSignedOrganization {
		return false
	}
	return time.Until(cert.NotAfter) < renewBefore
}

// writeFileReplace writes data to a private temporary file beside path and
// renames it over path.
func writeFileReplace(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// certReloader serves the certificate on disk and loads it again when the
// files change, so a renewed or replaced certificate needs no restart.
type certReloader struct {
	certPath, keyPath string

	mu    sync.Mutex
	cert  *tls.Certificate
	stamp string
}

func newCertReloader(certPath, keyPath string) (*certReloader, error) {
	r := &certReloader{certPath: certPath, keyPath: keyPath}
	if _, err := r.GetCertificate(nil); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate is a tls.Config.GetCertificate. A pair that does not load
// (mid-replacement) keeps the previous certificate in service.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	stamp := fileStamp(r.certPath) + "|" + fileStamp(r.keyPath)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && stamp == r.stamp {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, err
	}
	r.cert, r.stamp = &cert, stamp
	return r.cert, nil
}

func fileStamp(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return integrity.FileChangeKey(info)
}

func buildDNSNames(extra []string) []string {
	names := []string{"localhost"}
	for _, n := range extra {
		if net.ParseIP(n) == nil { // not an IP - it's a hostname
			names = append(names, n)
		}
	}
	return names
}

func buildIPList(extra []string) []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, n := range extra {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
