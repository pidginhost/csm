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

// Inject write failures without relying on permissions that root bypasses.
var writeTLSFile = writeFileReplace

// renewBefore is how close to expiry a generated certificate is replaced.
const renewBefore = 30 * 24 * time.Hour

// selfSignedOrganization marks the certificates EnsureTLSCert generates.
const selfSignedOrganization = "CSM Security Monitor"

// EnsureTLSCert generates a self-signed ECDSA P-256 certificate if the cert
// or key file doesn't exist, and renews one it generated earlier when it
// expires within renewBefore. Any other certificate, such as one the
// operator installed, is left alone. Includes localhost and the server
// hostname in the certificate SANs.
func EnsureTLSCert(certPath, keyPath string, extraNames ...string) error {
	if fileExists(certPath) && fileExists(keyPath) {
		return renewTLSCert(certPath, keyPath)
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
	// This path creates the initial pair. Renewal retains its key so a
	// failed certificate replacement cannot break the pair on disk.
	if err := writeTLSFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	if err := writeTLSFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})); err != nil {
		return fmt.Errorf("writing cert: %w", err)
	}
	return nil
}

// renewTLSCert never generates missing files: an operator may temporarily
// remove either file while replacing their certificate.
func renewTLSCert(certPath, keyPath string) error {
	// Read and validate the same certificate that will be renewed, even
	// when an operator replaces the files during this check.
	// #nosec G304 -- paths are operator-configured TLS files.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	block := leafCertificateBlock(certPEM)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing certificate for renewal: %w", err)
	}
	if !ownCertExpiring(cert) {
		return nil
	}
	// #nosec G304 -- paths are operator-configured TLS files.
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("loading certificate for renewal: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	cert.SerialNumber = serial
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.Add(selfSignedValidity)
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, cert.PublicKey, pair.PrivateKey)
	if err != nil {
		return fmt.Errorf("renewing certificate: %w", err)
	}
	return writeTLSFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// leafCertificateBlock returns the certificate the TLS stack serves: the
// first CERTIFICATE block. A combined file, such as cPanel's service
// certificate, carries the private key ahead of it.
func leafCertificateBlock(data []byte) *pem.Block {
	for {
		block, rest := pem.Decode(data)
		if block == nil || block.Type == "CERTIFICATE" {
			return block
		}
		data = rest
	}
}

// ownCertExpiring recognizes CSM's self-signed certificates near expiry.
// A matching issuer name alone does not prove a self-signature.
func ownCertExpiring(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != selfSignedOrganization {
		return false
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
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
