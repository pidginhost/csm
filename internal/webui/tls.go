package webui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// EnsureTLSCert generates a self-signed ECDSA P-256 certificate if the
// cert and key files don't exist. Includes localhost and the server hostname
// in the certificate SANs.
func EnsureTLSCert(certPath, keyPath string, extraNames ...string) error {
	// If both exist, nothing to do
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"CSM Security Monitor"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
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

	// Write cert
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("creating cert file: %w", err)
	}
	defer func() { _ = certFile.Close() }()
	if encErr := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); encErr != nil {
		return fmt.Errorf("encoding cert: %w", encErr)
	}

	// Write key
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer func() { _ = keyFile.Close() }()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("encoding key: %w", err)
	}

	return nil
}

func buildDNSNames(extra []string) []string {
	names := []string{"localhost"}
	for _, n := range extra {
		if net.ParseIP(n) == nil { // not an IP — it's a hostname
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
