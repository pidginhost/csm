package webui

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Keep non-certificate PEM blocks and surrounding text in the fixture so
// renewal must preserve the bundle, not just reconstruct a usable key pair.
func writeExpiringCombinedPEM(t *testing.T, path string, keyFirst bool) (prefix, suffix []byte) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	withCertValidity(t, 10*24*time.Hour)
	if err := EnsureTLSCert(certPath, keyPath, "host.example.com"); err != nil {
		t.Fatal(err)
	}
	withCertValidity(t, 365*24*time.Hour)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	prefix = []byte("# service certificate\n")
	suffix = pem.EncodeToMemory(&pem.Block{Type: "COMMENT", Bytes: []byte("bundle metadata")})
	suffix = append(suffix, []byte("# end of bundle\n")...)
	if keyFirst {
		prefix = append(prefix, keyPEM...)
	} else {
		suffix = append(keyPEM, suffix...)
	}
	data := append(bytes.Clone(prefix), certPEM...)
	data = append(data, suffix...)
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return prefix, suffix
}

func TestTLSRenewalPreservesCombinedBundle(t *testing.T) {
	for _, keyFirst := range []bool{true, false} {
		name := "certificate-first"
		if keyFirst {
			name = "key-first"
		}
		for _, failWrite := range []bool{false, true} {
			scenario := name + "/success"
			if failWrite {
				scenario = name + "/write-failure"
			}
			t.Run(scenario, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "service.pem")
				prefix, suffix := writeExpiringCombinedPEM(t, path, keyFirst)
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				reloader, err := newCertReloader(path, path)
				if err != nil {
					t.Fatal(err)
				}
				first, err := reloader.GetCertificate(nil)
				if err != nil {
					t.Fatal(err)
				}
				writeErr := errors.New("certificate storage unavailable")
				if failWrite {
					originalWrite := writeTLSFile
					writeTLSFile = func(string, []byte) error { return writeErr }
					t.Cleanup(func() { writeTLSFile = originalWrite })
				}
				err = renewTLSCert(path, path)
				if failWrite {
					if !errors.Is(err, writeErr) {
						t.Fatalf("renewal error = %v, want write failure", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if failWrite && !bytes.Equal(before, after) {
					t.Fatal("failed renewal changed the working bundle")
				}
				pair, err := tls.LoadX509KeyPair(path, path)
				if err != nil {
					t.Fatalf("renewal broke the combined key pair: %v", err)
				}
				if !bytes.HasPrefix(after, prefix) || !bytes.HasSuffix(after, suffix) {
					t.Fatal("renewal changed data outside the leaf certificate")
				}
				leaf, err := x509.ParseCertificate(pair.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				if !failWrite && (time.Until(leaf.NotAfter) < 300*24*time.Hour || bytes.Equal(first.Certificate[0], pair.Certificate[0])) {
					t.Fatal("expiring certificate was not renewed")
				}
				current, err := reloader.GetCertificate(nil)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(current.Certificate[0], pair.Certificate[0]) {
					t.Fatal("reloader did not serve the certificate on disk")
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("bundle permissions = %o, want 600", info.Mode().Perm())
				}
			})
		}
	}
}

func TestTLSRenewalUsesFirstCertificateInBundle(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		name := "operator-leaf"
		if malformed {
			name = "malformed-leaf"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "service.pem")
			writeExpiringCombinedPEM(t, path, true)
			ownBundle, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data := writeCombinedPEM(t, filepath.Join(dir, "operator.pem"))
			if malformed {
				invalid := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid certificate")})
				data = append(invalid, data...)
			}
			data = append(data, ownBundle...)
			if err = os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, loadErr := tls.LoadX509KeyPair(path, path)
			err = renewTLSCert(path, path)
			if malformed && (loadErr == nil || err == nil) {
				t.Fatal("malformed first certificate was skipped")
			}
			if !malformed && (loadErr != nil || err != nil) {
				t.Fatalf("operator leaf rejected: load=%v, renewal=%v", loadErr, err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, after) {
				t.Fatal("renewal changed a bundle based on a later certificate")
			}
		})
	}
}

func TestTLSRenewalPreservesAdditionalCertificates(t *testing.T) {
	dir := t.TempDir()
	path, keyPath := filepath.Join(dir, "service.pem"), filepath.Join(dir, "key.pem")
	prefix, suffix := writeExpiringCombinedPEM(t, path, true)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	operatorPath := filepath.Join(dir, "operator.pem")
	writeCombinedPEM(t, operatorPath)
	operatorPair, err := tls.LoadX509KeyPair(operatorPath, operatorPath)
	if err != nil {
		t.Fatal(err)
	}
	// An extra certificate must not be mistaken for the leaf or discarded.
	for _, der := range operatorPair.Certificate {
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		data = append(data, block...)
		suffix = append(suffix, block...)
	}
	// PEM decoding also accepts CRLF and skips incomplete BEGIN markers.
	preamble := []byte("-----BEGIN CERTIFICATE-----\ninvalid PEM\n")
	data = append(bytes.Clone(preamble), data...)
	prefix = append(preamble, prefix...)
	data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
	prefix = bytes.ReplaceAll(prefix, []byte("\n"), []byte("\r\n"))
	suffix = bytes.ReplaceAll(suffix, []byte("\n"), []byte("\r\n"))
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path, keyPath); err != nil {
		t.Fatal(err)
	}
	if err = renewTLSCert(path, keyPath); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(path, keyPath)
	if err != nil {
		t.Fatalf("renewal broke the bundle accessed through a key alias: %v", err)
	}
	if len(pair.Certificate) != 1+len(operatorPair.Certificate) {
		t.Fatal("renewal changed the number of bundled certificates")
	}
	for i, der := range operatorPair.Certificate {
		if !bytes.Equal(pair.Certificate[i+1], der) {
			t.Fatal("renewal changed a later certificate")
		}
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(leaf.NotAfter) < 300*24*time.Hour {
		t.Fatal("first certificate was not renewed")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(after, prefix) || !bytes.HasSuffix(after, suffix) {
		t.Fatal("renewal changed bytes outside the first certificate")
	}
}
