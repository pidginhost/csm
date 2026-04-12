package webui

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildDNSNamesLocalhost(t *testing.T) {
	names := buildDNSNames(nil)
	if len(names) != 1 || names[0] != "localhost" {
		t.Errorf("got %v", names)
	}
}

func TestBuildDNSNamesWithHostname(t *testing.T) {
	names := buildDNSNames([]string{"myhost.example.com", "203.0.113.5"})
	found := false
	for _, n := range names {
		if n == "myhost.example.com" {
			found = true
		}
		if n == "203.0.113.5" {
			t.Error("IP should not be in DNS names")
		}
	}
	if !found {
		t.Error("hostname should be in DNS names")
	}
}

func TestBuildIPListDefaults(t *testing.T) {
	ips := buildIPList(nil)
	if len(ips) < 2 {
		t.Fatalf("got %d IPs, want >= 2", len(ips))
	}
	hasLoopback := false
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Error("should contain 127.0.0.1")
	}
}

func TestBuildIPListWithExtra(t *testing.T) {
	ips := buildIPList([]string{"203.0.113.5", "not-an-ip"})
	found := false
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("203.0.113.5")) {
			found = true
		}
	}
	if !found {
		t.Error("extra IP should be included")
	}
}

func TestFileExistsTrue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test")
	_ = os.WriteFile(path, []byte("x"), 0600)
	if !fileExists(path) {
		t.Error("existing file should return true")
	}
}

func TestFileExistsFalse(t *testing.T) {
	if fileExists(filepath.Join(t.TempDir(), "nope")) {
		t.Error("missing file should return false")
	}
}

func TestEnsureTLSCertCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := EnsureTLSCert(certPath, keyPath, "myhost"); err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}

	if !fileExists(certPath) {
		t.Error("cert file not created")
	}
	if !fileExists(keyPath) {
		t.Error("key file not created")
	}
}

func TestEnsureTLSCertSkipsExisting(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certPath, []byte("existing"), 0600)
	_ = os.WriteFile(keyPath, []byte("existing"), 0600)

	if err := EnsureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}
	// Should not overwrite existing files
	data, _ := os.ReadFile(certPath)
	if string(data) != "existing" {
		t.Error("existing cert should not be overwritten")
	}
}
