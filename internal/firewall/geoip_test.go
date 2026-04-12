package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookupIPMatch(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "US.cidr"), []byte("203.0.113.0/24\n198.51.100.0/24\n"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "DE.cidr"), []byte("192.0.2.0/24\n"), 0600)

	matches := LookupIP(dir, "203.0.113.5")
	if len(matches) != 1 || matches[0] != "US" {
		t.Errorf("got %v, want [US]", matches)
	}
}

func TestLookupIPNoMatch(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "US.cidr"), []byte("203.0.113.0/24\n"), 0600)

	matches := LookupIP(dir, "10.0.0.1")
	if len(matches) != 0 {
		t.Errorf("got %v, want empty", matches)
	}
}

func TestLookupIPInvalid(t *testing.T) {
	if got := LookupIP(t.TempDir(), "not-an-ip"); got != nil {
		t.Errorf("invalid IP should return nil, got %v", got)
	}
}

func TestLookupIPv6Unsupported(t *testing.T) {
	if got := LookupIP(t.TempDir(), "2001:db8::1"); got != nil {
		t.Errorf("IPv6 should return nil, got %v", got)
	}
}

func TestLookupIPEmptyDir(t *testing.T) {
	matches := LookupIP(t.TempDir(), "203.0.113.5")
	if len(matches) != 0 {
		t.Errorf("empty dir should return no matches, got %v", matches)
	}
}

func TestLookupIPMissingDir(t *testing.T) {
	matches := LookupIP(filepath.Join(t.TempDir(), "missing"), "203.0.113.5")
	if matches != nil {
		t.Errorf("missing dir should return nil, got %v", matches)
	}
}

func TestContainsIPSkipsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.cidr")
	_ = os.WriteFile(path, []byte("# comment\n\n203.0.113.0/24\n"), 0600)

	ip := []byte{203, 0, 113, 5}
	if !containsIP(path, ip) {
		t.Error("should match after skipping comments")
	}
}
