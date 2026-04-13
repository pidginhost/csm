//go:build linux

package firewall

import (
	"os"
	"testing"
)

// Test the cloudflare.go functions that are Linux-only.

func TestLoadCountryCIDRsEmpty(t *testing.T) {
	dir := t.TempDir()
	// No CIDR files → empty result
	elements := loadCountryCIDRs(dir, "US")
	if len(elements) != 0 {
		t.Errorf("missing file should return 0, got %d", len(elements))
	}
}

func TestLoadCountryCIDRsWithData(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(dir+"/US.cidr", []byte("203.0.113.0/24\n198.51.100.0/24\n"), 0644)

	elements := loadCountryCIDRs(dir, "US")
	if len(elements) == 0 {
		t.Error("should load CIDR elements")
	}
	// Each CIDR produces 2 elements (start + interval end)
	if len(elements) != 4 {
		t.Errorf("2 CIDRs should produce 4 elements, got %d", len(elements))
	}
}
