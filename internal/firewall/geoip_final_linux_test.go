//go:build linux

package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// UpdateGeoIPDB is 0% covered. geoIPBaseURL is a package-level const, so we
// cannot redirect it to an httptest server. We exercise only the branches
// that don't require network access: directory creation and country-code
// validation (length check + trim/lowercase).

func TestUpdateGeoIPDBCreatesDirectoryAndSkipsBadCountryCodes(t *testing.T) {
	// Use a path in a deep parent so MkdirAll is exercised
	dir := filepath.Join(t.TempDir(), "nested", "geoip")

	// All invalid country codes (empty, length != 2) -> 0 updates, no
	// HTTP traffic because continue fires for each
	n, err := UpdateGeoIPDB(dir, []string{"", "x", "toolong", "  "})
	if err != nil {
		t.Fatalf("UpdateGeoIPDB: %v", err)
	}
	if n != 0 {
		t.Errorf("updated = %d, want 0", n)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("dir should be created: %v", err)
	}
}

func TestUpdateGeoIPDBMkdirFailureReturnsError(t *testing.T) {
	// Create a *file* and try to use its sub-path as the dbPath
	file := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// MkdirAll returns an error because the parent path is a regular file
	target := filepath.Join(file, "sub")
	n, err := UpdateGeoIPDB(target, []string{"us"})
	if err == nil {
		t.Error("expected error when dbPath parent is a regular file")
	}
	if n != 0 {
		t.Errorf("updated = %d, want 0 on error", n)
	}
}

func TestUpdateGeoIPDBEmptyCountryList(t *testing.T) {
	dir := t.TempDir()
	n, err := UpdateGeoIPDB(dir, nil)
	if err != nil {
		t.Fatalf("UpdateGeoIPDB: %v", err)
	}
	if n != 0 {
		t.Errorf("no countries -> 0 updates, got %d", n)
	}
}

// --- containsIP edge cases not already covered --------------------------

func TestContainsIPMalformedCIDRIsSkipped(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "ZZ.cidr")
	// Mix of malformed and valid - valid must still match
	body := strings.Join([]string{
		"malformed",
		"999.999.999.0/24",
		"203.0.113.0/24",
	}, "\n")
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ip := []byte{203, 0, 113, 5}
	if !containsIP(file, ip) {
		t.Error("should still find IP in valid CIDR after skipping malformed")
	}
}

func TestContainsIPPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read regardless of mode")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "NO.cidr")
	if err := os.WriteFile(file, []byte("203.0.113.0/24\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(file, 0o000); err != nil {
		t.Skipf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(file, 0o600) }()

	ip := []byte{203, 0, 113, 5}
	if containsIP(file, ip) {
		t.Error("unreadable file should return false")
	}
}

// --- LookupIP: file that exists but yields no match ----------------------

func TestLookupIPFileWithCIDRButNoMatch(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "US.cidr"), []byte("198.51.100.0/24\n"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "DE.cidr"), []byte("192.0.2.0/24\n"), 0600)

	if got := LookupIP(dir, "10.1.2.3"); len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// LookupIP skips non-.cidr files and directories; ensure .txt sibling is
// ignored even when it contains a matching CIDR.
func TestLookupIPIgnoresNonCIDRSuffix(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("203.0.113.0/24\n"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "US.cidr"), []byte("203.0.113.0/24\n"), 0600)

	matches := LookupIP(dir, "203.0.113.5")
	if len(matches) != 1 || matches[0] != "US" {
		t.Errorf("got %v, want [US]", matches)
	}
}
