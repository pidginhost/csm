package wpcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiskCachePersistence(t *testing.T) {
	dir := t.TempDir()
	c1 := NewCache(dir)

	checksums := map[string]string{
		"wp-includes/version.php":                "abc123",
		"wp-includes/Text/Diff/Engine/shell.php": "def456",
		"wp-admin/index.php":                     "ghi789",
	}
	rawJSON := []byte(`{"checksums":{"wp-includes/version.php":"abc123","wp-includes/Text/Diff/Engine/shell.php":"def456","wp-admin/index.php":"ghi789"}}`)

	err := c1.PersistChecksums("6.9.4", "en_US", rawJSON, checksums)
	if err != nil {
		t.Fatalf("PersistChecksums: %v", err)
	}

	diskPath := filepath.Join(dir, "wp-checksums", "6.9.4_en_US.json")
	if _, err := os.Stat(diskPath); err != nil {
		t.Fatalf("cache file not created: %v", err)
	}

	c2 := NewCache(dir)
	md5, ok := c2.lookupChecksum("6.9.4", "en_US", "wp-includes/Text/Diff/Engine/shell.php")
	if !ok {
		t.Fatal("expected checksum to be loaded from disk")
	}
	if md5 != "def456" {
		t.Errorf("checksum = %q, want %q", md5, "def456")
	}
}

func TestDiskCacheLocalizedVersion(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)

	checksums := map[string]string{"wp-includes/version.php": "aaa111"}
	rawJSON := []byte(`{"checksums":{"wp-includes/version.php":"aaa111"}}`)

	err := c.PersistChecksums("6.9.4", "de_DE", rawJSON, checksums)
	if err != nil {
		t.Fatalf("PersistChecksums: %v", err)
	}

	diskPath := filepath.Join(dir, "wp-checksums", "6.9.4_de_DE.json")
	if _, err := os.Stat(diskPath); err != nil {
		t.Fatalf("localized cache file not created: %v", err)
	}

	_, ok := c.lookupChecksum("6.9.4", "de_DE", "wp-includes/version.php")
	if !ok {
		t.Fatal("expected localized checksum lookup to succeed")
	}

	_, ok = c.lookupChecksum("6.9.4", "en_US", "wp-includes/version.php")
	if ok {
		t.Fatal("expected lookup with wrong locale to fail")
	}
}

func TestChecksumLookupMisses(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)

	checksums := map[string]string{"wp-includes/version.php": "abc123"}
	rawJSON := []byte(`{"checksums":{"wp-includes/version.php":"abc123"}}`)
	c.PersistChecksums("6.9.4", "en_US", rawJSON, checksums)

	_, ok := c.lookupChecksum("6.8.0", "en_US", "wp-includes/version.php")
	if ok {
		t.Error("expected miss for wrong version")
	}

	_, ok = c.lookupChecksum("6.9.4", "en_US", "wp-content/plugins/akismet/akismet.php")
	if ok {
		t.Error("expected miss for non-core file")
	}

	c2 := NewCache(t.TempDir())
	_, ok = c2.lookupChecksum("6.9.4", "en_US", "wp-includes/version.php")
	if ok {
		t.Error("expected miss on empty cache")
	}
}
