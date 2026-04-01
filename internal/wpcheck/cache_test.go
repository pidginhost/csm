package wpcheck

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
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
	if err := c.PersistChecksums("6.9.4", "en_US", rawJSON, checksums); err != nil {
		t.Fatal(err)
	}

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

func TestIsVerifiedCoreFile(t *testing.T) {
	dir := t.TempDir()

	// Set up fake WP install
	wpRoot := filepath.Join(dir, "public_html")
	wpIncludes := filepath.Join(wpRoot, "wp-includes")
	diffEngine := filepath.Join(wpIncludes, "Text", "Diff", "Engine")
	if err := os.MkdirAll(diffEngine, 0755); err != nil {
		t.Fatal(err)
	}

	// Write version.php
	versionContent := []byte("<?php\n$wp_version = '6.9.4';\n")
	if err := os.WriteFile(filepath.Join(wpIncludes, "version.php"), versionContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Write a "core" file with known content
	coreContent := []byte("<?php // legitimate WordPress core file\n")
	corePath := filepath.Join(diffEngine, "shell.php")
	if err := os.WriteFile(corePath, coreContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Compute expected MD5
	expectedHash := md5.Sum(coreContent)
	expectedMD5 := hex.EncodeToString(expectedHash[:])

	// Set up cache with pre-populated checksums
	stateDir := filepath.Join(dir, "state")
	c := NewCache(stateDir)
	checksums := map[string]string{
		"wp-includes/Text/Diff/Engine/shell.php": expectedMD5,
		"wp-includes/version.php":                "ignored",
	}
	rawJSON, _ := json.Marshal(map[string]interface{}{"checksums": checksums})
	if err := c.PersistChecksums("6.9.4", "en_US", rawJSON, checksums); err != nil {
		t.Fatal(err)
	}

	// Open the file to get a real fd (simulating fanotify event fd)
	f, err := os.Open(corePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := int(f.Fd())

	// Unmodified core file → true
	if !c.IsVerifiedCoreFile(fd, corePath) {
		t.Error("expected verified=true for unmodified core file")
	}

	// Modified file → false
	modifiedContent := []byte("<?php eval(base64_decode('malicious')); // injected\n")
	modifiedPath := filepath.Join(diffEngine, "shell.php")
	if err := os.WriteFile(modifiedPath, modifiedContent, 0644); err != nil {
		t.Fatal(err)
	}
	f2, _ := os.Open(modifiedPath)
	defer f2.Close()
	if c.IsVerifiedCoreFile(int(f2.Fd()), modifiedPath) {
		t.Error("expected verified=false for modified core file")
	}

	// Non-WP file → false
	nonWPPath := filepath.Join(dir, "random.php")
	if err := os.WriteFile(nonWPPath, []byte("<?php echo 'hi';"), 0644); err != nil {
		t.Fatal(err)
	}
	f3, _ := os.Open(nonWPPath)
	defer f3.Close()
	if c.IsVerifiedCoreFile(int(f3.Fd()), nonWPPath) {
		t.Error("expected verified=false for non-WP file")
	}

	// Plugin file (not in checksums) → false
	pluginDir := filepath.Join(wpRoot, "wp-content", "plugins", "akismet")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(pluginDir, "akismet.php")
	if err := os.WriteFile(pluginPath, []byte("<?php // plugin"), 0644); err != nil {
		t.Fatal(err)
	}
	f4, _ := os.Open(pluginPath)
	defer f4.Close()
	if c.IsVerifiedCoreFile(int(f4.Fd()), pluginPath) {
		t.Error("expected verified=false for plugin file (not in core checksums)")
	}
}

func TestVersionInvalidationOnMismatch(t *testing.T) {
	dir := t.TempDir()

	wpRoot := filepath.Join(dir, "public_html")
	wpIncludes := filepath.Join(wpRoot, "wp-includes")
	if err := os.MkdirAll(wpIncludes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpIncludes, "version.php"),
		[]byte("<?php\n$wp_version = '6.9.4';\n"), 0644); err != nil {
		t.Fatal(err)
	}

	coreContent := []byte("<?php // new version content\n")
	corePath := filepath.Join(wpIncludes, "class-wp.php")
	if err := os.WriteFile(corePath, coreContent, 0644); err != nil {
		t.Fatal(err)
	}

	expectedHash := md5.Sum(coreContent)
	expectedMD5 := hex.EncodeToString(expectedHash[:])

	stateDir := filepath.Join(dir, "state")
	c := NewCache(stateDir)

	// Old version — different checksum for this file
	oldChecksums := map[string]string{"wp-includes/class-wp.php": "old_hash_wont_match"}
	oldJSON, _ := json.Marshal(map[string]interface{}{"checksums": oldChecksums})
	if err := c.PersistChecksums("6.8.0", "en_US", oldJSON, oldChecksums); err != nil {
		t.Fatal(err)
	}

	// New version — correct checksum
	newChecksums := map[string]string{"wp-includes/class-wp.php": expectedMD5}
	newJSON, _ := json.Marshal(map[string]interface{}{"checksums": newChecksums})
	if err := c.PersistChecksums("6.9.4", "en_US", newJSON, newChecksums); err != nil {
		t.Fatal(err)
	}

	// Pre-populate root cache with OLD version (simulating stale cache)
	c.setRoot(wpRoot, "6.8.0", "en_US")

	f, _ := os.Open(corePath)
	defer f.Close()

	// Despite stale root cache pointing to 6.8.0, the mismatch should trigger
	// re-read of version.php, discover 6.9.4, and verify against new checksums
	if !c.IsVerifiedCoreFile(int(f.Fd()), corePath) {
		t.Error("expected verified=true after version re-read on mismatch")
	}
}

func TestVersionPhpInvalidation(t *testing.T) {
	dir := t.TempDir()

	wpRoot := filepath.Join(dir, "public_html")
	wpIncludes := filepath.Join(wpRoot, "wp-includes")
	if err := os.MkdirAll(wpIncludes, 0755); err != nil {
		t.Fatal(err)
	}

	versionPath := filepath.Join(wpIncludes, "version.php")
	if err := os.WriteFile(versionPath, []byte("<?php\n$wp_version = '6.9.4';\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stateDir := filepath.Join(dir, "state")
	c := NewCache(stateDir)

	// Pre-populate root cache
	c.setRoot(wpRoot, "6.8.0", "en_US")

	v, _, ok := c.getRoot(wpRoot)
	if !ok || v != "6.8.0" {
		t.Fatal("expected root cache to have 6.8.0")
	}

	// Call IsVerifiedCoreFile on version.php itself — should invalidate root cache
	f, _ := os.Open(versionPath)
	defer f.Close()
	c.IsVerifiedCoreFile(int(f.Fd()), versionPath)

	// Root cache should now reflect 6.9.4 (re-read from disk after invalidation)
	v, _, ok = c.getRoot(wpRoot)
	if !ok || v != "6.9.4" {
		t.Errorf("expected root cache to have 6.9.4 after invalidation, got %q", v)
	}
}
