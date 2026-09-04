package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// --- CMSHashCache Add / Contains / Size / Clear -----------------------

func TestCMSHashCacheAddAndContains(t *testing.T) {
	cache := &CMSHashCache{hashes: make(map[string]bool), sizes: make(map[int64]bool)}
	cache.Add("abc123", 42)
	if !cache.Contains("abc123") {
		t.Error("expected true after Add")
	}
	if cache.Contains("unknown") {
		t.Error("unknown hash should not be contained")
	}
	if !cache.MayContainSize(42) || cache.MayContainSize(43) {
		t.Error("cached size membership does not match the added file")
	}
}

func TestCMSHashCacheSize(t *testing.T) {
	cache := &CMSHashCache{hashes: make(map[string]bool), sizes: make(map[int64]bool)}
	if cache.Size() != 0 {
		t.Errorf("empty size = %d", cache.Size())
	}
	cache.Add("a", 1)
	cache.Add("b", 2)
	if cache.Size() != 2 {
		t.Errorf("size = %d, want 2", cache.Size())
	}
}

func TestCMSHashCacheClear(t *testing.T) {
	cache := &CMSHashCache{hashes: make(map[string]bool), sizes: make(map[int64]bool)}
	cache.Add("a", 1)
	cache.Clear()
	if cache.Size() != 0 {
		t.Errorf("size after clear = %d", cache.Size())
	}
	if cache.Contains("a") {
		t.Error("should not contain after clear")
	}
	if cache.MayContainSize(1) {
		t.Error("clear retained a cached file size")
	}
}

// --- HashFile ---------------------------------------------------------

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.php")
	_ = os.WriteFile(path, []byte("<?php echo 'hello'; ?>"), 0644)

	h := HashFile(path)
	if h == "" {
		t.Fatal("expected non-empty hash")
	}
	if len(h) != 64 {
		t.Errorf("hash length = %d, want 64 (SHA256 hex)", len(h))
	}

	// Same content → same hash
	path2 := filepath.Join(dir, "copy.php")
	_ = os.WriteFile(path2, []byte("<?php echo 'hello'; ?>"), 0644)
	if HashFile(path2) != h {
		t.Error("same content should produce same hash")
	}
}

func TestHashFileMissing(t *testing.T) {
	if got := HashFile(filepath.Join(t.TempDir(), "nope")); got != "" {
		t.Errorf("missing file should return empty, got %q", got)
	}
}

// --- IsVerifiedCMSFile ------------------------------------------------

func TestIsVerifiedCMSFileMatch(t *testing.T) {
	cache := GlobalCMSCache()
	cache.Clear()

	dir := t.TempDir()
	path := filepath.Join(dir, "wp-load.php")
	content := []byte("<?php require_once( dirname( __FILE__ ) . '/wp-blog-header.php' );")
	_ = os.WriteFile(path, content, 0644)

	h := HashFile(path)
	cache.Add(h, int64(len(content)))

	if !IsVerifiedCMSFile(path) {
		t.Error("file in cache should be verified")
	}
}

func TestIsVerifiedCMSFileNoMatch(t *testing.T) {
	cache := GlobalCMSCache()
	cache.Clear()

	dir := t.TempDir()
	path := filepath.Join(dir, "evil.php")
	_ = os.WriteFile(path, []byte("<?php system('id'); ?>"), 0644)

	if IsVerifiedCMSFile(path) {
		t.Error("uncached file should not be verified")
	}
}

func TestIsVerifiedCMSFileEmptyCache(t *testing.T) {
	cache := GlobalCMSCache()
	cache.Clear()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.php")
	_ = os.WriteFile(path, []byte("content"), 0644)

	if IsVerifiedCMSFile(path) {
		t.Error("empty cache should return false")
	}
}

func TestCacheWPCoreFilesExcludesUnverifiedConfiguration(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "wp-config.php")
	corePath := filepath.Join(root, "wp-login.php")
	if err := os.WriteFile(configPath, []byte("<?php eval($_POST['x']);"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corePath, []byte("<?php // distributed core file"), 0o600); err != nil {
		t.Fatal(err)
	}

	cache := &CMSHashCache{hashes: make(map[string]bool), sizes: make(map[int64]bool)}
	cacheWPCoreFiles(cache, root)
	if cache.Contains(HashFile(configPath)) {
		t.Fatal("site configuration was cached even though core checksums do not verify it")
	}
	if !cache.Contains(HashFile(corePath)) {
		t.Fatal("checksum-covered root core file was not cached")
	}
}
