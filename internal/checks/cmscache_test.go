package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// --- CMSHashCache Add / Contains / Size / Clear -----------------------

func TestCMSHashCacheAddAndContains(t *testing.T) {
	cache := &CMSHashCache{hashes: make(map[string]bool)}
	cache.Add("abc123")
	if !cache.Contains("abc123") {
		t.Error("expected true after Add")
	}
	if cache.Contains("unknown") {
		t.Error("unknown hash should not be contained")
	}
}

func TestCMSHashCacheSize(t *testing.T) {
	cache := &CMSHashCache{hashes: make(map[string]bool)}
	if cache.Size() != 0 {
		t.Errorf("empty size = %d", cache.Size())
	}
	cache.Add("a")
	cache.Add("b")
	if cache.Size() != 2 {
		t.Errorf("size = %d, want 2", cache.Size())
	}
}

func TestCMSHashCacheClear(t *testing.T) {
	cache := &CMSHashCache{hashes: make(map[string]bool)}
	cache.Add("a")
	cache.Clear()
	if cache.Size() != 0 {
		t.Errorf("size after clear = %d", cache.Size())
	}
	if cache.Contains("a") {
		t.Error("should not contain after clear")
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
	cache.Add(h)

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
