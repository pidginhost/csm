package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsWebshellName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"h4x0r.php", true},
		{"c99.php", true},
		{"shell.php", true},
		{"cmd.php", true},
		{"index.php", false},
		{"wp-config.php", false},
		{"style.css", false},
	}
	for _, tt := range tests {
		if got := isWebshellName(tt.name); got != tt.want {
			t.Errorf("isWebshellName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsSuspiciousPHPName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"shell.php", true},
		{"cmd.php", true},
		{"backdoor.php", true},
		{"upload.php", true},
		{"x7y2.php", true}, // short random
		{"ab1.php", true},  // short random with digit
		{"functions.php", false},
		{"wp-config.php", false},
		{"index.php", false},
		{"style.css", false},
		{"my-long-plugin-name.php", false},
	}
	for _, tt := range tests {
		if got := isSuspiciousPHPName(tt.name); got != tt.want {
			t.Errorf("isSuspiciousPHPName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsKnownSafeUpload(t *testing.T) {
	tests := []struct {
		path string
		name string
		want bool
	}{
		{"/home/user/public_html/wp-content/uploads/index.php", "index.php", true},
		{"/home/user/public_html/wp-content/uploads/redux/color.php", "color.php", true},
		{"/home/user/public_html/wp-content/uploads/mailchimp-for-wp/debug.php", "debug.php", true},
		{"/home/user/public_html/wp-content/uploads/evil.php", "evil.php", false},
		{"/home/user/public_html/wp-content/uploads/2024/shell.php", "shell.php", false},
	}
	for _, tt := range tests {
		if got := isKnownSafeUpload(tt.path, tt.name); got != tt.want {
			t.Errorf("isKnownSafeUpload(%q, %q) = %v, want %v", tt.path, tt.name, got, tt.want)
		}
	}
}

// --- loadDirCache / saveDirCache round-trip ----------------------------

func TestDirCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := dirMtimeCache{"/foo": 1000, "/bar": 2000}
	saveDirCache(dir, orig)

	loaded := loadDirCache(dir)
	if loaded["/foo"] != 1000 || loaded["/bar"] != 2000 {
		t.Errorf("got %v, want %v", loaded, orig)
	}
}

func TestLoadDirCacheMissing(t *testing.T) {
	loaded := loadDirCache(t.TempDir())
	if len(loaded) != 0 {
		t.Errorf("missing file should return empty cache, got %v", loaded)
	}
}

// --- dirChanged -------------------------------------------------------

func TestDirChangedFirstSeen(t *testing.T) {
	dir := t.TempDir()
	cache := make(dirMtimeCache)
	if !dirChanged(dir, cache, false) {
		t.Error("first time seeing dir should report changed")
	}
}

func TestDirChangedUnchanged(t *testing.T) {
	dir := t.TempDir()
	cache := make(dirMtimeCache)
	_ = dirChanged(dir, cache, false) // first call populates cache
	if dirChanged(dir, cache, false) {
		t.Error("unchanged dir should report not changed")
	}
}

func TestDirChangedForceFullScan(t *testing.T) {
	dir := t.TempDir()
	cache := make(dirMtimeCache)
	_ = dirChanged(dir, cache, false)
	if !dirChanged(dir, cache, true) {
		t.Error("force full scan should always report changed")
	}
}

func TestDirChangedMissing(t *testing.T) {
	cache := make(dirMtimeCache)
	if !dirChanged(filepath.Join(t.TempDir(), "missing"), cache, false) {
		t.Error("missing dir should report changed")
	}
}

// --- writeIndex / loadIndex round-trip --------------------------------

func TestWriteLoadIndexRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.idx")
	entries := []string{"/a/b.php", "/c/d.php", "/e/f.phtml"}
	writeIndex(path, entries)

	loaded := loadIndex(path)
	if len(loaded) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(loaded), len(entries))
	}
	for i, e := range entries {
		if loaded[i] != e {
			t.Errorf("index %d: got %q, want %q", i, loaded[i], e)
		}
	}
}

func TestLoadIndexMissing(t *testing.T) {
	if got := loadIndex(filepath.Join(t.TempDir(), "nope")); got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

// --- copyFile ---------------------------------------------------------

func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	_ = os.WriteFile(src, []byte("hello"), 0644)
	copyFile(src, dst)

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("dst not created: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q, want hello", data)
	}
}

func TestCopyFileMissingSrc(t *testing.T) {
	dir := t.TempDir()
	copyFile(filepath.Join(dir, "missing"), filepath.Join(dir, "dst"))
	// Should not panic.
}

// --- groupEntriesByUploadDir ------------------------------------------

func TestGroupEntriesByUploadDir(t *testing.T) {
	entries := []string{
		"/home/u/public_html/wp-content/uploads/evil.php",
		"/home/u/public_html/wp-content/uploads/2024/bad.php",
		"/home/u/public_html/.config/miner",
	}
	grouped := groupEntriesByUploadDir(entries)
	if len(grouped) != 3 {
		t.Errorf("got %d groups, want 3", len(grouped))
	}
	uploadsDir := "/home/u/public_html/wp-content/uploads"
	if len(grouped[uploadsDir]) != 1 {
		t.Errorf("uploads group got %d, want 1", len(grouped[uploadsDir]))
	}
}

// --- scanDirForPHP with t.TempDir ------------------------------------

func TestScanDirForPHPFindsFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "evil.php"), []byte("<?php"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.php"), []byte("<?php"), 0644) // skipped
	_ = os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("text"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "trick.phtml"), []byte("<?php"), 0644)

	cache := make(dirMtimeCache)
	prev := make(map[string][]string)
	var entries []string
	scanDirForPHP(dir, 3, cache, prev, false, &entries)

	if len(entries) != 2 {
		t.Errorf("got %d entries %v, want 2 (evil.php + trick.phtml)", len(entries), entries)
	}
}

func TestScanDirForPHPMaxDepthZero(t *testing.T) {
	var entries []string
	scanDirForPHP(t.TempDir(), 0, make(dirMtimeCache), nil, false, &entries)
	if len(entries) != 0 {
		t.Errorf("maxDepth=0 should return nothing, got %v", entries)
	}
}

func TestScanDirForPHPCarriesForwardUnchanged(t *testing.T) {
	dir := t.TempDir()
	cache := make(dirMtimeCache)
	prev := map[string][]string{dir: {"/old/entry.php"}}

	// First call: populates cache
	var e1 []string
	scanDirForPHP(dir, 3, cache, prev, false, &e1)

	// Second call: dir mtime unchanged, should carry forward
	var e2 []string
	scanDirForPHP(dir, 3, cache, prev, false, &e2)
	found := false
	for _, e := range e2 {
		if e == "/old/entry.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected carried-forward entry, got %v", e2)
	}
}

// --- scanDirForExecutables -------------------------------------------

func TestScanDirForExecutablesFindsExec(t *testing.T) {
	dir := t.TempDir()
	execPath := filepath.Join(dir, "miner")
	_ = os.WriteFile(execPath, []byte("#!/bin/sh"), 0755)
	noExecPath := filepath.Join(dir, "readme.txt")
	_ = os.WriteFile(noExecPath, []byte("text"), 0644)

	cache := make(dirMtimeCache)
	var entries []string
	scanDirForExecutables(dir, 3, cache, nil, false, &entries)
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1 executable", len(entries))
	}
}

// --- scanDirForSuspiciousExt -----------------------------------------

func TestScanDirForSuspiciousExtFindsPhtmlPht(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "evil.phtml"), []byte("<?php"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "trick.pht"), []byte("<?php"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("text"), 0644)

	cache := make(dirMtimeCache)
	var entries []string
	scanDirForSuspiciousExt(dir, 2, cache, nil, false, &entries)
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2 suspicious", len(entries))
	}
}
