package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
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
	uploadsDir := "/home/u/public_html/wp-content/uploads"
	nestedUploadsDir := filepath.Join(uploadsDir, "2026")
	entries := []string{
		"/home/u/public_html/wp-content/uploads/evil.php",
		filepath.Join(nestedUploadsDir, "bad.php"),
		"/home/u/public_html/.config/miner",
	}
	grouped := groupEntriesByUploadDir(entries)
	if len(grouped[uploadsDir]) != 2 {
		t.Errorf("uploads group got %d, want both direct and nested entries", len(grouped[uploadsDir]))
	}
	if len(grouped[nestedUploadsDir]) != 1 {
		t.Errorf("nested uploads group got %d, want 1", len(grouped[nestedUploadsDir]))
	}
}

// --- scanDirForPHP with t.TempDir ------------------------------------

func TestScanDirForPHPFindsFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "evil.php"), []byte("<?php"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.php"), []byte("<?php"), 0644) // indexed; inert stub suppressed later by content analysis
	_ = os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("text"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "trick.phtml"), []byte("<?php"), 0644)

	cache := make(dirMtimeCache)
	prev := make(map[string][]string)
	var entries []string
	scanDirForPHP(dir, 3, cache, prev, false, &entries)

	if len(entries) != 3 {
		t.Errorf("got %d entries %v, want 3 (evil.php + index.php + trick.phtml)", len(entries), entries)
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

func TestScanDirForPHPCarriesForwardNestedEntriesWhenRootUnchanged(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	nestedUpload := filepath.Join(dir, "2026", "05", "shell.php")
	nestedLanguage := filepath.Join(dir, "themes", "theme-ro_RO.l10n.php")
	prev := groupEntriesByUploadDir([]string{nestedUpload, nestedLanguage})
	cache := dirMtimeCache{dir: info.ModTime().Unix()}

	var entries []string
	scanDirForPHP(dir, 6, cache, prev, false, &entries)

	got := map[string]bool{}
	for _, entry := range entries {
		got[entry] = true
	}
	for _, want := range []string{nestedUpload, nestedLanguage} {
		if !got[want] {
			t.Errorf("expected cached nested entry %q to be carried forward, got %v", want, entries)
		}
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

// --- classifySensitiveDirPHP ---------------------------------------------

func TestClassifySensitiveDirPHP_CleanLanguages_Warning(t *testing.T) {
	tmp := t.TempDir()

	cleanPath := filepath.Join(tmp, "home", "u", "public_html",
		"wp-content", "languages", "customstrings.php")
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`<?php
return ['items' => ['greeting' => 'hello', 'farewell' => 'bye']];
`)
	if err := os.WriteFile(cleanPath, body, 0o644); err != nil {
		t.Fatal(err)
	}

	sev, check, _ := classifySensitiveDirPHP(cleanPath, filepath.Base(cleanPath))
	if sev != alert.Warning {
		t.Errorf("clean PHP in /languages/ must be Warning, got %v", sev)
	}
	if check != "new_php_in_sensitive_dir_clean" {
		t.Errorf("check = %q, want new_php_in_sensitive_dir_clean", check)
	}
}

func TestClassifySensitiveDirPHP_ObfuscatedUpgrade_StaysCritical(t *testing.T) {
	tmp := t.TempDir()

	// Two indicators trip the Critical path in analyzePHPContent:
	// (a) code-eval wrapping base64_decode on same line (hasNestedEvalDecode),
	// (b) >10 goto statements (LEVIATHAN-style spaghetti obfuscation).
	evilPath := filepath.Join(tmp, "home", "u", "public_html",
		"wp-content", "upgrade", "theme.1.0", "evil.php")
	if err := os.MkdirAll(filepath.Dir(evilPath), 0o755); err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	body.WriteString("<?php\n")
	// Split the literal so this source file itself does not trip local
	// Write/Edit security hooks; the runtime behaviour is unchanged.
	body.WriteString(`ev` + `al(base64_decode($payload));` + "\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&body, "goto lbl%d; lbl%d:\n", i, i)
	}
	if err := os.WriteFile(evilPath, []byte(body.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	sev, _, _ := classifySensitiveDirPHP(evilPath, filepath.Base(evilPath))
	if sev != alert.Critical {
		t.Errorf("obfuscated PHP in /upgrade/ must stay Critical, got %v", sev)
	}
}

func TestClassifySensitiveDirPHP_NotASensitiveDir_ReturnsUnset(t *testing.T) {
	sev, _, _ := classifySensitiveDirPHP(
		"/home/u/public_html/wp-content/plugins/foo/bar.php", "bar.php")
	if sev >= 0 {
		t.Errorf("non-sensitive path must return negative severity, got %v", sev)
	}
}

func TestClassifySensitiveDirPHP_SafePatterns_ReturnsUnset(t *testing.T) {
	cases := []string{
		"/home/u/public_html/wp-content/languages/index.php",
		"/home/u/public_html/wp-content/languages/en_US.l10n.php",
		"/home/u/public_html/wp-content/languages/admin-en_US.php",
	}
	for _, p := range cases {
		sev, _, _ := classifySensitiveDirPHP(p, filepath.Base(p))
		if sev >= 0 {
			t.Errorf("%s: expected negative severity, got %v", p, sev)
		}
	}
}
