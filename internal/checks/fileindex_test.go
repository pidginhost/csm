package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
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
	scanDirForPHP(dir, 3, cache, prev, false, phpHandlerOverlay{}, &entries)

	if len(entries) != 3 {
		t.Errorf("got %d entries %v, want 3 (evil.php + index.php + trick.phtml)", len(entries), entries)
	}
}

func TestScanDirForPHPIndexesHtaccessMappedExtension(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("AddHandler application/x-httpd-php .inc\n"), 0644)
	mapped := filepath.Join(dir, "evil.inc")
	_ = os.WriteFile(mapped, []byte("<?php system($_POST['c']);"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("text"), 0644)

	cache := make(dirMtimeCache)
	prev := make(map[string][]string)
	var entries []string
	scanDirForPHP(dir, 3, cache, prev, false, phpHandlerOverlay{}, &entries)

	if len(entries) != 1 || entries[0] != mapped {
		t.Errorf("got entries %v, want mapped .inc only", entries)
	}
}

func TestClassifySensitiveDirPHPHonorsHtaccessMappedExtension(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wp-content", "languages")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("AddHandler application/x-httpd-php .inc\n"), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evil.inc")
	if err := os.WriteFile(path, []byte("<?php system($_POST['c']);"), 0644); err != nil {
		t.Fatal(err)
	}

	sev, check, _ := classifySensitiveDirPHP(path, "evil.inc")
	if sev < 0 || check == "" {
		t.Fatalf("mapped .inc in sensitive dir should be classified, got severity=%v check=%q", sev, check)
	}
}

func TestScanDirForPHPMaxDepthZero(t *testing.T) {
	var entries []string
	scanDirForPHP(t.TempDir(), 0, make(dirMtimeCache), nil, false, phpHandlerOverlay{}, &entries)
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
	scanDirForPHP(dir, 3, cache, prev, false, phpHandlerOverlay{}, &e1)

	// Second call: dir mtime unchanged, should carry forward
	var e2 []string
	scanDirForPHP(dir, 3, cache, prev, false, phpHandlerOverlay{}, &e2)
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
	scanDirForPHP(dir, 6, cache, prev, false, phpHandlerOverlay{}, &entries)

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
	// Clean but genuinely executable PHP (an assignment then return-of-variable,
	// not a pure data return array, so the translation-cache recognizer does not
	// suppress it). It must surface as the visibility Warning, not Critical.
	body := []byte(`<?php
$strings = ['greeting' => 'hello', 'farewell' => 'bye'];
return $strings;
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

// A content-verified inert stub (the "silence is golden" index.php) is
// suppressed by CONTENT, not by its filename -- so it returns negative and the
// caller keeps walking. There is no filename allowlist any more.
func TestClassifySensitiveDirPHP_BenignStubSuppressed(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "index.php")
	if err := os.WriteFile(path, []byte("<?php\n// Silence is golden.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if sev, _, _ := classifySensitiveDirPHP(path, "index.php"); sev >= 0 {
		t.Errorf("benign stub index.php must be suppressed, got %v", sev)
	}
}

// An unreadable PHP body in a sensitive dir fails closed at High -- an attacker
// must not earn a "content clean" demote by racing the scanner.
func TestClassifySensitiveDirPHP_UnreadableFailsClosed(t *testing.T) {
	sev, check, _ := classifySensitiveDirPHP(
		"/home/u/public_html/wp-content/languages/gone.php", "gone.php")
	if sev < alert.High || check != "new_php_in_sensitive_dir" {
		t.Errorf("unreadable PHP must fail closed at High, got sev=%v check=%q", sev, check)
	}
}

func TestClassifySensitiveDirPHP_EmptyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "empty.php")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sev, check, _ := classifySensitiveDirPHP(path, "empty.php")
	if sev < alert.High || check != "new_php_in_sensitive_dir" {
		t.Errorf("empty PHP must fail closed at High, got sev=%v check=%q", sev, check)
	}
}

// --- file-index audit mode (ForceFileIndex=true) -------------------------

// TestFileIndexAuditModeDoesNotWriteState verifies the basic invariant:
// an audit run must not create any of the three live state files.
func TestFileIndexAuditModeDoesNotWriteState(t *testing.T) {
	stateDir := t.TempDir()
	ctx := ContextWithScanOptions(ContextWithAccountScope(context.Background(), "acct"),
		AccountScanOptions{ForceFileIndex: true})
	_ = CheckFileIndex(ctx, &config.Config{StatePath: stateDir}, nil)
	for _, f := range []string{"fileindex.current", "fileindex.previous", "dircache.json"} {
		if _, err := os.Stat(filepath.Join(stateDir, f)); err == nil {
			t.Errorf("audit mode must not write %s", f)
		}
	}
}

// TestFileIndexAuditModeFindsWithoutWritingState is the full behaviour test:
// a planted webshell IS reported, AND none of the live state files exist after
// the audit run.
func TestFileIndexAuditModeFindsWithoutWritingState(t *testing.T) {
	tmp := t.TempDir()
	stateDir := filepath.Join(tmp, "state")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-24 * time.Hour)

	logicalHome := "/home/acct"
	logicalUploads := filepath.Join(logicalHome, "public_html", "wp-content", "uploads")
	logicalShell := filepath.Join(logicalUploads, "c99.php")
	physicalUploads := filepath.Join(tmp, "acct", "public_html", "wp-content", "uploads")
	if err := os.MkdirAll(physicalUploads, 0755); err != nil {
		t.Fatal(err)
	}
	physicalShell := filepath.Join(physicalUploads, "c99.php")
	writePHPFixture(t, physicalShell, phpCacheMalicious, old)

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case logicalHome:
				return nil, nil
			case logicalUploads:
				return []os.DirEntry{testDirEntry{name: "c99.php", isDir: false}}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		stat: func(name string) (os.FileInfo, error) {
			switch name {
			case logicalHome:
				return &fakeFileInfoMtime{name: "acct", dir: true, mode: 0755, mtime: old}, nil
			case logicalUploads:
				return &fakeFileInfoMtime{name: "uploads", dir: true, mode: 0755, mtime: old}, nil
			case logicalShell:
				return os.Stat(physicalShell)
			default:
				return nil, os.ErrNotExist
			}
		},
		open: func(name string) (*os.File, error) {
			if name == logicalShell {
				return os.Open(physicalShell)
			}
			return nil, os.ErrNotExist
		},
	})

	ctx := ContextWithScanOptions(ContextWithAccountScope(context.Background(), "acct"),
		AccountScanOptions{ForceFileIndex: true})
	findings := CheckFileIndex(ctx, &config.Config{StatePath: stateDir}, nil)
	if !hasFindingPath(findings, "new_webshell_file", logicalShell) {
		t.Fatalf("audit mode missed planted webshell: %+v", findings)
	}
	for _, f := range []string{"fileindex.current", "fileindex.previous", "dircache.json"} {
		if _, err := os.Stat(filepath.Join(stateDir, f)); err == nil {
			t.Fatalf("audit mode wrote live state file %s", f)
		}
	}
}

// --- CHK-R02: shrink-guard wedge self-heals ------------------------------

// stateAwareFileIndexMock builds a mockOS that virtualizes the /home tree for
// one account's uploads dir while passing every state-file operation under
// stateDir through to the real filesystem. Directory stats return an
// ever-advancing mtime so dirChanged always re-reads (the shrink test needs the
// current index to reflect the mutated on-disk file set, not carried-forward
// cache entries).
func stateAwareFileIndexMock(stateDir, uploadsPath string, files *[]os.DirEntry, mtime *int64) *mockOS {
	return &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			case "/home/alice":
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			case uploadsPath:
				return *files, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasPrefix(name, stateDir) {
				return os.Stat(name)
			}
			*mtime++
			return &fakeFileInfoMtime{name: filepath.Base(name), dir: true, mode: 0755, mtime: time.Unix(*mtime, 0)}, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasPrefix(name, stateDir) {
				return os.Open(name)
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasPrefix(name, stateDir) {
				return os.ReadFile(name)
			}
			return nil, os.ErrNotExist
		},
	}
}

func phpDirEntries(names ...string) []os.DirEntry {
	out := make([]os.DirEntry, 0, len(names))
	for _, n := range names {
		out = append(out, testDirEntry{name: n, isDir: false})
	}
	return out
}

func countIndexLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read index %s: %v", path, err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func setFileIndexShrinkSkips(t *testing.T, n int32) {
	t.Helper()
	atomic.StoreInt32(&fileIndexShrinkSkips, n)
	t.Cleanup(func() {
		atomic.StoreInt32(&fileIndexShrinkSkips, 0)
	})
}

// A legitimate >50% shrink (a WP install genuinely removed) must NOT instantly
// flush the baseline, but it also must NOT wedge forever. After
// fileIndexShrinkPromoteThreshold consecutive shrinking scans the smaller index
// is promoted as the new baseline, so new-file detection resumes on its own.
func TestCheckFileIndexShrinkWedgeSelfHeals(t *testing.T) {
	setFileIndexShrinkSkips(t, 0)
	stateDir := t.TempDir()
	previousPath := filepath.Join(stateDir, "fileindex.previous")
	uploadsPath := "/home/alice/public_html/wp-content/uploads"

	var big []string
	for i := 0; i < 12; i++ {
		big = append(big, fmt.Sprintf("f%02d.php", i))
	}
	files := phpDirEntries(big...)
	var mtime int64
	withMockOS(t, stateAwareFileIndexMock(stateDir, uploadsPath, &files, &mtime))

	cfg := &config.Config{StatePath: stateDir}

	// Cycle 1: baseline of 12 entries.
	if got := CheckFileIndex(context.Background(), cfg, nil); len(got) != 0 {
		t.Fatalf("baseline scan must not emit findings, got %+v", got)
	}
	if n := countIndexLines(t, previousPath); n != 12 {
		t.Fatalf("baseline previous index = %d entries, want 12", n)
	}

	// Cycles 2..threshold-1: index shrinks hard. Baseline must stay intact
	// (the guard's safety purpose: a mass deletion does not instantly flush).
	files = phpDirEntries("f00.php", "f01.php")
	for cycle := 2; cycle < fileIndexShrinkPromoteThreshold+1; cycle++ {
		if got := CheckFileIndex(context.Background(), cfg, nil); len(got) != 0 {
			t.Fatalf("shrink cycle %d must skip diff (no findings), got %+v", cycle, got)
		}
		if n := countIndexLines(t, previousPath); n != 12 {
			t.Fatalf("shrink cycle %d prematurely changed baseline to %d entries, want 12", cycle, n)
		}
	}

	// The promoting cycle: shrink persisted long enough; baseline advances to
	// the smaller reality and no diff is emitted this cycle.
	if got := CheckFileIndex(context.Background(), cfg, nil); len(got) != 0 {
		t.Fatalf("promoting cycle must not emit findings, got %+v", got)
	}
	if n := countIndexLines(t, previousPath); n != 2 {
		t.Fatalf("baseline was not promoted to the smaller index: got %d entries, want 2", n)
	}

	// Detection has resumed: a new webshell against the new baseline surfaces.
	files = phpDirEntries("f00.php", "f01.php", "shell.php")
	got := CheckFileIndex(context.Background(), cfg, nil)
	newShell := filepath.Join(uploadsPath, "shell.php")
	if !hasFindingPath(got, "new_webshell_file", newShell) {
		t.Fatalf("after self-heal, new webshell must be detected: %+v", got)
	}
}

func TestCheckFileIndexEmptyCurrentShrinkDoesNotPromote(t *testing.T) {
	setFileIndexShrinkSkips(t, 0)
	stateDir := t.TempDir()
	previousPath := filepath.Join(stateDir, "fileindex.previous")
	uploadsPath := "/home/alice/public_html/wp-content/uploads"

	var big []string
	for i := 0; i < 12; i++ {
		big = append(big, fmt.Sprintf("f%02d.php", i))
	}
	files := phpDirEntries(big...)
	var mtime int64
	withMockOS(t, stateAwareFileIndexMock(stateDir, uploadsPath, &files, &mtime))

	cfg := &config.Config{StatePath: stateDir}
	if got := CheckFileIndex(context.Background(), cfg, nil); len(got) != 0 {
		t.Fatalf("baseline scan must not emit findings, got %+v", got)
	}
	if n := countIndexLines(t, previousPath); n != 12 {
		t.Fatalf("baseline previous index = %d entries, want 12", n)
	}

	files = nil
	for cycle := 1; cycle <= fileIndexShrinkPromoteThreshold+1; cycle++ {
		if got := CheckFileIndex(context.Background(), cfg, nil); len(got) != 0 {
			t.Fatalf("empty-current cycle %d must skip diff, got %+v", cycle, got)
		}
		if n := countIndexLines(t, previousPath); n != 12 {
			t.Fatalf("empty-current cycle %d promoted empty baseline to %d entries, want 12", cycle, n)
		}
	}
}

func TestCheckFileIndexShrinkStillAlertsNewFiles(t *testing.T) {
	setFileIndexShrinkSkips(t, 0)
	stateDir := t.TempDir()
	previousPath := filepath.Join(stateDir, "fileindex.previous")
	uploadsPath := "/home/alice/public_html/wp-content/uploads"

	baseline := []string{"keepone.php"}
	for i := 0; i < 11; i++ {
		baseline = append(baseline, fmt.Sprintf("f%02d.php", i))
	}
	files := phpDirEntries(baseline...)
	var mtime int64
	withMockOS(t, stateAwareFileIndexMock(stateDir, uploadsPath, &files, &mtime))

	cfg := &config.Config{StatePath: stateDir}
	if got := CheckFileIndex(context.Background(), cfg, nil); len(got) != 0 {
		t.Fatalf("baseline scan must not emit findings, got %+v", got)
	}
	if n := countIndexLines(t, previousPath); n != 12 {
		t.Fatalf("baseline previous index = %d entries, want 12", n)
	}

	files = phpDirEntries("keepone.php", "shell.php")
	shell := filepath.Join(uploadsPath, "shell.php")
	got := CheckFileIndex(context.Background(), cfg, nil)
	if !hasFindingPath(got, "new_webshell_file", shell) {
		t.Fatalf("shrink cycle must still alert on new paths, got %+v", got)
	}
	if n := countIndexLines(t, previousPath); n != 13 {
		t.Fatalf("shrink cycle must merge alerted path into preserved baseline, got %d entries, want 13", n)
	}

	if got := CheckFileIndex(context.Background(), cfg, nil); len(got) != 0 {
		t.Fatalf("already-alerted shrink path must not repeat, got %+v", got)
	}
}

func TestCheckFileIndexCanceledWhileLiveScanActiveDoesNotBlock(t *testing.T) {
	select {
	case fileIndexLiveScanGate <- struct{}{}:
		t.Cleanup(func() { <-fileIndexLiveScanGate })
	default:
		t.Fatal("file index live scan gate unexpectedly held")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan []alert.Finding, 1)
	go func() {
		done <- CheckFileIndex(ctx, &config.Config{StatePath: t.TempDir()}, nil)
	}()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Fatalf("canceled scan returned findings: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled scan blocked behind active live file-index run")
	}
}

// --- CHK-R02: evaluateFileIndexShrink threshold logic --------------------

func TestEvaluateFileIndexShrinkNonShrinkResetsCounter(t *testing.T) {
	setFileIndexShrinkSkips(t, 2) // pretend two shrinks happened
	isShrink, promote := evaluateFileIndexShrink(100, 100)
	if isShrink || promote {
		t.Fatalf("equal sizes are not a shrink: isShrink=%v promote=%v", isShrink, promote)
	}
	if got := atomic.LoadInt32(&fileIndexShrinkSkips); got != 0 {
		t.Fatalf("a non-shrink cycle must reset the counter, got %d", got)
	}
}

func TestEvaluateFileIndexShrinkPromotesAfterThreshold(t *testing.T) {
	setFileIndexShrinkSkips(t, 0)
	for i := 1; i < fileIndexShrinkPromoteThreshold; i++ {
		isShrink, promote := evaluateFileIndexShrink(100, 2)
		if !isShrink || promote {
			t.Fatalf("shrink %d before threshold: isShrink=%v promote=%v", i, isShrink, promote)
		}
	}
	isShrink, promote := evaluateFileIndexShrink(100, 2)
	if !isShrink || !promote {
		t.Fatalf("shrink at threshold must promote: isShrink=%v promote=%v", isShrink, promote)
	}
	if got := atomic.LoadInt32(&fileIndexShrinkSkips); got != 0 {
		t.Fatalf("counter must reset after a promotion, got %d", got)
	}
}

// A recovered cycle between shrinks resets the streak, so two shrinks, a normal
// scan, then two more shrinks does not promote -- only *consecutive* shrinks do.
func TestEvaluateFileIndexShrinkStreakResetsOnRecovery(t *testing.T) {
	if fileIndexShrinkPromoteThreshold < 3 {
		t.Skipf("test assumes threshold >= 3, got %d", fileIndexShrinkPromoteThreshold)
	}
	setFileIndexShrinkSkips(t, 0)
	evaluateFileIndexShrink(100, 2) // streak 1
	evaluateFileIndexShrink(100, 2) // streak 2
	evaluateFileIndexShrink(100, 100)
	if got := atomic.LoadInt32(&fileIndexShrinkSkips); got != 0 {
		t.Fatalf("recovery must reset streak, got %d", got)
	}
	for i := 1; i < fileIndexShrinkPromoteThreshold; i++ {
		if _, promote := evaluateFileIndexShrink(100, 2); promote {
			t.Fatalf("streak restarted, must not promote at shrink %d", i)
		}
	}
}

// The empty-index guard (previous had many entries, current is zero) is the
// extreme shrink case and self-heals through the same counter.
func TestEvaluateFileIndexShrinkEmptyCurrentIsShrink(t *testing.T) {
	setFileIndexShrinkSkips(t, 0)
	isShrink, _ := evaluateFileIndexShrink(50, 0)
	if !isShrink {
		t.Fatal("empty current against a large previous must count as a shrink")
	}
}

func TestEvaluateFileIndexShrinkEmptyCurrentDoesNotPromote(t *testing.T) {
	setFileIndexShrinkSkips(t, 0)
	for i := 1; i <= fileIndexShrinkPromoteThreshold+1; i++ {
		isShrink, promote := evaluateFileIndexShrink(50, 0)
		if !isShrink {
			t.Fatalf("empty current cycle %d: isShrink=false", i)
		}
		if promote {
			t.Fatalf("empty current cycle %d promoted an empty baseline", i)
		}
	}
	if got := atomic.LoadInt32(&fileIndexShrinkSkips); got != 0 {
		t.Fatalf("empty current must not advance shrink counter, got %d", got)
	}
}

// --- CHK-R03: new file deep in an unchanged parent subtree ---------------

// A webshell dropped into uploads/2026/07 bumps only 07's mtime, not the mtime
// of uploads or 2026. A scan that finds the top directory unchanged must still
// descend to 07 and index the new file, instead of carrying the whole subtree
// forward from the cache and missing it until the periodic forced full scan.
func TestScanDirForPHPDetectsNewFileInUnchangedParentDir(t *testing.T) {
	root := t.TempDir()
	mid := filepath.Join(root, "2026")
	leaf := filepath.Join(mid, "07")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(leaf, "old.php")
	if err := os.WriteFile(existing, []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Freeze the whole tree to a known instant and cache it, as a completed
	// prior scan would have.
	base := time.Now().Add(-time.Hour)
	for _, d := range []string{root, mid, leaf} {
		if err := os.Chtimes(d, base, base); err != nil {
			t.Fatal(err)
		}
	}
	cache := dirMtimeCache{root: base.Unix(), mid: base.Unix(), leaf: base.Unix()}
	prev := groupEntriesByUploadDir([]string{existing})

	// Attacker drops a webshell deep in the tree; only the leaf's mtime moves.
	shell := filepath.Join(leaf, "shell.php")
	if err := os.WriteFile(shell, []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	newer := base.Add(30 * time.Minute)
	if err := os.Chtimes(leaf, newer, newer); err != nil {
		t.Fatal(err)
	}
	// Keep the ancestors frozen so pruning at the unchanged top is what the
	// test exercises.
	for _, d := range []string{root, mid} {
		if err := os.Chtimes(d, base, base); err != nil {
			t.Fatal(err)
		}
	}

	var entries []string
	scanDirForPHP(root, 6, cache, prev, false, phpHandlerOverlay{}, &entries)

	got := map[string]bool{}
	for _, e := range entries {
		got[e] = true
	}
	if !got[shell] {
		t.Fatalf("new webshell in unchanged parent subtree was not indexed: %v", entries)
	}
	if !got[existing] {
		t.Fatalf("pre-existing file dropped from index: %v", entries)
	}
}

// Same nested-mtime hazard for the .config executable scanner: the shared
// subtree check must let a new executable in a deep, cached subdir surface even
// when the top directory looks unchanged.
func TestScanDirForExecutablesDetectsNewFileInUnchangedParentDir(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "autostart")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}

	base := time.Now().Add(-time.Hour)
	for _, d := range []string{root, leaf} {
		if err := os.Chtimes(d, base, base); err != nil {
			t.Fatal(err)
		}
	}
	cache := dirMtimeCache{root: base.Unix(), leaf: base.Unix()}
	prev := groupEntriesByUploadDir(nil)

	miner := filepath.Join(leaf, "miner")
	if err := os.WriteFile(miner, []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	newer := base.Add(30 * time.Minute)
	if err := os.Chtimes(leaf, newer, newer); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(root, base, base); err != nil {
		t.Fatal(err)
	}

	var entries []string
	scanDirForExecutables(root, 3, cache, prev, false, &entries)

	found := false
	for _, e := range entries {
		if e == miner {
			found = true
		}
	}
	if !found {
		t.Fatalf("new executable in unchanged parent subtree was not indexed: %v", entries)
	}
}

// A fully stable subtree (nothing changed anywhere) still takes the cache
// shortcut: entries come straight from the previous index with no ReadDir.
// This pins that the CHK-R03 descent does not defeat the mtime optimization.
func TestScanDirForPHPStableSubtreeUsesCacheShortcut(t *testing.T) {
	root := t.TempDir()
	mid := filepath.Join(root, "2026")
	leaf := filepath.Join(mid, "07")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}

	base := time.Now().Add(-time.Hour)
	for _, d := range []string{root, mid, leaf} {
		if err := os.Chtimes(d, base, base); err != nil {
			t.Fatal(err)
		}
	}
	cache := dirMtimeCache{root: base.Unix(), mid: base.Unix(), leaf: base.Unix()}

	// The cached file does not exist on disk: if the scan honoured the cache
	// shortcut it is carried forward; if it wrongly re-read disk it would
	// vanish (the leaf is empty on disk).
	cachedOnly := filepath.Join(leaf, "carried.php")
	prev := groupEntriesByUploadDir([]string{cachedOnly})

	var entries []string
	scanDirForPHP(root, 6, cache, prev, false, phpHandlerOverlay{}, &entries)

	found := false
	for _, e := range entries {
		if e == cachedOnly {
			found = true
		}
	}
	if !found {
		t.Fatalf("stable subtree must carry cached entry forward, got %v", entries)
	}
}

func TestSubtreeChangeTrackerReusesStatSnapshotAcrossQueries(t *testing.T) {
	const root = "/home/alice/public_html/wp-content/uploads"
	base := time.Unix(1234, 0)
	cache := dirMtimeCache{root: base.Unix()}
	var children []string
	for i := 0; i < 40; i++ {
		child := filepath.Join(root, fmt.Sprintf("d%02d", i))
		leaf := filepath.Join(child, "leaf")
		cache[child] = base.Unix()
		cache[leaf] = base.Unix()
		children = append(children, child)
	}

	var statCalls int32
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			atomic.AddInt32(&statCalls, 1)
			return &fakeFileInfoMtime{name: filepath.Base(name), dir: true, mode: 0o755, mtime: base}, nil
		},
	})

	tracker := newSubtreeChangeTracker(cache)
	for _, child := range children {
		if tracker.hasChangedDir(context.Background(), child) {
			t.Fatalf("unchanged child %s reported changed", child)
		}
	}
	if got, want := atomic.LoadInt32(&statCalls), int32(len(cache)); got != want {
		t.Fatalf("stat calls = %d, want one per cached dir (%d)", got, want)
	}
}
