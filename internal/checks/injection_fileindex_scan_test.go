package checks

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// scanDirForSuspiciousExt: walks a directory tree (bounded by maxDepth),
// honoring the dirMtimeCache shortcut and the suspiciousExtensions allowlist.

func TestScanDirForSuspiciousExtRespectsMaxDepthZero(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "a.phtml"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var entries []string
	scanDirForSuspiciousExt(tmp, 0, dirMtimeCache{}, nil, true, &entries)
	if len(entries) != 0 {
		t.Errorf("maxDepth=0 should yield no entries, got %v", entries)
	}
}

func TestScanDirForSuspiciousExtMissingDirIsSilent(t *testing.T) {
	var entries []string
	scanDirForSuspiciousExt("/nonexistent-dir-xyz", 4, dirMtimeCache{}, nil, true, &entries)
	if len(entries) != 0 {
		t.Errorf("missing dir should yield no entries, got %v", entries)
	}
}

func TestScanDirForSuspiciousExtFlagsKnownExtensions(t *testing.T) {
	tmp := t.TempDir()
	for _, n := range []string{"x.phtml", "y.pht", "z.php5", "harmless.php", "boring.txt"} {
		if err := os.WriteFile(filepath.Join(tmp, n), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var entries []string
	scanDirForSuspiciousExt(tmp, 4, dirMtimeCache{}, nil, true, &entries)

	sort.Strings(entries)
	got := map[string]bool{}
	for _, e := range entries {
		got[filepath.Base(e)] = true
	}
	for _, want := range []string{"x.phtml", "y.pht", "z.php5"} {
		if !got[want] {
			t.Errorf("expected %s flagged, got %v", want, entries)
		}
	}
	if got["harmless.php"] || got["boring.txt"] {
		t.Errorf("non-listed extensions should NOT be flagged, got %v", entries)
	}
}

func TestScanDirForSuspiciousExtRecursesIntoSubdirs(t *testing.T) {
	tmp := t.TempDir()
	deep := filepath.Join(tmp, "a", "b")
	if err := os.MkdirAll(deep, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "buried.haxor"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var entries []string
	scanDirForSuspiciousExt(tmp, 4, dirMtimeCache{}, nil, true, &entries)
	found := false
	for _, e := range entries {
		if filepath.Base(e) == "buried.haxor" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected nested .haxor file to be flagged, got %v", entries)
	}
}

func TestScanDirForSuspiciousExtUsesPrevWhenDirUnchanged(t *testing.T) {
	tmp := t.TempDir()
	// Pre-populate cache with the dir's current mtime so dirChanged returns
	// false (and the function takes the cache shortcut).
	info, err := os.Stat(tmp)
	if err != nil {
		t.Fatal(err)
	}
	cache := dirMtimeCache{tmp: info.ModTime().Unix()}
	prev := map[string][]string{tmp: {"/cached/x.phtml", "/cached/y.pht"}}

	var entries []string
	scanDirForSuspiciousExt(tmp, 4, cache, prev, false, &entries)

	if len(entries) != 2 || entries[0] != "/cached/x.phtml" || entries[1] != "/cached/y.pht" {
		t.Errorf("expected cached entries to be reused, got %v", entries)
	}
}

func TestScanDirForSuspiciousExtForceFullScanIgnoresCache(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "fresh.pht"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(tmp)
	cache := dirMtimeCache{tmp: info.ModTime().Unix()}
	prev := map[string][]string{tmp: {"/cached/old.phtml"}}

	var entries []string
	scanDirForSuspiciousExt(tmp, 4, cache, prev, true, &entries)

	// forceFullScan=true should re-scan, picking up fresh.pht and ignoring
	// the cached "/cached/old.phtml" entry entirely.
	for _, e := range entries {
		if e == "/cached/old.phtml" {
			t.Errorf("cached entry should be ignored on forced rescan, got %v", entries)
		}
	}
	found := false
	for _, e := range entries {
		if filepath.Base(e) == "fresh.pht" {
			found = true
		}
	}
	if !found {
		t.Errorf("fresh.pht should be flagged on forced rescan, got %v", entries)
	}
}
