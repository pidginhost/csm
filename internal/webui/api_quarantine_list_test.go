package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// apiQuarantine lists entries found as <item>.meta files under
// quarantineDir and quarantineDir/pre_clean. Drive it with an empty
// dir, a mix of valid + unreadable metas, and the pre_clean subdir.

func TestApiQuarantineEmptyDirReturnsEmptyList(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantine(w, httptest.NewRequest(http.MethodGet, "/api/v1/quarantine", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := strings.TrimSpace(w.Body.String())
	// Empty slice serialises as either "null" or "[]" depending on the
	// writer — both are acceptable as "no entries".
	if body != "[]" && body != "null" {
		t.Errorf("expected empty list, got %q", body)
	}
}

func TestApiQuarantineListsRootAndPreCleanEntries(t *testing.T) {
	tmp := t.TempDir()
	preClean := filepath.Join(tmp, "pre_clean")
	if err := os.MkdirAll(preClean, 0700); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, tmp)

	// Root-level quarantine entry.
	rootID := "20260415-100000_evil.php"
	rootMeta := map[string]interface{}{
		"original_path":  "/home/alice/public_html/evil.php",
		"size":           int64(4096),
		"quarantined_at": time.Now().Format(time.RFC3339),
		"reason":         "Webshell detected",
	}
	rmj, _ := json.Marshal(rootMeta)
	if err := os.WriteFile(filepath.Join(tmp, rootID+".meta"), rmj, 0600); err != nil {
		t.Fatal(err)
	}

	// Pre-clean (surgical cleaning backup) entry.
	pcID := "20260415-110000_plugin.php"
	pcMeta := map[string]interface{}{
		"original_path":  "/home/bob/public_html/wp-content/plugins/foo/plugin.php",
		"size":           int64(8192),
		"quarantined_at": time.Now().Format(time.RFC3339),
		"reason":         "Pre-clean backup",
	}
	pmj, _ := json.Marshal(pcMeta)
	if err := os.WriteFile(filepath.Join(preClean, pcID+".meta"), pmj, 0600); err != nil {
		t.Fatal(err)
	}

	// Corrupt meta (invalid JSON) — must be silently skipped.
	if err := os.WriteFile(filepath.Join(tmp, "corrupt.meta"), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantine(w, httptest.NewRequest(http.MethodGet, "/api/v1/quarantine", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var got []struct {
		ID           string `json:"id"`
		OriginalPath string `json:"original_path"`
		Size         int64  `json:"size"`
		Reason       string `json:"reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad JSON: %v body=%s", err, w.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (root + pre_clean), got %d: %+v", len(got), got)
	}

	hasRoot, hasPreClean := false, false
	for _, e := range got {
		if e.ID == rootID {
			hasRoot = true
		}
		if e.ID == "pre_clean:"+pcID {
			hasPreClean = true
		}
	}
	if !hasRoot {
		t.Errorf("root entry missing from listing")
	}
	if !hasPreClean {
		t.Errorf("pre_clean entry missing or wrong id prefix: %+v", got)
	}
}

// Stale-entry filter: once a quarantined file has been restored in place
// byte-for-byte, the archive serves no purpose and the UI must hide it.
// Operator complaint: the quarantine page listed 14 WPML false-positive
// entries even after the originals were cp -p'd back from the archives.
// The live filesystem is authoritative; the UI must reflect it.

func quarantineListingPaths(t *testing.T) []string {
	t.Helper()
	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantine(w, httptest.NewRequest(http.MethodGet, "/api/v1/quarantine", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var got []struct {
		OriginalPath string `json:"original_path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad JSON: %v body=%s", err, w.Body.String())
	}
	var paths []string
	for _, e := range got {
		paths = append(paths, e.OriginalPath)
	}
	return paths
}

func quarantineListingEntries(t *testing.T) []struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	OriginalPath string `json:"original_path"`
	LiveState    string `json:"live_state"`
} {
	t.Helper()
	s := &Server{}
	w := httptest.NewRecorder()
	s.apiQuarantine(w, httptest.NewRequest(http.MethodGet, "/api/v1/quarantine", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var got []struct {
		ID           string `json:"id"`
		Kind         string `json:"kind"`
		OriginalPath string `json:"original_path"`
		LiveState    string `json:"live_state"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad JSON: %v body=%s", err, w.Body.String())
	}
	return got
}

func writeArchive(t *testing.T, dir, id, originalPath, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, id), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	meta := map[string]interface{}{
		"original_path":  originalPath,
		"size":           int64(len(content)),
		"quarantined_at": time.Now().Format(time.RFC3339),
		"reason":         "test",
	}
	mj, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(dir, id+".meta"), mj, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestApiQuarantineHidesEntryWhenOriginalRestoredIdentical(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	home := t.TempDir()
	orig := filepath.Join(home, "wpml_zip.php")
	body := "<?php /* PHPZip library body */ ?>"
	if err := os.WriteFile(orig, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	writeArchive(t, tmp, "20260420-111140_archived.php", orig, body)

	paths := quarantineListingPaths(t)
	for _, p := range paths {
		if p == orig {
			t.Fatalf("restored-identical entry must be hidden; got %v", paths)
		}
	}
}

func TestApiQuarantineShowsEntryWhenOriginalMissing(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	home := t.TempDir()
	orig := filepath.Join(home, "evil.php")
	writeArchive(t, tmp, "20260420-120000_missing.php", orig, "<?php attack(); ?>")

	entries := quarantineListingEntries(t)
	found := false
	for _, e := range entries {
		if e.OriginalPath == orig {
			found = true
			if e.Kind != "quarantine" {
				t.Fatalf("kind = %q, want quarantine", e.Kind)
			}
			if e.LiveState != "original_missing" {
				t.Fatalf("live_state = %q, want original_missing", e.LiveState)
			}
			break
		}
	}
	if !found {
		t.Fatalf("missing-original entry must be shown; got %+v", entries)
	}
}

func TestApiQuarantineShowsEntryWhenOriginalDiffers(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineDir(t, tmp)

	home := t.TempDir()
	orig := filepath.Join(home, "plugin.php")
	// Live file is NOT the archived one (operator replaced with clean vendor
	// copy from elsewhere, or attacker re-dropped a different payload).
	if err := os.WriteFile(orig, []byte("<?php /* different */ ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	writeArchive(t, tmp, "20260420-130000_differs.php", orig, "<?php /* archived */ ?>")

	entries := quarantineListingEntries(t)
	found := false
	for _, e := range entries {
		if e.OriginalPath == orig {
			found = true
			if e.LiveState != "live_differs" {
				t.Fatalf("live_state = %q, want live_differs", e.LiveState)
			}
			break
		}
	}
	if !found {
		t.Fatalf("content-diverged entry must be shown; got %+v", entries)
	}
}

func TestApiQuarantineMarksPreCleanEntries(t *testing.T) {
	tmp := t.TempDir()
	preClean := filepath.Join(tmp, "pre_clean")
	if err := os.MkdirAll(preClean, 0700); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, tmp)

	home := t.TempDir()
	orig := filepath.Join(home, ".htaccess")
	writeArchive(t, preClean, "20260420-150000_htaccess", orig, "RewriteRule bad")

	entries := quarantineListingEntries(t)
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1: %+v", len(entries), entries)
	}
	if entries[0].Kind != "pre_clean" {
		t.Fatalf("kind = %q, want pre_clean", entries[0].Kind)
	}
	if entries[0].ID == "" || !strings.HasPrefix(entries[0].ID, preCleanQuarantineIDPrefix) {
		t.Fatalf("pre_clean id prefix missing: %+v", entries[0])
	}
}

func TestApiQuarantineStaleFilterAppliesToPreClean(t *testing.T) {
	tmp := t.TempDir()
	preClean := filepath.Join(tmp, "pre_clean")
	if err := os.MkdirAll(preClean, 0700); err != nil {
		t.Fatal(err)
	}
	withQuarantineDir(t, tmp)

	home := t.TempDir()
	orig := filepath.Join(home, "cleaned.php")
	body := "<?php /* pre-clean snapshot */ ?>"
	if err := os.WriteFile(orig, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	writeArchive(t, preClean, "20260420-140000_cleaned.php", orig, body)

	paths := quarantineListingPaths(t)
	for _, p := range paths {
		if p == orig {
			t.Fatalf("pre_clean backup identical to live file must be hidden; got %v", paths)
		}
	}
}
