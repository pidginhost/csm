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
