package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A removal loaded after a restart has no sequence, so the cursor that clears
// alert state skips it. The snapshot must still return it.
func TestRemovedFilesIncludesLoadedRemovals(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	useRemovedFilesClock(t, &now)
	_, restart := useRemovedFilesState(t)
	loaded := filepath.Join(t.TempDir(), "loaded.php")
	rememberRemovedFile(loaded, strings.Repeat("a", 64), 1, "quarantine")
	restart()

	if since, _ := RemovedFilesSince(0); len(since) != 0 {
		t.Fatalf("loaded removal reported as new: %+v", since)
	}
	got := RemovedFiles()
	if len(got) != 1 || got[0].Path != loaded || got[0].Action != "quarantine" {
		t.Fatalf("RemovedFiles() = %+v, want the loaded removal of %s", got, loaded)
	}

	rememberRemovedFile(filepath.Join(t.TempDir(), "fresh.php"), strings.Repeat("b", 64), 2, "clean")
	if got := RemovedFiles(); len(got) != 2 {
		t.Fatalf("RemovedFiles() = %+v, want 2 removals", got)
	}

	now = now.Add(removedFileMemory)
	if got := RemovedFiles(); len(got) != 0 {
		t.Fatalf("expired removals still listed: %+v", got)
	}
}

func writeWebshellTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWebshellFlaggedFiles(t *testing.T) {
	home := t.TempDir()
	docroot := filepath.Join(home, "public_html")
	shop := filepath.Join(docroot, "shop")
	docroots := []string{docroot, shop}
	// The main site is a WordPress install; the upload directory is not.
	writeWebshellTestFile(t, filepath.Join(docroot, "wp-includes", "version.php"))

	listed := filepath.Join(docroot, "wp-includes", "listed.php")
	planted := filepath.Join(docroot, "wp-includes", "Text", "planted.php")
	stubPackageListing(t, func(path string) (bool, bool) {
		switch path {
		case listed:
			return true, true
		case planted:
			return false, true
		}
		return false, false
	})

	critical := func(check, path string) alert.Finding {
		return alert.Finding{Check: check, Severity: alert.Critical, FilePath: path}
	}
	deep := filepath.Join(docroot, "wp-content", "uploads", "x", "index.php")
	rebuilt := filepath.Join(docroot, "rebuilt.php")
	writeWebshellTestFile(t, rebuilt)
	gone := filepath.Join(docroot, "gone.php")

	tests := []struct {
		name    string
		latest  []alert.Finding
		removed []RemovedFile
		path    string
		want    bool
		removal bool
	}{
		{name: "critical malware finding", latest: []alert.Finding{critical("webshell", deep)}, path: deep, want: true},
		{name: "high severity", latest: []alert.Finding{{Check: "webshell", Severity: alert.High, FilePath: deep}}, path: deep},
		{name: "not a malware check", latest: []alert.Finding{critical("http_request_flood", deep)}, path: deep},
		{name: "not PHP-executable", latest: []alert.Finding{critical("webshell", filepath.Join(docroot, "a.jpg"))}, path: filepath.Join(docroot, "a.jpg")},
		{name: "outside every docroot", latest: []alert.Finding{critical("webshell", filepath.Join(home, "tmp", "a.php"))}, path: filepath.Join(home, "tmp", "a.php")},
		{name: "relative path", latest: []alert.Finding{critical("webshell", "public_html/a.php")}, path: "public_html/a.php"},
		{name: "docroot index", latest: []alert.Finding{critical("webshell", filepath.Join(docroot, "index.php"))}, path: filepath.Join(docroot, "index.php")},
		{name: "nested docroot index", latest: []alert.Finding{critical("webshell", filepath.Join(shop, "index.php"))}, path: filepath.Join(shop, "index.php")},
		{name: "file the release ships", latest: []alert.Finding{critical("webshell", listed)}, path: listed},
		{name: "planted at a core path", latest: []alert.Finding{critical("webshell", planted)}, path: planted, want: true},
		{name: "WordPress root entry file", latest: []alert.Finding{critical("webshell", filepath.Join(docroot, "wp-login.php"))}, path: filepath.Join(docroot, "wp-login.php")},
		{name: "entry file name outside a WordPress root", latest: []alert.Finding{critical("webshell", filepath.Join(docroot, "wp-content", "uploads", "wp-login.php"))}, path: filepath.Join(docroot, "wp-content", "uploads", "wp-login.php"), want: true},
		{name: "quarantined and still absent", removed: []RemovedFile{{Path: gone, Action: "quarantine"}}, path: gone, want: true, removal: true},
		{name: "quarantined path rebuilt clean", removed: []RemovedFile{{Path: rebuilt, Action: "quarantine"}}, path: rebuilt},
		{name: "quarantined path flagged again", latest: []alert.Finding{critical("webshell", rebuilt)}, removed: []RemovedFile{{Path: rebuilt, Action: "quarantine"}}, path: rebuilt, want: true},
		{name: "cleaned file", removed: []RemovedFile{{Path: gone, Action: "clean"}}, path: gone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := webshellFlaggedFiles(tt.latest, tt.removed, docroots)
			removal, ok := got[tt.path]
			if ok != tt.want || removal != tt.removal {
				t.Fatalf("flagged[%s] = (%v, %v), want (%v, %v); set %v", tt.path, removal, ok, tt.removal, tt.want, got)
			}
			if !tt.want && got != nil {
				t.Fatalf("nothing is flagged, want a nil set, got %v", got)
			}
		})
	}
}
