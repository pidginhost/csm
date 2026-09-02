package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A staged export lands under the daemon's own state directory, the one
// place the sandbox guarantees writable, named after the operator's
// requested file so the CLI can move it into place.
func TestPrepareExportStagingPathIsPrivateAndUnique(t *testing.T) {
	statePath := t.TempDir()
	exportDir := filepath.Join(statePath, "exports")
	if err := os.Mkdir(exportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	first, err := prepareExportStagingPath(statePath, "/var/backups/csm-2026-09-02.csmbak", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepareExportStagingPath(statePath, "/var/backups/csm-2026-09-02.csmbak", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("concurrent exports reused the same staging path")
	}
	for _, got := range []string{first, second} {
		if filepath.Base(got) != "csm-2026-09-02.csmbak" || !strings.HasPrefix(got, exportDir+string(filepath.Separator)) {
			t.Fatalf("staging path = %q, want private path under %q with final basename", got, exportDir)
		}
	}
	info, err := os.Stat(exportDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("export directory mode = %o, want 700", info.Mode().Perm())
	}
}

func TestPrepareExportStagingPathRemovesStaleOrphan(t *testing.T) {
	statePath := t.TempDir()
	exportDir := filepath.Join(statePath, "exports")
	staleDir := filepath.Join(exportDir, "export-stale")
	if err := os.MkdirAll(staleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-exportStagingMaxAge - time.Hour)
	if err := os.Chtimes(staleDir, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareExportStagingPath(statePath, "/tmp/new.csmbak", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Fatalf("stale staged export not removed: %v", err)
	}
}

func TestPrepareExportStagingPathRejectsParentBasename(t *testing.T) {
	statePath := t.TempDir()
	if _, err := prepareExportStagingPath(statePath, "..", time.Now()); err == nil {
		t.Fatal("parent basename accepted as an export staging path")
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state directory was damaged: %v", err)
	}
}
