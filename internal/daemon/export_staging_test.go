package daemon

import (
	"path/filepath"
	"testing"
)

// A staged export lands under the daemon's own state directory, the one
// place the sandbox guarantees writable, named after the operator's
// requested file so the CLI can move it into place.
func TestExportStagingPathUnderStateDir(t *testing.T) {
	got := exportStagingPath("/var/lib/csm/state", "/var/backups/csm-2026-09-02.csmbak")
	want := filepath.Join("/var/lib/csm/state", "exports", "csm-2026-09-02.csmbak")
	if got != want {
		t.Fatalf("exportStagingPath = %q, want %q", got, want)
	}
}
