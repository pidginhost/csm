package forensic

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func minimalSnapshot(out string) Snapshot {
	return Snapshot{
		Account:   "alice",
		OutPath:   out,
		Timestamp: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		Sources: Sources{
			DiscoverTargets: func(string) []SchemaTarget { return nil },
			ListRecentFiles: func(_ string, _ time.Time) ([]byte, error) { return []byte("none\n"), nil },
		},
	}
}

// The archive and its sidecar were written with os.WriteFile, which follows
// a symlink already sitting at the destination. A compromised account with
// its own code execution pre-creates /tmp/acct.tar.gz -> another tenant's
// file (outside its own home, so the out-path guard passes) and root
// overwrites that file with the tar stream. The archive is written as a new
// file only: an existing path, symlink or not, is refused untouched.
func TestSnapshot_Write_RefusesExistingOrSymlinkedOutPath(t *testing.T) {
	tmp := t.TempDir()
	victim := filepath.Join(tmp, "victim.php")
	if err := os.WriteFile(victim, []byte("<?php // other tenant"), 0o644); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(tmp, "snap.tar.gz")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatal(err)
	}
	if _, _, err := minimalSnapshot(planted).Write(); err == nil {
		t.Fatal("archive written through a planted symlink")
	}
	if got, _ := os.ReadFile(victim); string(got) != "<?php // other tenant" {
		t.Fatalf("symlink target overwritten: %q", got)
	}
	if _, err := os.Lstat(planted + ".sha256"); !os.IsNotExist(err) {
		t.Fatalf("sidecar created next to a refused archive: %v", err)
	}

	existing := filepath.Join(tmp, "existing.tar.gz")
	if err := os.WriteFile(existing, []byte("previous evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := minimalSnapshot(existing).Write(); err == nil {
		t.Fatal("existing archive overwritten")
	}
	if got, _ := os.ReadFile(existing); string(got) != "previous evidence" {
		t.Fatalf("existing archive clobbered: %q", got)
	}
}

// The archive is created before its checksum sidecar. If the sidecar path is
// already occupied, returning an error while leaving a complete-looking
// archive behind gives an operator evidence with no integrity record and
// prevents a clean retry at the same path.
func TestSnapshot_Write_RemovesArchiveWhenSidecarCreationFails(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "snap.tar.gz")
	sidecar := out + ".sha256"
	if err := os.WriteFile(sidecar, []byte("existing integrity record"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := minimalSnapshot(out).Write(); err == nil {
		t.Fatal("snapshot succeeded despite an occupied sidecar path")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("archive left behind after sidecar failure: %v", err)
	}
	if got, err := os.ReadFile(sidecar); err != nil || string(got) != "existing integrity record" {
		t.Fatalf("existing sidecar changed: data=%q err=%v", got, err)
	}
}
