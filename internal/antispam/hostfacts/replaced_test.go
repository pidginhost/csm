package hostfacts

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

// Only regular files with a backup name count, in name order. A link or a
// directory under a backup name is never followed, and other names are
// skipped.
func TestReplacedListsRegularBackups(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	write := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("operator\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	backup := write(antispam.BackupName("/etc/rspamd/local.d/milter_headers.conf", at))
	earlier := write(antispam.BackupName("/etc/rspamd/local.d/actions.conf", at.Add(-time.Hour)))
	write("notes.txt")
	if err := os.Symlink(backup, filepath.Join(dir, antispam.BackupName("/etc/rspamd/local.d/actions.conf", at))); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, antispam.BackupName("/etc/rspamd/local.d/greylist.conf", at)), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := Replaced(dir)
	want := []antispam.Replacement{
		{Path: "/etc/rspamd/local.d/actions.conf", Backup: earlier},
		{Path: "/etc/rspamd/local.d/milter_headers.conf", Backup: backup},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Replaced = %+v, %v; want %+v", got, err, want)
	}
	if got, err := Replaced(filepath.Join(dir, "absent")); err != nil || got != nil {
		t.Fatalf("missing directory: %+v, %v", got, err)
	}
	if _, err := Replaced(backup); err == nil {
		t.Fatal("a file in place of the directory was not an error")
	}
}
