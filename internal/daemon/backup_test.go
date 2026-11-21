package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

var backupTestNow = time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC)

// newBackupTestDaemon publishes an enabled backup block whose root and
// destination live in temp directories, with a store to export.
func newBackupTestDaemon(t *testing.T) (*Daemon, *config.Config) {
	t.Helper()
	stateDir := t.TempDir()
	_, restore := openTestBoltStore(t, stateDir)
	t.Cleanup(restore)
	st, err := state.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	root := t.TempDir()
	if err = os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.SetBackupRoot(root))
	cfg, err := config.LoadBytes([]byte("backup:\n  enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = stateDir
	cfg.Signatures.RulesDir = ""
	cfg.Backup.DestinationDir = filepath.Join(root, "backups")

	prev := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prev) })
	return New(cfg, st, nil, ""), cfg
}

func backupPlan(t *testing.T, cfg *config.Config) config.BackupPlan {
	t.Helper()
	plan, err := config.ParseBackup(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func writeBackupFixture(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertNoAlert(t *testing.T, d *Daemon) {
	t.Helper()
	select {
	case f := <-d.alertCh:
		t.Fatalf("unexpected finding %s: %s", f.Check, f.Message)
	default:
	}
}

func TestScheduledBackupRunsOnScheduleAndPrunes(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	if err := os.MkdirAll(plan.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	expired := plan.ArchiveName(backupTestNow.Add(-15 * 24 * time.Hour))
	kept := plan.ArchiveName(backupTestNow.Add(-2 * 24 * time.Hour))
	// Left by a clock that ran ahead; it must not hold off the export.
	future := plan.ArchiveName(backupTestNow.Add(2 * 24 * time.Hour))
	foreign := []string{"csm-notadate.csmbak", "notes.txt", "other-20261001T000000Z.csmbak", expired + ".old"}
	writeBackupFixture(t, plan.Dir, append([]string{expired, expired + ".sha256", kept, future}, foreign...)...)

	last := d.runBackupIfDue(backupTestNow, time.Time{})
	if !last.Equal(backupTestNow) {
		t.Fatalf("returned %v, want the run time", last)
	}
	assertNoAlert(t, d)
	first := plan.ArchiveName(backupTestNow)
	want := append([]string{first, first + ".sha256", kept, future}, foreign...)
	got := dirNames(t, plan.Dir)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("after the first run: %v, want %v", got, want)
	}
	if len(archiveEntry(t, filepath.Join(plan.Dir, first), "bbolt.snapshot")) == 0 {
		t.Fatal("scheduled archive carries an empty store snapshot")
	}

	// A restart forgets the last attempt; the archive on disk still holds
	// the schedule.
	if next := d.runBackupIfDue(backupTestNow.Add(time.Hour), time.Time{}); !next.Equal(backupTestNow) {
		t.Fatalf("restart inside the schedule returned %v, want the newest archive time", next)
	}
	if got := dirNames(t, plan.Dir); !slices.Equal(got, want) {
		t.Fatalf("exported again inside the schedule: %v", got)
	}

	second := backupTestNow.Add(24 * time.Hour)
	d.runBackupIfDue(second, last)
	if _, err := os.Stat(filepath.Join(plan.Dir, plan.ArchiveName(second))); err != nil {
		t.Fatalf("no export once the schedule passed: %v", err)
	}
}

func TestScheduledBackupFailureRaisesWarning(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{"destination writable by others", func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		}, "writable by group or others"},
		{"destination is a symlink", func(t *testing.T, dir string) {
			target := filepath.Join(filepath.Dir(dir), "real")
			if err := os.Rename(dir, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
		}, "symlink"},
		{"store unavailable", func(t *testing.T, _ string) {
			prev := store.Global()
			store.SetGlobal(nil)
			t.Cleanup(func() { store.SetGlobal(prev) })
		}, "bbolt store not available"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, cfg := newBackupTestDaemon(t)
			plan := backupPlan(t, cfg)
			if err := os.MkdirAll(plan.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			expired := plan.ArchiveName(backupTestNow.Add(-30 * 24 * time.Hour))
			writeBackupFixture(t, plan.Dir, expired)
			tc.setup(t, plan.Dir)

			last := d.runBackupIfDue(backupTestNow, time.Time{})
			if !last.Equal(backupTestNow) {
				t.Fatalf("returned %v, want the attempt time so the retry waits a schedule", last)
			}
			f := drainAlert(t, d, time.Second)
			if f.Check != "backup_export_failed" || f.Severity != alert.Warning || !strings.Contains(f.Message, tc.want) {
				t.Fatalf("finding = %s/%v %q, want backup_export_failed Warning naming %q", f.Check, f.Severity, f.Message, tc.want)
			}
			// The retry waits a schedule instead of warning every tick.
			d.runBackupIfDue(backupTestNow.Add(time.Hour), last)
			assertNoAlert(t, d)
			if _, err := os.Lstat(filepath.Join(plan.Dir, plan.ArchiveName(backupTestNow))); !os.IsNotExist(err) {
				t.Fatalf("failed run left an archive: %v", err)
			}
			// Without a new archive, the old one is the only backup left.
			if _, err := os.Stat(filepath.Join(plan.Dir, expired)); err != nil {
				t.Fatalf("failed run pruned the last archive: %v", err)
			}
		})
	}
}

// A reload publishes the new config; the next tick acts on it.
func TestScheduledBackupFollowsLiveConfig(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)

	off, err := config.LoadBytes([]byte("{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	off.StatePath = cfg.StatePath
	config.SetActive(off)
	last := d.runBackupIfDue(backupTestNow, time.Time{})
	if names := dirNames(t, plan.Dir); len(names) != 0 {
		t.Fatalf("disabled block exported: %v", names)
	}

	config.SetActive(cfg)
	d.runBackupIfDue(backupTestNow, last)
	if _, err := os.Stat(filepath.Join(plan.Dir, plan.ArchiveName(backupTestNow))); err != nil {
		t.Fatalf("enabling the block did not export: %v", err)
	}
	assertNoAlert(t, d)
}
