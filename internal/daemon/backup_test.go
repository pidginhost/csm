package daemon

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
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

	last := d.runBackupIfDue(d.currentCfg(), backupTestNow, time.Time{})
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
	if next := d.runBackupIfDue(d.currentCfg(), backupTestNow.Add(time.Hour), time.Time{}); !next.Equal(backupTestNow) {
		t.Fatalf("restart inside the schedule returned %v, want the newest archive time", next)
	}
	if got := dirNames(t, plan.Dir); !slices.Equal(got, want) {
		t.Fatalf("exported again inside the schedule: %v", got)
	}

	second := backupTestNow.Add(24 * time.Hour)
	d.runBackupIfDue(d.currentCfg(), second, last)
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

			last := d.runBackupIfDue(d.currentCfg(), backupTestNow, time.Time{})
			if !last.Equal(backupTestNow) {
				t.Fatalf("returned %v, want the attempt time so the retry waits a schedule", last)
			}
			f := drainAlert(t, d, time.Second)
			if f.Check != "backup_export_failed" || f.Severity != alert.Warning || !strings.Contains(f.Message, tc.want) {
				t.Fatalf("finding = %s/%v %q, want backup_export_failed Warning naming %q", f.Check, f.Severity, f.Message, tc.want)
			}
			// The retry waits a schedule instead of warning every tick.
			d.runBackupIfDue(d.currentCfg(), backupTestNow.Add(time.Hour), last)
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
	last := d.runBackupIfDue(d.currentCfg(), backupTestNow, time.Time{})
	if names := dirNames(t, plan.Dir); len(names) != 0 {
		t.Fatalf("disabled block exported: %v", names)
	}

	config.SetActive(cfg)
	d.runBackupIfDue(d.currentCfg(), backupTestNow, last)
	if _, err := os.Stat(filepath.Join(plan.Dir, plan.ArchiveName(backupTestNow))); err != nil {
		t.Fatalf("enabling the block did not export: %v", err)
	}
	assertNoAlert(t, d)
}

func TestScheduledBackupRecoversInterruptedExport(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	name := plan.ArchiveName(backupTestNow)
	stage := filepath.Join(plan.Dir, ".csm-b-"+name)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	writeBackupFixture(t, stage, name, name+".sha256", "csm-export-bbolt-123.snap", ".session-free-456")
	if err := os.Link(filepath.Join(stage, name+".sha256"), filepath.Join(plan.Dir, name+".sha256")); err != nil {
		t.Fatal(err)
	}
	d.runBackupIfDue(d.currentCfg(), backupTestNow, time.Time{})
	assertNoAlert(t, d)
	if got := dirNames(t, plan.Dir); !slices.Equal(got, []string{name, name + ".sha256"}) {
		t.Fatalf("after recovery: %v", got)
	}
	data, err := os.ReadFile(filepath.Join(plan.Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(filepath.Join(plan.Dir, name+".sha256"))
	if err != nil || string(sum) != fmt.Sprintf("%x  %s\n", sha256.Sum256(data), name) {
		t.Fatalf("invalid companion for recovered archive: %v", err)
	}
}

func TestScheduledBackupPublicationFailurePreservesFiles(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	name := plan.ArchiveName(backupTestNow)
	if err := os.MkdirAll(plan.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	expired := plan.ArchiveName(backupTestNow.Add(-20 * 24 * time.Hour))
	writeBackupFixture(t, plan.Dir, name+".sha256", expired)
	d.runBackupIfDue(d.currentCfg(), backupTestNow, time.Time{})
	if f := drainAlert(t, d, time.Second); f.Check != "backup_export_failed" {
		t.Fatalf("finding = %s", f.Check)
	}
	if files := dirNames(t, plan.Dir); !slices.Equal(files, []string{expired, name + ".sha256"}) {
		t.Fatalf("failed publication left %v", files)
	}
	data, err := os.ReadFile(filepath.Join(plan.Dir, name+".sha256"))
	if err != nil || string(data) != "fixture" {
		t.Fatalf("existing companion changed: %v", err)
	}
}

func TestScheduledBackupClockMovesBack(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	d.runBackupIfDue(d.currentCfg(), backupTestNow, backupTestNow.Add(48*time.Hour))
	plan := backupPlan(t, cfg)
	if _, err := os.Stat(filepath.Join(plan.Dir, plan.ArchiveName(backupTestNow))); err != nil {
		t.Fatal(err)
	}
}

func TestScheduledBackupRejectsAliasedSource(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(plan.Root, alias); err != nil {
		t.Fatal(err)
	}
	cfg.Signatures.RulesDir = filepath.Join(alias, filepath.Base(plan.Dir))
	d.runBackupIfDue(d.currentCfg(), backupTestNow, time.Time{})
	if f := drainAlert(t, d, time.Second); !strings.Contains(f.Message, "rules_dir") {
		t.Fatalf("expected overlapping rules_dir finding, got %s", f.Message)
	}
	if len(dirNames(t, plan.Dir)) != 0 {
		t.Fatal("export wrote inside its rules source")
	}
}

func TestScheduledBackupReloadsDestination(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	var timer backupTimer
	timer.tick(d, backupTestNow)
	next := *cfg
	next.Backup.DestinationDir += "-new"
	config.SetActive(&next)
	at := backupTestNow.Add(time.Minute)
	timer.tick(d, at)
	plan := backupPlan(t, &next)
	if _, err := os.Stat(filepath.Join(plan.Dir, plan.ArchiveName(at))); err != nil {
		t.Fatal(err)
	}
}

func TestScheduledBackupRecoversLooseSnapshot(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	if err := os.MkdirAll(plan.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	const snap = "csm-export-bbolt-1024.snap"
	const foreign = "csm-export-bbolt-other.snap"
	incomplete := plan.ArchiveName(backupTestNow.Add(-time.Minute))
	writeBackupFixture(t, plan.Dir, snap, foreign, incomplete)
	d.runBackupIfDue(d.currentCfg(), backupTestNow, time.Time{})
	assertNoAlert(t, d)
	if _, err := os.Stat(filepath.Join(plan.Dir, snap)); !os.IsNotExist(err) {
		t.Fatalf("abandoned snapshot remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(plan.Dir, foreign)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(plan.Dir, plan.ArchiveName(backupTestNow))); err != nil {
		t.Fatalf("incomplete archive suppressed the new export: %v", err)
	}
}

func TestScheduledBackupSkipsNonRegularState(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	foreign := filepath.Join(t.TempDir(), "outside")
	writeBackupFixture(t, filepath.Dir(foreign), "outside")
	if err := os.Symlink(foreign, filepath.Join(cfg.StatePath, "link")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cfg.StatePath)
	listener, err := net.Listen("unix", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	d.runBackupIfDue(d.currentCfg(), backupTestNow, time.Time{})
	assertNoAlert(t, d)
	plan := backupPlan(t, cfg)
	path := filepath.Join(plan.Dir, plan.ArchiveName(backupTestNow))
	if len(archiveEntry(t, path, "bbolt.snapshot")) == 0 {
		t.Fatal("empty snapshot")
	}
}

func TestScheduledBackupPreservesExpiredCompanionDirectory(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	expired := plan.ArchiveName(backupTestNow.Add(-30 * 24 * time.Hour))
	foreignDir := filepath.Join(plan.Dir, expired+".sha256")
	if err := os.MkdirAll(foreignDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeBackupFixture(t, plan.Dir, expired)
	d.runBackupIfDue(cfg, backupTestNow, time.Time{})
	assertNoAlert(t, d)
	if _, err := os.Stat(filepath.Join(plan.Dir, expired)); !os.IsNotExist(err) {
		t.Fatalf("expired archive remains: %v", err)
	}
	if info, err := os.Stat(foreignDir); err != nil || !info.IsDir() {
		t.Fatalf("pruning removed an unrelated directory: %v", err)
	}
}

func TestScheduledBackupKeepsPartialArchivePrivate(t *testing.T) {
	_, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	if err := os.MkdirAll(plan.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	name := plan.ArchiveName(backupTestNow)
	final := filepath.Join(plan.Dir, name)
	stopped := errors.New("export interrupted")
	_, err := publishBackup(cfg, final, func(_ *config.Config, path string) (*store.ExportResult, error) {
		writeBackupFixture(t, filepath.Dir(path), filepath.Base(path))
		if _, err := os.Stat(final); !os.IsNotExist(err) {
			t.Fatalf("archive visible before export finished: %v", err)
		}
		return nil, stopped
	})
	if !errors.Is(err, stopped) || len(dirNames(t, plan.Dir)) != 0 {
		t.Fatalf("interrupted export left %v, error %v", dirNames(t, plan.Dir), err)
	}
}

func TestDirectExportSnapshotSurvivesScheduledCleanup(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	if err := os.MkdirAll(plan.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	locked, err := lockDirectExport(plan.Dir)
	if err != nil || locked == nil {
		t.Fatalf("direct export could not lock its destination: %v", err)
	}
	defer locked.Close()
	const snap = "csm-export-bbolt-12345.snap"
	writeBackupFixture(t, plan.Dir, snap)
	if last := d.runBackupIfDue(cfg, backupTestNow, time.Time{}); !last.IsZero() {
		t.Fatalf("busy destination advanced the schedule: %v", last)
	}
	if files := dirNames(t, plan.Dir); !slices.Equal(files, []string{snap}) {
		t.Fatalf("scheduled export interfered with direct export: %v", files)
	}
	assertNoAlert(t, d)
}

func TestScheduledBackupLeavesForeignStageDirectory(t *testing.T) {
	d, cfg := newBackupTestDaemon(t)
	plan := backupPlan(t, cfg)
	foreign := filepath.Join(plan.Dir, ".csm-b-note-20260101T000000Z")
	if err := os.MkdirAll(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	writeBackupFixture(t, foreign, "notes.txt")
	d.runBackupIfDue(cfg, backupTestNow, time.Time{})
	assertNoAlert(t, d)
	if files := dirNames(t, foreign); !slices.Equal(files, []string{"notes.txt"}) {
		t.Fatalf("unrelated directory changed: %v", files)
	}
	if _, err := os.Stat(filepath.Join(plan.Dir, plan.ArchiveName(backupTestNow))); err != nil {
		t.Fatal(err)
	}
}
