package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/state"
	csmstore "github.com/pidginhost/csm/internal/store"
)

var restoreLedgerT0 = time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC)

// writeRestoreLedger leaves a closed ledger in stateDir whose clock reads
// wall, started live when live is set, beside a firewall state file
// holding fw.
func writeRestoreLedger(t *testing.T, stateDir string, wall time.Time, live bool, fw string) {
	t.Helper()
	reg, err := admission.NewRegistry(func(string) (string, admission.Policy, bool) { return "", admission.Policy{}, false })
	if err != nil {
		t.Fatal(err)
	}
	reg.Seal()
	db, err := csmstore.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := csmstore.OpenAdmissionLedger(db, reg)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Tick(admission.ClockReading{Wall: wall, BootID: "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b", SinceBoot: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if live {
		if err = l.StartLive(admission.LegacyHandover{}); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	writeRestoreFirewallState(t, stateDir, fw)
}

func writeRestoreFirewallState(t *testing.T, stateDir, fw string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(stateDir, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "firewall", "state.json"), []byte(fw), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readRestoreState(t *testing.T, stateDir string) (db, fw []byte) {
	t.Helper()
	db, err := os.ReadFile(filepath.Join(stateDir, "csm.db"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if fw, err = os.ReadFile(filepath.Join(stateDir, "firewall", "state.json")); err != nil {
		t.Fatal(err)
	}
	return db, fw
}

// A restore that would put an older ledger, and the firewall state saved
// beside it, over a ledger that started live is refused unless forced, and
// the refusal leaves the target as it was. A host whose ledger never
// started live, or that has none, takes any archive.
func TestRestoreRefusesALedgerBehindALiveTarget(t *testing.T) {
	later := restoreLedgerT0.Add(time.Hour)
	type side struct {
		at        time.Time
		live, has bool
	}
	for _, tc := range []struct {
		name            string
		archive, target side
		force           bool
		want            string
	}{
		{"target live and archive not", side{restoreLedgerT0, false, true}, side{restoreLedgerT0, true, true}, false, "never started live"},
		{"archive without a database", side{has: false}, side{restoreLedgerT0, true, true}, false, "never started live"},
		{"archive clock behind", side{restoreLedgerT0, true, true}, side{later, true, true}, false, "clock reads 2024-01-02T12:00:00Z, this host's 2024-01-02T13:00:00Z"},
		{"same clock", side{restoreLedgerT0, true, true}, side{restoreLedgerT0, true, true}, false, ""},
		{"archive newer", side{later, true, true}, side{restoreLedgerT0, true, true}, false, ""},
		{"target not live", side{restoreLedgerT0, false, true}, side{later, false, true}, false, ""},
		{"no target database", side{restoreLedgerT0, false, true}, side{has: false}, false, ""},
		{"forced", side{restoreLedgerT0, false, true}, side{later, true, true}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := filepath.Join(t.TempDir(), "state"), filepath.Join(t.TempDir(), "state")
			for _, s := range []struct {
				dir, fw string
				side
			}{{src, "archive", tc.archive}, {dst, "target", tc.target}} {
				if s.has {
					writeRestoreLedger(t, s.dir, s.at, s.live, s.fw)
				} else {
					writeRestoreFirewallState(t, s.dir, s.fw)
				}
			}
			archive := filepath.Join(t.TempDir(), "backup.tar.gz")
			if err := WriteBackupArchive(archive, BackupSources{StateDir: src}); err != nil {
				t.Fatal(err)
			}
			beforeDB, beforeFW := readRestoreState(t, dst)
			err := RestoreBackupArchive(archive, BackupSources{StateDir: dst, Force: tc.force})
			afterDB, afterFW := readRestoreState(t, dst)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("restore refused: %v", err)
				}
				if string(afterFW) != "archive" {
					t.Fatalf("firewall state after restore = %q, want the archive's", afterFW)
				}
				return
			}
			if !errors.Is(err, csmstore.ErrLedgerBehind) || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "--force") {
				t.Fatalf("restore error = %v, want a behind refusal naming %q and --force", err, tc.want)
			}
			if !bytes.Equal(beforeDB, afterDB) || !bytes.Equal(beforeFW, afterFW) {
				t.Fatal("a refused restore changed the target")
			}
		})
	}
}

// Only restore takes --force; backup refuses it as an unknown option.
func TestParseBackupRestoreForce(t *testing.T) {
	for _, args := range [][]string{{"--force", "backup.tar.gz"}, {"backup.tar.gz", "--force"}} {
		path, _, force, err := parseBackupRestoreArgs(args, true)
		if err != nil || path != "backup.tar.gz" || !force {
			t.Errorf("restore %v = (%q, %v, %v), want the archive forced", args, path, force, err)
		}
		if _, _, _, err := parseBackupRestoreArgs(args, false); err == nil || !strings.Contains(err.Error(), "unknown backup/restore option --force") {
			t.Errorf("backup %v error = %v, want --force refused", args, err)
		}
	}
	if _, _, force, err := parseBackupRestoreArgs([]string{"backup.tar.gz"}, true); err != nil || force {
		t.Errorf("restore without --force = (%v, %v)", force, err)
	}
	if _, _, _, err := parseBackupRestoreArgs([]string{"backup.tar.gz", "--force=true"}, true); err == nil {
		t.Error("--force with a value accepted")
	}
}

// csm store import takes --force and lists it in its usage. The child stops
// at the unknown flag after it, before any daemon or config work.
func TestStoreImportAcceptsForce(t *testing.T) {
	if os.Getenv("CSM_TEST_STORE_IMPORT_FORCE") == "1" {
		os.Args = []string{"csm", "store", "import", "backup.csmbak", "--force", "--bogus"}
		runStoreImportCLI()
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreImportAcceptsForce$")
	cmd.Env = append(os.Environ(), "CSM_TEST_STORE_IMPORT_FORCE=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	var exitErr *exec.ExitError
	if err := cmd.Run(); err != nil && !errors.As(err, &exitErr) {
		t.Fatal(err)
	}
	out := stderr.String()
	if code := cmd.ProcessState.ExitCode(); code != 2 || !strings.HasPrefix(out, "csm store import: unknown flag \"--bogus\"\n") || !strings.Contains(out, "[--force]") {
		t.Fatalf("exit %d, stderr %q; want --force accepted and listed in the usage", code, out)
	}
}

// restoreTreeOf is every path under dir with its mode and, for a file, its
// bytes; a missing dir is an empty tree.
func restoreTreeOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		entry := info.Mode().String()
		if info.Mode().IsRegular() {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			entry += ":" + string(data)
		}
		out[rel] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// restoreLedgerPosition opens the ledger in stateDir and reports whether
// it started live and its clock.
func restoreLedgerPosition(t *testing.T, stateDir string) (bool, time.Time) {
	t.Helper()
	reg, err := admission.NewRegistry(func(string) (string, admission.Policy, bool) { return "", admission.Policy{}, false })
	if err != nil {
		t.Fatal(err)
	}
	reg.Seal()
	db, err := csmstore.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	l, err := csmstore.OpenAdmissionLedger(db, reg)
	if err != nil {
		t.Fatal(err)
	}
	clock, err := csmstore.ReadAdmissionClock(db)
	if err != nil {
		t.Fatal(err)
	}
	return l.LiveStarted(), clock.Now()
}

// restoreHost is a host with a config, a drop-in, a learning directory and
// a state directory whose ledger started live an hour after the archives'.
func restoreHost(t *testing.T) BackupSources {
	t.Helper()
	root := t.TempDir()
	dst := BackupSources{
		ConfigPath: filepath.Join(root, "etc", "csm.yaml"), ConfDir: filepath.Join(root, "etc", "conf.d"),
		StateDir: filepath.Join(root, "state"), LearningDir: filepath.Join(root, "learning"),
	}
	for path, body := range map[string]string{
		dst.ConfigPath: "hostname: target\n",
		filepath.Join(dst.ConfDir, "10-local.yaml"):   "hostname: target-dropin\n",
		filepath.Join(dst.LearningDir, "kept"):        "target learning",
		filepath.Join(dst.StateDir, "integrity.json"): "kept state",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeRestoreLedger(t, dst.StateDir, restoreLedgerT0.Add(time.Hour), true, "target")
	return dst
}

// A refused restore writes nothing anywhere: the config, the drop-ins, the
// state directory and the learning directory keep every file, byte and
// mode, and nothing is left staged beside them. An archive without a state
// section replaces no ledger, so it is restored and the live ledger stays.
func TestLedgerRestoreGuardLeavesTargetsUntouched(t *testing.T) {
	archiveOf := func(t *testing.T, state, learning, config bool) string {
		t.Helper()
		root := t.TempDir()
		var src BackupSources
		if state {
			src.StateDir = filepath.Join(root, "state")
			writeRestoreLedger(t, src.StateDir, restoreLedgerT0, false, "archive")
		}
		if learning {
			src.LearningDir = filepath.Join(root, "learning")
			writeLearningTree(t, src.LearningDir, "csmfz_archive")
		}
		if config {
			src.ConfigPath = filepath.Join(root, "csm.yaml")
			if err := os.WriteFile(src.ConfigPath, []byte("hostname: archive\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		archive := filepath.Join(t.TempDir(), "backup.tar.gz")
		if err := WriteBackupArchive(archive, src); err != nil {
			t.Fatal(err)
		}
		return archive
	}
	for _, tc := range []struct {
		name                    string
		state, learning, config bool
	}{
		{"state", true, false, false},
		{"state and learning", true, true, false},
		{"state and config", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := restoreHost(t)
			root := filepath.Dir(dst.StateDir)
			before := restoreTreeOf(t, root)
			err := RestoreBackupArchive(archiveOf(t, tc.state, tc.learning, tc.config), dst)
			if !errors.Is(err, csmstore.ErrLedgerBehind) {
				t.Fatalf("restore error = %v, want a behind refusal", err)
			}
			after := restoreTreeOf(t, root)
			if len(before) != len(after) {
				t.Fatalf("a refused restore left %d paths, had %d: %v", len(after), len(before), after)
			}
			for path, entry := range before {
				if after[path] != entry {
					t.Fatalf("a refused restore changed %s", path)
				}
			}
		})
	}
	t.Run("config only", func(t *testing.T) {
		dst := restoreHost(t)
		if err := RestoreBackupArchive(archiveOf(t, false, false, true), dst); err != nil {
			t.Fatalf("a config-only restore was refused: %v", err)
		}
		if got, err := os.ReadFile(dst.ConfigPath); err != nil || string(got) != "hostname: archive\n" {
			t.Fatalf("config after the restore = %q (%v)", got, err)
		}
		if live, clock := restoreLedgerPosition(t, dst.StateDir); !live || !clock.Equal(restoreLedgerT0.Add(time.Hour)) {
			t.Fatalf("ledger after a config-only restore: live %t, clock %v", live, clock)
		}
	})
	t.Run("learning only", func(t *testing.T) {
		dst := restoreHost(t)
		if err := RestoreBackupArchive(archiveOf(t, false, true, false), dst); err != nil {
			t.Fatalf("a learning-only restore was refused: %v", err)
		}
		if live, clock := restoreLedgerPosition(t, dst.StateDir); !live || !clock.Equal(restoreLedgerT0.Add(time.Hour)) {
			t.Fatalf("ledger after a learning-only restore: live %t, clock %v", live, clock)
		}
		if _, fw := readRestoreState(t, dst.StateDir); string(fw) != "target" {
			t.Fatalf("firewall state after a learning-only restore = %q", fw)
		}
	})
}

// The comparison runs under the stopped-daemon state lock and releases it
// whether the restore is refused or goes ahead.
func TestLedgerRestoreGuardUnderStateLock(t *testing.T) {
	saved := controlSocketPath
	controlSocketPath = shortSockPath(t)
	defer func() { controlSocketPath = saved }()
	for _, force := range []bool{false, true} {
		dst := restoreHost(t)
		src := filepath.Join(t.TempDir(), "state")
		writeRestoreLedger(t, src, restoreLedgerT0, false, "archive")
		archive := filepath.Join(t.TempDir(), "backup.tar.gz")
		if err := WriteBackupArchive(archive, BackupSources{StateDir: src}); err != nil {
			t.Fatal(err)
		}
		dst.Force = force
		err := restoreBackupArchiveGuarded(archive, dst)
		if force != (err == nil) || (!force && !errors.Is(err, csmstore.ErrLedgerBehind)) {
			t.Fatalf("force %t: restore = %v", force, err)
		}
		lock, lockErr := state.AcquireLock(dst.StateDir)
		if lockErr != nil {
			t.Fatalf("force %t: the state lock was not released: %v", force, lockErr)
		}
		lock.Release()
		live, clock := restoreLedgerPosition(t, dst.StateDir)
		if force == live || force != clock.Equal(restoreLedgerT0) {
			t.Fatalf("force %t: ledger live %t, clock %v", force, live, clock)
		}
	}
}

// csm restore hands --force to the restore: without it the command exits
// with the refusal and leaves the host alone, with it the archive lands.
func TestRestoreCommandPassesForce(t *testing.T) {
	if os.Getenv("CSM_TEST_RESTORE_ARGS") != "" {
		controlSocketPath = os.Getenv("CSM_TEST_RESTORE_SOCKET")
		os.Args = append([]string{"csm", "restore"}, strings.Split(os.Getenv("CSM_TEST_RESTORE_ARGS"), "\n")...)
		runRestore()
		os.Exit(0)
	}
	for _, force := range []bool{false, true} {
		root := t.TempDir()
		stateDir, confDir := filepath.Join(root, "state"), filepath.Join(root, "conf.d")
		writeRestoreLedger(t, stateDir, restoreLedgerT0.Add(time.Hour), true, "target")
		if err := os.MkdirAll(confDir, 0o700); err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(root, "csm.yaml")
		if err := os.WriteFile(cfgPath, []byte("state_path: "+stateDir+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(t.TempDir(), "state")
		writeRestoreLedger(t, src, restoreLedgerT0, false, "archive")
		archive := filepath.Join(t.TempDir(), "backup.tar.gz")
		if err := WriteBackupArchive(archive, BackupSources{StateDir: src}); err != nil {
			t.Fatal(err)
		}
		args := []string{archive, "--config", cfgPath, "--config-dir", confDir}
		if force {
			args = append(args, "--force")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestRestoreCommandPassesForce$")
		cmd.Env = append(os.Environ(), "CSM_TEST_RESTORE_ARGS="+strings.Join(args, "\n"), "CSM_TEST_RESTORE_SOCKET="+shortSockPath(t))
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		var exitErr *exec.ExitError
		if err := cmd.Run(); err != nil && !errors.As(err, &exitErr) {
			t.Fatal(err)
		}
		_, fw := readRestoreState(t, stateDir)
		code, out := cmd.ProcessState.ExitCode(), stderr.String()
		if force && (code != 0 || string(fw) != "archive") {
			t.Fatalf("forced restore: exit %d, firewall state %q, stderr %q", code, fw, out)
		}
		if !force && (code != 1 || string(fw) != "target" || !strings.Contains(out, "never started live") || !strings.Contains(out, "--force")) {
			t.Fatalf("restore without --force: exit %d, firewall state %q, stderr %q", code, fw, out)
		}
	}
}
