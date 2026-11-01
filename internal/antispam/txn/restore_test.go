package txn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/safepath"
)

func restorePass(h *Host, dry bool) antispam.Result {
	if !dry {
		return h.Remove()
	}
	s := enforce()
	s.DryRun = true
	return h.Apply(s)
}

func restoreFixture(t *testing.T) (*fakeHost, string) {
	t.Helper()
	f := postfixFake(t)
	writeTest(t, f.root+actionsPath, foreignActions, 0o640)
	wantOK(t, f.host().Apply(enforce()))
	f.reset()
	return f, filepath.Join(f.root+antispam.ReplacedDir, antispam.BackupName(actionsPath, f.start))
}

func TestPostfixRestoreRejectsUnsafeCopy(t *testing.T) {
	for _, dry := range []bool{false, true} {
		kinds := []string{"writable", "symlink", "symlink directory"}
		if os.Geteuid() == 0 {
			kinds = append(kinds, "foreign owner")
		}
		for _, kind := range kinds {
			t.Run(kind+map[bool]string{true: "/dry", false: "/remove"}[dry], func(t *testing.T) {
				f, backup := restoreFixture(t)
				before := f.file(actionsPath)
				switch kind {
				case "writable":
					if err := os.Chmod(backup, 0o666); err != nil {
						t.Fatal(err)
					}
				case "foreign owner":
					if err := os.Chown(backup, 65534, -1); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					moved := backup + ".original"
					if err := os.Rename(backup, moved); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(moved, backup); err != nil {
						t.Fatal(err)
					}
				case "symlink directory":
					dir := filepath.Dir(backup)
					if err := os.Rename(dir, dir+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(t.TempDir(), dir); err != nil {
						t.Fatal(err)
					}
				}
				r := restorePass(f.host(), dry)
				if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone {
					t.Fatalf("unsafe copy accepted: %+v", r)
				}
				if f.file(actionsPath) != before || f.count("systemctl reload") != 0 {
					t.Fatal("unsafe restore changed the active configuration")
				}
			})
		}
	}
}

func TestPostfixRestoreRollbackKeepsCopyInPinnedDirectory(t *testing.T) {
	f, backup := restoreFixture(t)
	h := f.host()
	replace := h.replace
	dir := filepath.Dir(backup)
	outside := t.TempDir()
	h.replace = func(p string, want, next fileState) error {
		if p == f.root+antispam.RecordPath && !next.exists {
			if err := os.Rename(dir, dir+".original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, dir); err != nil {
				t.Fatal(err)
			}
			return errConflict
		}
		return replace(p, want, next)
	}
	r := h.Remove()
	if r.OK || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("changed backup directory was not reported: %+v", r)
	}
	got, err := os.ReadFile(filepath.Join(dir+".original", filepath.Base(backup)))
	if err != nil || string(got) != foreignActions {
		t.Fatalf("rollback lost the consumed copy: %v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rollback wrote through the backup symlink: %v", err)
	}
}

// A rollback deadline must not strand consumed backups only in memory.
// A later pass can overwrite the restored operator files on disk.
func TestPostfixRestoreRollbackPreservesCopyAfterDeadline(t *testing.T) {
	f, backup := restoreFixture(t)
	h := f.host()
	tx := h.begin()
	defer tx.cancel()
	changes, err := plan(h.targets(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.restoreCopies(changes, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if err = tx.write(c); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.consumeRestored(); err != nil {
		t.Fatal(err)
	}
	tx.start = time.Now().Add(-totalBudget)
	state, err := tx.rollback()
	if state != antispam.RollbackFailed || err == nil {
		t.Fatalf("expired rollback reported %s, %v", state, err)
	}
	got, err := os.ReadFile(backup)
	if err != nil || string(got) != foreignActions {
		t.Fatalf("expired rollback lost the consumed backup: %v", err)
	}
}

func TestPostfixReplacementUsesPinnedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	p := filepath.Join(dir, "actions.conf")
	writeTest(t, p, "before", 0o640)
	target, err := safepath.OpenTarget("/", strings.TrimPrefix(p, "/"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	outside := t.TempDir()
	writeTest(t, filepath.Join(outside, "actions.conf"), "before", 0o640)
	if err = os.Rename(dir, dir+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	err = replacePinned(target, fileState{exists: true, content: "before"}, fileState{exists: true, content: "after"})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		filepath.Join(dir+".original", "actions.conf"): "after",
		filepath.Join(outside, "actions.conf"):         "before",
	} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("pinned write escaped its directory: %v", err)
		}
	}
	if err := target.Check(); err == nil {
		t.Fatal("renamed parent accepted as a completed write")
	}
}

func TestPostfixRestoreKeepsChangedCopy(t *testing.T) {
	for _, dry := range []bool{false, true} {
		f, backup := restoreFixture(t)
		before := f.file(actionsPath)
		changed := "reject = 90;\n"
		f.onCall = func(line string) {
			if line == "systemctl reload rspamd.service" {
				writeTest(t, backup, changed, 0o600)
			}
		}
		r := restorePass(f.host(), dry)
		if r.OK || r.FailedStep != StepComplete || r.Rollback != antispam.RollbackVerified {
			t.Fatalf("dry=%t: changed copy accepted: %+v", dry, r)
		}
		got, err := os.ReadFile(backup)
		if err != nil || string(got) != changed || f.file(actionsPath) != before {
			t.Fatalf("dry=%t: backup or active configuration lost: %v", dry, err)
		}
	}
}

func TestPostfixRestorePinsDestinationMode(t *testing.T) {
	for _, dry := range []bool{false, true} {
		f, _ := restoreFixture(t)
		h := f.host()
		replace := h.replace
		h.replace = func(p string, want, next fileState) error {
			if p == f.root+antispam.RecordPath && next.content == string(antispam.EncodeRecord("")) {
				if err := os.Chmod(f.root+actionsPath, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			return replace(p, want, next)
		}
		wantOK(t, restorePass(h, dry))
		wantMode(t, f.root+actionsPath, 0o640, os.Getgid())
	}
}

func TestPostfixRestoreRefusesLoosenedTarget(t *testing.T) {
	for _, dry := range []bool{false, true} {
		f, backup := restoreFixture(t)
		before := f.file(actionsPath)
		if err := os.Chmod(f.root+actionsPath, 0o666); err != nil {
			t.Fatal(err)
		}
		r := restorePass(f.host(), dry)
		if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone {
			t.Fatalf("dry=%t: unsafe restore accepted: %+v", dry, r)
		}
		got, err := os.ReadFile(backup)
		if err != nil || string(got) != foreignActions || f.file(actionsPath) != before || f.count("systemctl reload") != 0 {
			t.Fatalf("dry=%t: private backup published or lost: %v", dry, err)
		}
	}
}

// Replacing a checked parent with a symlink must never redirect the root
// worker's write, including a write later undone by rollback.
func TestPostfixRestoreRejectsChangedParent(t *testing.T) {
	for _, dry := range []bool{false, true} {
		f, _ := restoreFixture(t)
		h := f.host()
		replace := h.replace
		outside := t.TempDir()
		before := f.file(actionsPath)
		writeTest(t, filepath.Join(outside, "actions.conf"), before, 0o640)
		touched := false
		h.replace = func(p string, want, next fileState) error {
			if p == f.root+antispam.RecordPath && next.content == string(antispam.EncodeRecord("")) {
				dir := f.root + antispam.RspamdLocalDir
				if err := os.Rename(dir, dir+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, dir); err != nil {
					t.Fatal(err)
				}
			}
			err := replace(p, want, next)
			if strings.HasPrefix(p, f.root+antispam.RspamdLocalDir+"/") && err == nil {
				touched = true
			}
			return err
		}
		r := restorePass(h, dry)
		if r.OK || touched {
			t.Fatalf("dry=%t: redirected write=%t, result=%+v", dry, touched, r)
		}
		got, err := os.ReadFile(filepath.Join(outside, "actions.conf"))
		if err != nil || string(got) != before {
			t.Fatalf("outside file changed: %v", err)
		}
	}
}
