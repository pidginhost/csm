package txn

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

// foreignActions is an operator's own actions.conf at CSM's core path.
const foreignActions = "actions { reject = 70; }\n"

var actionsPath = antispam.RspamdLocalDir + "/actions.conf"

// replaced returns each backup by the target it was taken from. Every entry
// must be a regular 0600 file with a backup name, so a leftover temporary
// file fails the test.
func (f *fakeHost) replaced() map[string]string {
	f.t.Helper()
	entries, err := os.ReadDir(f.root + antispam.ReplacedDir)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}
	}
	if err != nil {
		f.t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		target, ok := antispam.ParseBackupName(e.Name())
		if !ok {
			f.t.Fatalf("%s is not a backup name", e.Name())
		}
		info, err := e.Info()
		if err != nil {
			f.t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			f.t.Fatalf("backup %s has mode %v, want a regular 0600 file", e.Name(), info.Mode())
		}
		out[target] = f.file(antispam.ReplacedDir + "/" + e.Name())
	}
	return out
}

func wantBackups(t *testing.T, f *fakeHost, want map[string]string) {
	t.Helper()
	got := f.replaced()
	if len(got) != len(want) {
		t.Fatalf("backups %q, want %q", got, want)
	}
	for p, content := range want {
		if got[p] != content {
			t.Fatalf("backup of %s = %q, want %q", p, got[p], content)
		}
	}
}

func TestApplyBacksUpForeignCoreFile(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	s := enforce()
	wantOK(t, f.host().Apply(s))
	managed, err := antispam.ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.file(actionsPath); got != managed[actionsPath] {
		t.Fatalf("actions.conf = %q", got)
	}
	wantBackups(t, f, map[string]string{actionsPath: foreignActions})
	if info, err := os.Stat(f.root + antispam.ReplacedDir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("backup directory: %v, %v", info, err)
	}
	// An update rewrites CSM's own file and backs up nothing more.
	f.reset()
	s.RejectScore = 20
	wantOK(t, f.host().Apply(s))
	if f.count("systemctl reload rspamd.service") != 1 {
		t.Fatalf("update did not rewrite rspamd files: %v", f.calls)
	}
	wantBackups(t, f, map[string]string{actionsPath: foreignActions})
}

func TestApplyBacksUpForeignWantedOptionalFile(t *testing.T) {
	f := newFake(t)
	p := antispam.RedirectPath(antispam.RedirectWhitelist)
	writeTest(t, f.root+p, "operator\n", 0o644)
	wantOK(t, f.host().Apply(enforce()))
	if got := f.file(p); !antispam.IsManaged(got) {
		t.Fatalf("redirect not replaced: %q", got)
	}
	wantBackups(t, f, map[string]string{p: "operator\n"})
}

// A file that can hold the operator's key keeps it private in the backup.
func TestApplyBacksUpForeignSecretFile(t *testing.T) {
	f := newFake(t)
	f.modules = "Modules enabled: dkim, spf, rbl\n"
	f.rbl = `{"rbls":{"csm_dqs_zen":{},"csm_dqs_dbl":{},"csm_dqs_zrd":{}}}`
	writeTest(t, f.root+antispam.FeedRBLPath, "operator key\n", 0o644)
	s := enforce()
	s.Feeds, s.DQSKeyFile = []string{antispam.FeedSpamhausDQS}, "/etc/csm/k"
	wantOK(t, f.host().Apply(s))
	if info, _ := os.Stat(f.root + antispam.FeedRBLPath); info.Mode().Perm() != antispam.SecretFileMode {
		t.Fatalf("secret file mode %v", info.Mode().Perm())
	}
	wantBackups(t, f, map[string]string{antispam.FeedRBLPath: "operator key\n"})
}

// A rollback restores the operator's file, so the backup goes too and no
// warning claims a replacement that did not stick.
func TestRollbackRemovesBackup(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	f.pingFail = []int{1}
	r := f.host().Apply(enforce())
	if r.OK || r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	if got := f.file(actionsPath); got != foreignActions {
		t.Fatalf("actions.conf not restored: %q", got)
	}
	wantBackups(t, f, nil)
}

// While the operator's file is not back, its backup may be the only copy.
func TestFailedRestoreKeepsBackup(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	f.pingFail = []int{1}
	h := f.host()
	h.replace = func(p string, want, next fileState) error {
		if p == f.root+actionsPath && next.content == foreignActions {
			return errors.New("restore failed")
		}
		return replaceFile(p, want, next)
	}
	r := h.Apply(enforce())
	if r.OK || r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	wantBackups(t, f, map[string]string{actionsPath: foreignActions})
}

// A file changed after the snapshot is refused with the conflict error and
// leaves no backup, whether the change lands before the backup or after it.
func TestConflictWritesNoBackup(t *testing.T) {
	const edited = "actions { reject = 50; }\n"
	for _, when := range []string{"before backup", "after backup"} {
		t.Run(when, func(t *testing.T) {
			f := newFake(t)
			writeTest(t, f.root+actionsPath, foreignActions, 0o644)
			h := f.host()
			if when == "before backup" {
				f.onCall = func(line string) {
					if strings.HasPrefix(line, "exim -bP") {
						writeTest(t, f.root+actionsPath, edited, 0o644)
					}
				}
			} else {
				h.replace = func(p string, want, next fileState) error {
					if p == f.root+actionsPath && want.content == foreignActions {
						writeTest(t, p, edited, 0o644)
					}
					return replaceFile(p, want, next)
				}
			}
			r := h.Apply(enforce())
			if r.OK || r.FailedStep != StepRspamdFiles || r.Rollback != antispam.RollbackVerified || !strings.Contains(r.Error, "changed by another writer") {
				t.Fatalf("result %+v", r)
			}
			if got := f.file(actionsPath); got != edited {
				t.Fatalf("concurrent edit replaced: %q", got)
			}
			wantBackups(t, f, nil)
		})
	}
}

// Backups never overwrite each other: a name already taken fails the write
// before the target changes, and the next pass tries again.
func TestBackupNameClashFailsTheWrite(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	if err := os.MkdirAll(f.root+antispam.ReplacedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	earlier := f.root + antispam.ReplacedDir + "/" + antispam.BackupName(actionsPath, f.start)
	writeTest(t, earlier, "earlier backup\n", 0o600)
	r := f.host().Apply(enforce())
	if r.OK || r.FailedStep != StepRspamdFiles || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	if got := f.file(actionsPath); got != foreignActions {
		t.Fatalf("actions.conf changed without a backup: %q", got)
	}
	wantBackups(t, f, map[string]string{actionsPath: "earlier backup\n"})
}

// Removal on cPanel deletes CSM's files and never restores or deletes a
// backup; Postfix restores them (TestRemovePostfixRestoresCopies).
func TestRemoveKeepsBackups(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	wantOK(t, f.host().Apply(enforce()))
	f.reset()
	wantOK(t, f.host().Remove())
	if got := f.file(actionsPath); got != "<absent>" {
		t.Fatalf("actions.conf = %q", got)
	}
	wantBackups(t, f, map[string]string{actionsPath: foreignActions})
}
