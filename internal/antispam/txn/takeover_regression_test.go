package txn

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

// Cleanup follows each original, even when another restore fails.
func TestPartialRollbackDropsOnlyRestoredBackups(t *testing.T) {
	f := newFake(t)
	other := antispam.RspamdLocalDir + "/phishing.conf"
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	writeTest(t, f.root+other, "operator phishing settings\n", 0o644)
	f.fail["rspamadm configtest"] = []int{1}
	h := f.host()
	h.replace = func(p string, want, next fileState) error {
		if p == f.root+other && next.content == "operator phishing settings\n" {
			return errors.New("restore failed")
		}
		return replaceFile(p, want, next)
	}
	r := h.Apply(enforce())
	if r.OK || r.FailedStep != StepRspamdCheck || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if f.file(actionsPath) != foreignActions || !antispam.IsManaged(f.file(other)) {
		t.Fatal("unexpected restored files")
	}
	wantBackups(t, f, map[string]string{other: "operator phishing settings\n"})
}

// A refused replacement never needs a backup, even if rollback of an
// earlier file fails.
func TestFailedReplacementDropsBackupDuringFailedRollback(t *testing.T) {
	f := newFake(t)
	other := antispam.RspamdLocalDir + "/phishing.conf"
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	writeTest(t, f.root+other, "operator phishing settings\n", 0o644)
	h := f.host()
	h.replace = func(p string, want, next fileState) error {
		if p == f.root+other || p == f.root+actionsPath && next.content == foreignActions {
			return errors.New("write failed")
		}
		return replaceFile(p, want, next)
	}
	r := h.Apply(enforce())
	if r.OK || r.FailedStep != StepRspamdFiles || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if !antispam.IsManaged(f.file(actionsPath)) || f.file(other) != "operator phishing settings\n" {
		t.Fatal("unexpected files after failed replacement")
	}
	wantBackups(t, f, map[string]string{actionsPath: foreignActions})
}

// A durability failure cannot authorize deleting the only confirmed
// durable copy of the original.
func TestRestoreSyncFailureKeepsOnlyUnconfirmedBackup(t *testing.T) {
	f := newFake(t)
	other := antispam.RspamdLocalDir + "/phishing.conf"
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	writeTest(t, f.root+other, "operator phishing settings\n", 0o644)
	f.fail["rspamadm configtest"] = []int{1}
	h := f.host()
	h.replace = func(p string, want, next fileState) error {
		if err := replaceFile(p, want, next); err != nil {
			return err
		}
		if p == f.root+other && next.content == "operator phishing settings\n" {
			return errDurability
		}
		return nil
	}
	r := h.Apply(enforce())
	if r.OK || r.FailedStep != StepRspamdCheck || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if f.file(actionsPath) != foreignActions || f.file(other) != "operator phishing settings\n" {
		t.Fatal("originals were not restored")
	}
	wantBackups(t, f, map[string]string{other: "operator phishing settings\n"})
}

func TestExpiredRollbackDropsUnusedBackup(t *testing.T) {
	f := newFake(t)
	h := f.host()
	tx := h.begin()
	defer tx.cancel()
	if err := tx.writeRecord(""); err != nil {
		t.Fatal(err)
	}
	h.replace = func(p string, want, next fileState) error {
		if p == f.root+antispam.ScoresPath {
			return errors.New("replacement refused")
		}
		return replaceFile(p, want, next)
	}
	for _, p := range []string{actionsPath, antispam.ScoresPath} {
		writeTest(t, f.root+p, "operator\n", 0o644)
		c := change{target: antispam.TargetFacts{
			Target: antispam.Target{Path: p, Kind: antispam.TargetRspamd}, Content: "operator\n",
		}, next: fileState{exists: true, content: antispam.ManagedHeader + "\n"}}
		err := tx.write(c)
		if (err != nil) != (p == antispam.ScoresPath) {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	// Even an exhausted restore budget must clean up a copy whose original
	// was never replaced. The overwritten original still needs its backup.
	tx.start = f.start.Add(-totalBudget)
	state, err := tx.rollback()
	if state != antispam.RollbackFailed || err == nil {
		t.Fatalf("rollback %s, %v", state, err)
	}
	if f.file(antispam.ScoresPath) != "operator\n" || !antispam.IsManaged(f.file(actionsPath)) {
		t.Fatal("rollback changed files after its deadline")
	}
	wantBackups(t, f, map[string]string{actionsPath: "operator\n"})
}

func TestRollbackRestoresForeignSecretPermissions(t *testing.T) {
	f := newFake(t)
	s := learningApply(f)
	p := antispam.LearningWorkerPath
	writeTest(t, f.root+p, "operator worker settings\n", 0o600)
	before, err := readFile(f.root + p)
	if err != nil {
		t.Fatal(err)
	}
	f.fail["rspamadm configtest"] = []int{1}
	r := f.host().Apply(s)
	if r.OK || r.FailedStep != StepRspamdCheck || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	after, err := readFile(f.root + p)
	if err != nil || after != before {
		t.Fatalf("original state not restored: mode %v, uid %d, gid %d, err %v", after.perm, after.uid, after.gid, err)
	}
	wantBackups(t, f, nil)
}

func TestTakeoverRefusesPermissionsLoosenedAfterPreflight(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	f.onCall = func(line string) {
		if strings.HasPrefix(line, "exim -bP") {
			if err := os.Chmod(f.root+actionsPath, 0o666); err != nil {
				t.Fatal(err)
			}
		}
	}
	r := f.host().Apply(enforce())
	if r.OK || r.FailedStep != StepRspamdFiles || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	if f.file(actionsPath) != foreignActions {
		t.Fatal("unsafe operator file was replaced")
	}
	wantBackups(t, f, nil)
}

func TestTakeoverRechecksProtectionAroundBackup(t *testing.T) {
	for _, p := range []string{actionsPath, antispam.LearningLuaPath, antispam.RoundcubeIncludePath} {
		for _, afterBackup := range []bool{false, true} {
			for name, loosen := range map[string]func(*antispam.TargetFacts){
				"file owner":      func(f *antispam.TargetFacts) { f.File.UID = 1234 },
				"group write":     func(f *antispam.TargetFacts) { f.File.Mode |= 0o020 },
				"other write":     func(f *antispam.TargetFacts) { f.File.Mode |= 0o002 },
				"file ACL":        func(f *antispam.TargetFacts) { f.File.ExtACL = true },
				"symlink":         func(f *antispam.TargetFacts) { f.File.Mode = fs.ModeSymlink | 0o777 },
				"parent owner":    func(f *antispam.TargetFacts) { f.Parents[0].UID = 1234 },
				"parent writable": func(f *antispam.TargetFacts) { f.Parents[0].Mode |= 0o022 },
				"parent ACL":      func(f *antispam.TargetFacts) { f.Parents[0].ExtACL = true },
				"parent symlink":  func(f *antispam.TargetFacts) { f.Parents[0].Mode = fs.ModeSymlink | 0o777 },
			} {
				when := "before backup"
				if afterBackup {
					when = "after backup"
				}
				t.Run(p+"/"+when+"/"+name, func(t *testing.T) {
					f := newFake(t)
					writeTest(t, f.root+p, "operator\n", 0o644)
					s := roundcubeApply(f)
					h := f.host()
					collect := h.targets
					reads := 0
					h.targets = func() []antispam.TargetFacts {
						reads++
						targets := collect()
						if afterBackup && reads == 1 {
							return targets
						}
						if afterBackup {
							wantBackups(t, f, map[string]string{p: "operator\n"})
						}
						for i := range targets {
							if targets[i].Path == p {
								loosen(&targets[i])
							}
						}
						return targets
					}
					r := h.Apply(s)
					step := StepRspamdFiles
					if p == antispam.RoundcubeIncludePath {
						step = StepRoundcube
					}
					if r.OK || r.FailedStep != step || r.Rollback != antispam.RollbackVerified {
						t.Fatalf("result %+v", r)
					}
					wantReads := 1
					if afterBackup {
						wantReads = 2
					}
					if reads != wantReads || f.file(p) != "operator\n" {
						t.Fatalf("unsafe target was changed or checked %d times, want %d", reads, wantReads)
					}
					wantBackups(t, f, nil)
				})
			}
		}
	}
}
