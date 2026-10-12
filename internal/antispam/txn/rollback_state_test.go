package txn

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestRollbackRejectsInactiveGeneratedBlocks(t *testing.T) {
	for _, preprocessing := range []string{"conditional block", "conditional ACL", "macro substitution"} {
		t.Run(preprocessing, func(t *testing.T) {
			f := installedForRemoval(t)
			hooks, err := antispam.RenderExim(enforce())
			if err != nil {
				t.Fatal(err)
			}
			f.fail["systemctl reload rspamd.service"] = []int{1}
			f.onCall = func(line string) {
				if line != "exim -bV" || f.count(line) != 2 {
					return
				}
				conf := f.file(antispam.GeneratedEximConfPath)
				switch preprocessing {
				case "conditional block":
					conf = strings.Replace(conf, hooks.Post, ".ifdef CSM_DISABLED_HOOK\n"+hooks.Post+".endif\n", 1)
				case "conditional ACL":
					conf = strings.Replace(conf, "acl_smtp_data:\n", ".ifdef CSM_DISABLED_HOOK\nacl_smtp_data:\n.endif\n", 1)
				case "macro substitution":
					conf = "Yes = No\n" + conf
				}
				writeTest(t, f.root+antispam.GeneratedEximConfPath, conf, 0o644)
			}
			r := f.host().Remove()
			if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
				t.Fatalf("inactive restored hooks reported as %+v", r)
			}
			if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
				t.Error("unverified hooks restored a completed record")
			}
		})
	}
}

func TestRollbackPreservesConcurrentFileMode(t *testing.T) {
	f := installedForRemoval(t)
	prior := f.file(antispam.HookPostPath)
	p := f.root + antispam.HookPostPath
	f.fail["systemctl reload exim.service"] = []int{1}
	f.onCall = func(line string) {
		if line == "systemctl reload exim.service" && f.count(line) == 1 {
			if err := os.Chmod(p, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	s := enforce()
	s.RejectScore++
	r := f.host().Apply(s)
	if r.FailedStep != StepEximReload || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	st, err := readFile(p)
	if err != nil || st.content != prior || st.perm != 0o600 {
		t.Fatalf("restored content matches: %t, mode: %v, error: %v", st.content == prior, st.perm, err)
	}
}

func TestRollbackRequiresPriorACLSelection(t *testing.T) {
	for _, option := range []string{"acl_smtp_rcpt", "acl_smtp_data"} {
		t.Run(option, func(t *testing.T) {
			f := installedForRemoval(t)
			f.fail["systemctl reload rspamd.service"] = []int{1}
			h := f.host()
			run := h.run
			h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
				r := run(ctx, limit, name, args...)
				if f.count(BuildEximConf) == 2 && name == "exim" && len(args) > 0 && args[0] == "-bP" {
					r.Stdout = strings.Replace(r.Stdout, option+" = "+option, option+" = other_acl", 1)
				}
				return r
			}
			f.onCall = func(line string) {
				if line == "exim -bV" && f.count(line) == 2 {
					writeTest(t, f.root+antispam.GeneratedEximConfPath,
						f.file(antispam.GeneratedEximConfPath)+"\nother_acl:\n  accept\n", 0o644)
				}
			}
			r := h.Remove()
			if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
				t.Fatalf("redirected restored ACL reported as %+v", r)
			}
			if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
				t.Error("unverified ACL restored a completed record")
			}
		})
	}
}

func TestRollbackValidatesRestoredNamedLists(t *testing.T) {
	f := installedForRemoval(t)
	f.fail["systemctl reload rspamd.service"] = []int{1}
	h := f.host()
	run := h.run
	h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
		r := run(ctx, limit, name, args...)
		if f.count(BuildEximConf) == 2 && name == "exim" && len(args) > 0 && args[0] == "-C" {
			// Undefined lists can exit successfully while printing a failure.
			r.Stdout, r.Stderr = "Failed: missing list\n", "unknown named list\n"
		}
		return r
	}
	r := h.Remove()
	if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("unusable restored named lists reported as %+v", r)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("unverified named lists restored a completed record")
	}
}

func TestRecordRemovalRejectsLateSuccess(t *testing.T) {
	f := newFake(t)
	tx := f.host().begin()
	defer tx.cancel()
	if _, _, err := tx.readRecord(); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeRecord(""); err != nil {
		t.Fatal(err)
	}
	tx.h.replace = func(p string, want, next fileState) error {
		if err := replaceFile(p, want, next); err != nil {
			return err
		}
		tx.cancel()
		return nil
	}
	if err := tx.removeRecord(); !errors.Is(err, context.Canceled) {
		t.Fatalf("late record removal returned %v, want cancellation", err)
	}
	if tx.recordCurrent.exists {
		t.Fatal("late record deletion was not tracked")
	}
	state, err := tx.rollback()
	if state != antispam.RollbackVerified || err != nil || f.file(antispam.RecordPath) != "<absent>" {
		t.Fatalf("late record deletion rollback: %s, %v", state, err)
	}
}

func TestRecordRestoreRejectsLateSuccess(t *testing.T) {
	f := installedForRemoval(t)
	tx := f.host().begin()
	defer tx.cancel()
	if _, _, err := tx.readRecord(); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeRecord(""); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx.h.replace = func(p string, want, next fileState) error {
		if err := replaceFile(p, want, next); err != nil {
			return err
		}
		cancel()
		return nil
	}
	if err := tx.restoreRecord(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("late record restoration returned %v, want cancellation", err)
	}
	if !sameContent(tx.recordCurrent, tx.record) {
		t.Fatal("late record restoration was not tracked")
	}
}
