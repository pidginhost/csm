package txn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

func installedForRemoval(t *testing.T) *fakeHost {
	t.Helper()
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	f.reset()
	return f
}

func TestRemoveRollbackRequiresSuccessfulCommands(t *testing.T) {
	for _, command := range []string{BuildEximConf, "exim -bV", "systemctl reload exim.service", "rspamadm configtest", "systemctl reload rspamd.service", "systemctl is-active rspamd.service"} {
		t.Run(command, func(t *testing.T) {
			f := installedForRemoval(t)
			f.fail["systemctl reload rspamd.service"] = []int{1}
			f.fail[command] = append(f.fail[command], 2)
			r := f.host().Remove()
			if r.OK || r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
				t.Fatalf("result %+v", r)
			}
			if got := f.file(antispam.RecordPath); got != string(antispam.EncodeRecord("")) {
				t.Errorf("record = %q", got)
			}
			if f.count("systemctl reload exim.service") != 2 || f.count("systemctl reload rspamd.service") != 2 {
				t.Errorf("rollback skipped reload: %v", f.calls)
			}
		})
	}
}

// Spec 6.3 step 5, which 6.4 shares: a stopped Exim is started on the
// restored configuration, never restarted; one that stays down fails the
// restore.
func TestRemoveStartsStoppedEximButNeverRestarts(t *testing.T) {
	f := installedForRemoval(t)
	f.fail["systemctl is-active exim.service"] = []int{2, 3, 4}
	r := f.host().Remove()
	if r.FailedStep != StepEximProbe || r.Rollback != antispam.RollbackFailed {
		t.Errorf("result %+v", r)
	}
	if f.count("systemctl start exim.service") != 1 || f.count("systemctl restart") != 0 {
		t.Errorf("rollback start calls: %v", f.calls)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("incomplete record lost")
	}
}

func TestRemoveKeepsConcurrentRecord(t *testing.T) {
	for _, step := range []string{"before write", "before delete", "before restore"} {
		t.Run(step, func(t *testing.T) {
			f := installedForRemoval(t)
			foreign := string(antispam.EncodeRecord(strings.Repeat("a", 64)))
			changed := false
			f.onCall = func(line string) {
				at := step == "before write" && line == "systemctl is-active rspamd.service" ||
					step != "before write" && line == "systemctl reload rspamd.service"
				if at && !changed {
					writeTest(t, f.root+antispam.RecordPath, foreign, 0o600)
					changed = true
				}
			}
			if step == "before restore" {
				f.fail["systemctl reload rspamd.service"] = []int{1}
			}
			r := f.host().Remove()
			wantStep, wantRollback := StepComplete, antispam.RollbackFailed
			if step == "before write" {
				wantStep, wantRollback = StepRecord, antispam.RollbackNone
			}
			if step == "before restore" {
				wantStep = StepRspamdReload
			}
			if r.OK || r.FailedStep != wantStep || r.Rollback != wantRollback || !strings.Contains(r.Error, "changed by another writer") {
				t.Errorf("result %+v", r)
			}
			if got := f.file(antispam.RecordPath); got != foreign {
				t.Errorf("concurrent record overwritten: %q", got)
			}
		})
	}
}

func TestRemoveRollbackKeepsConcurrentTarget(t *testing.T) {
	f := installedForRemoval(t)
	foreign := "operator replacement\n"
	f.onCall = func(line string) {
		if line == "systemctl reload rspamd.service" && f.count(line) == 1 {
			writeTest(t, f.root+antispam.HookRCPTPath, foreign, 0o644)
		}
	}
	f.fail["systemctl reload rspamd.service"] = []int{1}
	r := f.host().Remove()
	if r.Rollback != antispam.RollbackFailed || !strings.Contains(r.Error, "changed by another writer") {
		t.Errorf("result %+v", r)
	}
	if f.file(antispam.HookRCPTPath) != foreign {
		t.Error("restored over concurrent target")
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("incomplete record lost")
	}
}

func TestRemoveRestoresDeletedFileModes(t *testing.T) {
	f := installedForRemoval(t)
	p := f.root + antispam.RspamdLocalDir + "/actions.conf"
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	f.fail["rspamadm configtest"] = []int{1}
	r := f.host().Remove()
	if r.FailedStep != StepRspamdCheck || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", st.Mode().Perm())
	}
}

func TestRemoveStopsWritesAtForwardDeadline(t *testing.T) {
	// A result that arrives after the deadline counts as failed, so each
	// expiry surfaces at the command that was running.
	for when, step := range map[string]string{"before record": StepPreconditions, "before rspamd files": StepEximProbe, "before completion": StepRspamdReload} {
		t.Run(when, func(t *testing.T) {
			f := installedForRemoval(t)
			f.start = time.Now().Add(-forwardBudget + 2*time.Second)
			h := f.host()
			expired := false
			h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
				r := f.run(ctx, limit, name, args...)
				line := strings.Join(append([]string{name}, args...), " ")
				expire := when == "before record" && line == "systemctl is-active rspamd.service" ||
					when == "before rspamd files" && line == "systemctl is-active exim.service" && f.count(line) == 2 ||
					when == "before completion" && line == "systemctl is-active rspamd.service" && f.count(line) == 2
				if expire {
					<-ctx.Done()
					expired = true
				}
				return r
			}
			before := f.state()
			r := h.Remove()
			if !expired || r.OK || r.FailedStep != step {
				t.Fatalf("result %+v (expired at intended step: %t)", r, expired)
			}
			wantRollback := antispam.RollbackVerified
			if when == "before record" {
				wantRollback = antispam.RollbackNone
			}
			if r.Rollback != wantRollback || fmt.Sprint(f.state()) != fmt.Sprint(before) {
				t.Errorf("deadline failure did not preserve prior state: %+v", r)
			}
		})
	}
}

func TestRemoveReportsOnlyCommandNames(t *testing.T) {
	f := installedForRemoval(t)
	h := f.host()
	run := h.run
	h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
		r := run(ctx, limit, name, args...)
		if name == BuildEximConf {
			r.Err = errors.New("sensitive output sentinel")
		}
		return r
	}
	r := h.Remove()
	if r.FailedStep != StepEximBuild || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if strings.Contains(r.Error, "sensitive output sentinel") {
		t.Error("error leaked command text")
	}
}

func TestRemoveRepairsMissingGeneratedConfig(t *testing.T) {
	f := newFake(t)
	if err := os.Remove(f.root + antispam.GeneratedEximConfPath); err != nil {
		t.Fatal(err)
	}
	wantOK(t, f.host().Remove())
	if f.count(BuildEximConf) != 1 {
		t.Errorf("missing config not rebuilt: %v", f.calls)
	}
	if f.file(antispam.GeneratedEximConfPath) == "<absent>" {
		t.Error("generated config still absent")
	}
}

func TestRemoveRepairsUnreadableEximSettings(t *testing.T) {
	f := installedForRemoval(t)
	f.fail["exim -bP"] = []int{1}
	wantOK(t, f.host().Remove())
	if f.count(BuildEximConf) != 1 || f.count("systemctl reload exim.service") != 1 {
		t.Errorf("removal did not rebuild: %v", f.calls)
	}
}

func TestRemoveTracksEditsThatFailDirectorySync(t *testing.T) {
	for _, path := range []string{antispam.HookRCPTPath, antispam.RspamdLocalDir + "/actions.conf", antispam.RecordPath} {
		t.Run(path, func(t *testing.T) {
			f := installedForRemoval(t)
			before := f.state()
			h := f.host()
			injected := false
			h.replace = func(p string, want, next fileState) error {
				err := replaceFile(p, want, next)
				if err == nil && p == f.root+path && !injected {
					injected = true
					return fmt.Errorf("%w: test failure", errDurability)
				}
				return err
			}
			r := h.Remove()
			if !injected || r.OK || r.Rollback != antispam.RollbackVerified {
				t.Fatalf("result %+v (injected %t)", r, injected)
			}
			if got := f.state(); fmt.Sprint(got) != fmt.Sprint(before) {
				t.Error("rollback lost an edit that failed after changing disk")
			}
		})
	}
}

func TestRemoveRetainsIncompleteRecordAfterFailedDelete(t *testing.T) {
	f := installedForRemoval(t)
	h := f.host()
	failedDelete := false
	h.replace = func(p string, want, next fileState) error {
		err := replaceFile(p, want, next)
		if err == nil && p == f.root+antispam.RecordPath && !next.exists && !failedDelete {
			failedDelete = true
			return fmt.Errorf("%w: test failure", errDurability)
		}
		return err
	}
	f.fail[BuildEximConf] = []int{2}
	r := h.Remove()
	if !failedDelete || r.FailedStep != StepComplete || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("failed rollback lost the incomplete record")
	}
}

func TestRemoveRollbackRequiresPriorGreeting(t *testing.T) {
	f := installedForRemoval(t)
	f.greets = 0
	f.greetFail = []int{3}
	f.fail["systemctl reload rspamd.service"] = []int{1}
	r := f.host().Remove()
	if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("unverified listener lost the incomplete record")
	}
}

func TestRemoveDoesNotTreatActivityErrorsAsStopped(t *testing.T) {
	for _, unit := range []string{antispam.EximUnit, antispam.RspamdUnit} {
		t.Run(unit, func(t *testing.T) {
			f := installedForRemoval(t)
			before := f.state()
			h := f.host()
			run := h.run
			h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
				if name == "systemctl" && len(args) == 2 && args[0] == "is-active" && args[1] == unit {
					return antispam.CommandResult{Err: errors.New("activity unavailable sentinel")}
				}
				return run(ctx, limit, name, args...)
			}
			r := h.Remove()
			if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone {
				t.Fatalf("result %+v", r)
			}
			if fmt.Sprint(f.state()) != fmt.Sprint(before) {
				t.Error("changed files without knowing service activity")
			}
			if strings.Contains(r.Error, "activity unavailable sentinel") {
				t.Error("activity error leaked text")
			}
		})
	}
}

func TestRemoveRequiresGeneratedConfigAfterBuild(t *testing.T) {
	f := installedForRemoval(t)
	before := f.state()
	f.onCall = func(line string) {
		if line == "exim -bV" && f.count(line) == 1 {
			if err := os.Remove(f.root + antispam.GeneratedEximConfPath); err != nil {
				t.Fatal(err)
			}
		}
	}
	r := f.host().Remove()
	if r.FailedStep != StepEximBuild || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	if fmt.Sprint(f.state()) != fmt.Sprint(before) {
		t.Error("missing generated config did not roll back")
	}
}

func TestRemoveRollbackRequiresGeneratedConfig(t *testing.T) {
	f := installedForRemoval(t)
	f.fail["systemctl reload rspamd.service"] = []int{1}
	f.onCall = func(line string) {
		if line == "exim -bV" && f.count(line) == 2 {
			if err := os.Remove(f.root + antispam.GeneratedEximConfPath); err != nil {
				t.Fatal(err)
			}
		}
	}
	r := f.host().Remove()
	if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("missing rollback config lost the incomplete record")
	}
}

func TestRemoveRollbackRejectsStaleBuild(t *testing.T) {
	f := installedForRemoval(t)
	f.fail["systemctl reload rspamd.service"] = []int{1}
	f.staleBuilds = []int{f.builds + 2}
	r := f.host().Remove()
	if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("stale rollback build lost the incomplete record")
	}
}

func TestRemoveRollbackRequiresPriorBlockPlacement(t *testing.T) {
	f := installedForRemoval(t)
	f.fail["systemctl reload rspamd.service"] = []int{1}
	f.onCall = func(line string) {
		if line == "exim -bV" && f.count(line) == 2 {
			conf := f.file(antispam.GeneratedEximConfPath)
			writeTest(t, f.root+antispam.GeneratedEximConfPath, strings.Replace(conf, "acl_smtp_rcpt:", "other_rcpt:", 1), 0o644)
		}
	}
	r := f.host().Remove()
	if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("misplaced rollback blocks lost the incomplete record")
	}
}

func TestRemoveRollbackRequiresPriorDataOrder(t *testing.T) {
	f := installedForRemoval(t)
	hooks, err := antispam.RenderExim(enforce())
	if err != nil {
		t.Fatal(err)
	}
	f.fail["systemctl reload rspamd.service"] = []int{1}
	f.onCall = func(line string) {
		if line == "exim -bV" && f.count(line) == 2 {
			conf := f.file(antispam.GeneratedEximConfPath)
			conf = strings.Replace(conf, hooks.Scan, "CSM_SCAN_PLACEHOLDER", 1)
			conf = strings.Replace(conf, hooks.Post, hooks.Scan, 1)
			conf = strings.Replace(conf, "CSM_SCAN_PLACEHOLDER", hooks.Post, 1)
			writeTest(t, f.root+antispam.GeneratedEximConfPath, conf, 0o644)
		}
	}
	r := f.host().Remove()
	if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("reordered rollback hooks lost the incomplete record")
	}
}

func TestRemoveWaitsForStableServiceActivity(t *testing.T) {
	for _, state := range []string{"activating", "deactivating"} {
		t.Run(state, func(t *testing.T) {
			f := installedForRemoval(t)
			before := f.state()
			h := f.host()
			run := h.run
			h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
				if name == "systemctl" && len(args) == 2 && args[0] == "is-active" && args[1] == antispam.EximUnit {
					return antispam.CommandResult{Stdout: state + "\n", Err: inactiveExit{}}
				}
				return run(ctx, limit, name, args...)
			}
			r := h.Remove()
			if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone {
				t.Fatalf("result %+v", r)
			}
			if fmt.Sprint(f.state()) != fmt.Sprint(before) {
				t.Error("changed files while service activity was transitional")
			}
		})
	}
}
