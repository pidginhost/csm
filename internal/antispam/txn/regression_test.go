package txn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestApplyChecksRollbackEximReload(t *testing.T) {
	f := newFake(t)
	f.fail["systemctl reload exim.service"] = []int{1, 2}
	r := f.host().Apply(enforce())
	if r.FailedStep != StepEximReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("failed rollback reload reported as %+v", r)
	}
	if f.count("systemctl reload exim.service") != 2 || f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Fatal("rollback must retry the reload and retain the incomplete record")
	}
}

func TestApplyRetriesRspamdReloadWhenRollbackValidationFails(t *testing.T) {
	f := newFake(t)
	f.fail["systemctl reload rspamd.service"] = []int{1}
	f.fail["rspamadm configtest"] = []int{2}
	r := f.host().Apply(enforce())
	if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed || f.count("systemctl reload rspamd.service") != 2 {
		t.Errorf("rollback did not retry the attempted reload: %+v, calls %v", r, f.calls)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("rollback validation failure cleared the incomplete record")
	}
}

func TestApplyRollbackProbesPriorSocket(t *testing.T) {
	f := newFake(t)
	old := enforce()
	old.Socket = "/run/rspamd/prior.sock"
	wantOK(t, f.host().Apply(old))
	before := f.state()
	f.reset()
	h := f.host()
	var sockets []string
	h.ping = func(_ context.Context, socket string) error {
		sockets = append(sockets, socket)
		if socket != old.Socket {
			return errors.New("probe failed")
		}
		return nil
	}
	s := enforce()
	s.RejectScore++
	r := h.Apply(s)
	if r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackVerified {
		t.Errorf("rollback did not confirm the prior socket: %+v", r)
	}
	if len(sockets) < 2 || sockets[len(sockets)-1] != old.Socket {
		t.Errorf("rollback sockets %v, want prior socket last", sockets)
	}
	for p, text := range before {
		if got := f.file(p); got != text {
			t.Errorf("rollback changed %s", p)
		}
	}
}

func TestRollbackInvalidatesCompletedRecordOnFailure(t *testing.T) {
	f := newFake(t)
	tx := f.host().begin()
	defer tx.cancel()
	if _, _, err := tx.readRecord(); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeRecord(""); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeRecord(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	// The final rename can succeed before its directory fsync fails.
	tx.eximTouched = true
	f.fail[BuildEximConf] = []int{-1}
	f.onCall = func(line string) {
		if line == BuildEximConf && f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
			t.Error("recovery started with a completed record")
		}
	}
	state, err := tx.rollback()
	if state != antispam.RollbackFailed || err == nil {
		t.Fatalf("rollback: %s, %v", state, err)
	}
	if got := f.file(antispam.RecordPath); got != string(antispam.EncodeRecord("")) {
		t.Errorf("failed rollback left a completed record: %q", got)
	}
}

func TestApplyRollsBackDurabilityFailures(t *testing.T) {
	for _, target := range []string{antispam.RspamdLocalDir + "/actions.conf", antispam.HookScanPath, "incomplete record", "complete record", "record restore"} {
		t.Run(target, func(t *testing.T) {
			f := newFake(t)
			wantOK(t, f.host().Apply(enforce()))
			before := f.state()
			f.reset()
			h := f.host()
			injected := false
			h.replace = func(p string, want, next fileState) error {
				if err := replaceFile(p, want, next); err != nil {
					return err
				}
				isRecord := p == f.root+antispam.RecordPath
				if !injected && (p == f.root+target ||
					target == "incomplete record" && isRecord && next.content == string(antispam.EncodeRecord("")) ||
					target == "complete record" && isRecord && next.content != string(antispam.EncodeRecord("")) ||
					target == "record restore" && isRecord && next.content == before[antispam.RecordPath]) {
					injected = true
					return fmt.Errorf("%w: test failure", errDurability)
				}
				return nil
			}
			if target == "record restore" {
				f.fail[BuildEximConf] = []int{1}
			}
			s := enforce()
			s.RejectScore++
			r := h.Apply(s)
			wantState := antispam.RollbackVerified
			if target == "record restore" {
				wantState = antispam.RollbackFailed
				before[antispam.RecordPath] = string(antispam.EncodeRecord(""))
			}
			if !injected || r.OK || r.Rollback != wantState {
				t.Errorf("durability failure result: %+v, injected %t", r, injected)
			}
			for p, text := range before {
				if got := f.file(p); got != text {
					t.Errorf("%s not restored after durability failure", p)
				}
			}
		})
	}
}

func TestApplyRecordConflicts(t *testing.T) {
	for _, when := range []string{"before writes", "before completion", "during rollback"} {
		t.Run(when, func(t *testing.T) {
			f := newFake(t)
			wantOK(t, f.host().Apply(enforce()))
			f.reset()
			external := string(antispam.EncodeRecord(strings.Repeat("a", 64)))
			f.onCall = func(line string) {
				if when == "before writes" && line == "systemctl is-active exim.service" ||
					when == "before completion" && line == "systemctl reload exim.service" ||
					when == "during rollback" && line == BuildEximConf && f.seen[BuildEximConf] == 1 {
					writeTest(t, f.root+antispam.RecordPath, external, 0o600)
				}
			}
			if when == "during rollback" {
				f.fail[BuildEximConf] = []int{1}
			}
			s := enforce()
			s.RejectScore++
			r := f.host().Apply(s)
			if r.OK || !strings.Contains(r.Error, errConflict.Error()) {
				t.Errorf("record conflict not reported: %+v", r)
			}
			if got := f.file(antispam.RecordPath); got != external {
				t.Errorf("another writer's record was overwritten: %q", got)
			}
			if when == "before writes" && (f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0) {
				t.Error("record conflict must abort before service mutations")
			}
			if when != "before writes" && r.Rollback != antispam.RollbackFailed {
				t.Errorf("record conflict rollback was %+v", r)
			}
		})
	}
}

func TestTransactionErrorsOmitCommandAndProbeData(t *testing.T) {
	const data = "SENSITIVE_TEST_DATA"
	for _, command := range []string{"exim -bP", "rspamadm configtest", "systemctl reload exim.service", "systemctl reload rspamd.service"} {
		t.Run(command, func(t *testing.T) {
			f := newFake(t)
			h := f.host()
			run := h.run
			h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
				if strings.HasPrefix(strings.Join(append([]string{name}, args...), " "), command) {
					return antispam.CommandResult{Stdout: data, Stderr: data, Err: errors.New(data)}
				}
				return run(ctx, limit, name, args...)
			}
			r := h.Apply(enforce())
			if r.OK || strings.Contains(r.Error, data) {
				t.Errorf("unsafe error result: %+v", r)
			}
		})
	}
	t.Run("ping", func(t *testing.T) {
		f := newFake(t)
		h := f.host()
		h.ping = func(context.Context, string) error { return errors.New(data) }
		r := h.Apply(enforce())
		if r.FailedStep != StepRspamdReload || strings.Contains(r.Error, data) {
			t.Errorf("unsafe ping result: %+v", r)
		}
	})
	for _, dump := range []string{`{"reject":1e300,"add_header":6}`, `{"reject":"SENSITIVE_TEST_DATA"}`, `SENSITIVE_TEST_DATA`} {
		t.Run("actions "+dump, func(t *testing.T) {
			f := newFake(t)
			f.actions = dump
			r := f.host().Apply(enforce())
			if r.FailedStep != StepRspamdCheck || r.Error != "rspamadm configdump -j actions: rspamd configuration conflict" {
				t.Errorf("actions error must omit dump values and parser errors: %+v", r)
			}
		})
	}
}

func TestEximProbeErrorOmitsListenerFromCommandOutput(t *testing.T) {
	f := newFake(t)
	h := f.host()
	h.greet = func(context.Context, string) error { return errors.New("SENSITIVE_TEST_DATA") }
	tx := h.begin()
	defer tx.cancel()
	tx.greeting = "192.0.2.77:25"
	err := tx.probeExim(tx.fwd)
	if err == nil || strings.Contains(err.Error(), tx.greeting) || strings.Contains(err.Error(), "SENSITIVE_TEST_DATA") {
		t.Errorf("probe error repeats command or greeting data: %v", err)
	}
}

func TestTransactionStopsWritesAtForwardDeadline(t *testing.T) {
	f := newFake(t)
	tx := f.host().begin()
	tx.cancel()
	snapshot := tx.h.targets()
	changes, err := plan(snapshot, map[string]string{antispam.RspamdLocalDir + "/actions.conf": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.write(changes[0]); !errors.Is(err, context.Canceled) {
		t.Errorf("write after forward deadline: %v", err)
	}
	if err := tx.writeRecord(""); !errors.Is(err, context.Canceled) {
		t.Errorf("record write after forward deadline: %v", err)
	}
	if f.file(antispam.RspamdLocalDir+"/actions.conf") != "<absent>" || f.file(antispam.RecordPath) != "<absent>" {
		t.Error("expired forward context changed files")
	}
}

func TestTransactionRollsBackWritesThatFinishAfterCancellation(t *testing.T) {
	for _, target := range []string{"file", "incomplete record", "complete record"} {
		t.Run(target, func(t *testing.T) {
			f := newFake(t)
			tx := f.host().begin()
			defer tx.cancel()
			if _, _, err := tx.readRecord(); err != nil {
				t.Fatal(err)
			}
			tx.h.replace = func(p string, want, next fileState) error {
				if err := replaceFile(p, want, next); err != nil {
					return err
				}
				tx.cancel()
				return nil
			}
			var err error
			switch target {
			case "file":
				changes, planErr := plan(tx.h.targets(), map[string]string{antispam.RspamdLocalDir + "/actions.conf": "test"})
				if planErr != nil {
					t.Fatal(planErr)
				}
				err = tx.write(changes[0])
			case "incomplete record":
				err = tx.writeRecord("")
			case "complete record":
				err = tx.writeRecord(strings.Repeat("a", 64))
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("late write error %v, want cancellation", err)
			}
			state, err := tx.rollback()
			if state != antispam.RollbackVerified || err != nil {
				t.Fatalf("late write rollback: %s, %v", state, err)
			}
			if f.file(antispam.RspamdLocalDir+"/actions.conf") != "<absent>" || f.file(antispam.RecordPath) != "<absent>" {
				t.Error("late write was not restored")
			}
		})
	}
}

func TestApplyCannotCompleteAfterForwardDeadline(t *testing.T) {
	f := newFake(t)
	before := f.state()
	h := f.host()
	h.now = func() time.Time { return time.Now().Add(-forwardBudget + time.Second) }
	run := h.run
	waited := false
	h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == antispam.EximUnit && f.count("systemctl reload exim.service") == 0 {
			// A command can finish successfully just as the budget expires.
			<-ctx.Done()
			waited = true
		}
		return run(ctx, limit, name, args...)
	}
	r := h.Apply(enforce())
	if !waited || r.FailedStep != StepEximReload || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("apply did not roll back the expired reload: %+v, waited %t", r, waited)
	}
	for p, text := range before {
		if f.file(p) != text {
			t.Errorf("expired reload did not restore %s", p)
		}
	}
}

func TestRollbackStopsAtItsDeadline(t *testing.T) {
	f := newFake(t)
	tx := f.host().begin()
	defer tx.cancel()
	if _, _, err := tx.readRecord(); err != nil {
		t.Fatal(err)
	}
	if err := tx.writeRecord(""); err != nil {
		t.Fatal(err)
	}
	changes, err := plan(tx.h.targets(), map[string]string{antispam.RspamdLocalDir + "/actions.conf": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.write(changes[0]); err != nil {
		t.Fatal(err)
	}
	tx.start = time.Now().Add(-totalBudget)
	state, err := tx.rollback()
	if state != antispam.RollbackFailed || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expired rollback: %s, %v", state, err)
	}
	if f.file(antispam.RspamdLocalDir+"/actions.conf") != "test" || f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("expired rollback changed files or cleared the incomplete record")
	}
}

func TestApplyCannotVerifyAnyFailedRollbackStep(t *testing.T) {
	for _, step := range []string{"restore", "exim -bV", "rspamd reload", "ping", "greeting"} {
		t.Run(step, func(t *testing.T) {
			f := newFake(t)
			f.fail["systemctl reload exim.service"] = []int{1}
			switch step {
			case "restore":
				f.onCall = func(line string) {
					if line == "systemctl reload exim.service" {
						writeTest(t, f.root+antispam.HookScanPath, "# operator update\n", 0o644)
					}
				}
			case "exim -bV":
				f.fail["exim -bV"] = []int{2}
			case "rspamd reload":
				f.fail["systemctl reload rspamd.service"] = []int{2}
			case "ping":
				f.pingFail = []int{2}
			case "greeting":
				f.greetFail = []int{2}
			}
			r := f.host().Apply(enforce())
			if r.FailedStep != StepEximReload || r.Rollback != antispam.RollbackFailed {
				t.Errorf("failed rollback step reported as %+v", r)
			}
			if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) || f.count("systemctl start") != 0 {
				t.Error("failed rollback cleared the record or started a service")
			}
			if step == "restore" && f.file(antispam.HookScanPath) != "# operator update\n" {
				t.Error("rollback overwrote another writer's edit")
			}
		})
	}
}
