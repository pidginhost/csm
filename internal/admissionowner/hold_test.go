package admissionowner

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

func executionHeld(t *testing.T, o *Owner) string {
	t.Helper()
	s := o.Status()
	if s == nil || s.Owner == nil {
		t.Fatal("no owner status")
	}
	return s.Owner.ExecutionHeld
}

func heldMono(t *testing.T, o *Owner) *fakeMono {
	t.Helper()
	mono := &fakeMono{now: time.Unix(1000, 0)}
	setOwnerHook(t, o, &monoNow, mono.read)
	return mono
}

// A state write the engine could not make holds automatic execution
// (P8): later block picks wait, deferred as an unavailable engine,
// without reaching the engine. After a second the owner writes the safe
// state again; once that succeeds the hold ends and work runs.
func TestOwnerHoldsExecutionUntilTheStateIsSafe(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockUnknown, Err: fmt.Errorf("%w: no space left on device", firewall.ErrBlockBatchState)}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if held := executionHeld(t, o); !strings.Contains(held, "no space left on device") {
		t.Fatalf("execution held = %q", held)
	}
	waiting, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	for _, step := range []time.Duration{0, time.Second - time.Nanosecond} {
		mono.advance(step)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		checks, _ := blocks.calls()
		if len(checks) != 1 || blocks.probes() != 0 {
			t.Fatalf("a held turn reached the engine: %d checks, %d probes", len(checks), blocks.probes())
		}
		if c := candidate(t, o, waiting); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 {
			t.Fatalf("held work = %+v", c)
		}
	}
	mono.advance(time.Nanosecond)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if blocks.probes() != 1 {
		t.Fatalf("probes = %d", blocks.probes())
	}
	if c := candidate(t, o, waiting); c.State != admission.StateVerified {
		t.Fatalf("work after the hold = %+v", c)
	}
	if held := executionHeld(t, o); held != "" {
		t.Fatalf("execution still held: %q", held)
	}
}

// A probe that fails doubles the wait for the next, from one second up to
// a minute: a firewall that stays broken costs one probe a minute.
func TestOwnerProbesAtMostOncePerBackoff(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Err: fmt.Errorf("%w: restore failed", firewall.ErrBlockBatchState)}
	blocks.markErr = fmt.Errorf("%w: read-only file system", firewall.ErrBlockBatchState)
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	for i, wait := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
		wait *= time.Second
		mono.advance(wait - time.Nanosecond)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if blocks.probes() != i {
			t.Fatalf("probe %d ran before its %v wait", i+1, wait)
		}
		mono.advance(time.Nanosecond)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if blocks.probes() != i+1 {
			t.Fatalf("probe %d did not run after its %v wait", i+1, wait)
		}
	}
	if held := executionHeld(t, o); !strings.Contains(held, "read-only file system") {
		t.Fatalf("execution held = %q", held)
	}
}

// An engine that cannot check a batch holds execution too. Its probe is
// the next batch check, after the wait; no state is rewritten for it.
func TestOwnerHoldsExecutionWhenTheEngineFails(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.checkErr = errors.New("listing blocked set: operation not permitted")
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatalf("turn = %v", err)
	}
	if held := executionHeld(t, o); !strings.Contains(held, "operation not permitted") {
		t.Fatalf("execution held = %q", held)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable {
		t.Fatalf("held work = %+v", c)
	}
	blocks.set(func(b *fakeBlocks) { b.checkErr = nil })
	mono.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified || blocks.probes() != 0 || executionHeld(t, o) != "" {
		t.Fatalf("after the probe: %+v, %d state probes, held %q", c, blocks.probes(), executionHeld(t, o))
	}
}

// Without a running firewall engine execution is held and says so; an
// engine that runs again serves the next turn at once.
func TestOwnerHoldsExecutionWithoutAnEngine(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	var running bool
	opts := previewOptions(f)
	opts.Blocks = func() BlockEngine {
		if !running {
			return nil
		}
		return blocks
	}
	o := f.start(opts)
	heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if held := executionHeld(t, o); !strings.Contains(held, "firewall engine is not running") {
		t.Fatalf("execution held = %q", held)
	}
	if err := o.do(func() error { running = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified || executionHeld(t, o) != "" {
		t.Fatalf("after the engine started: %+v, held %q", c, executionHeld(t, o))
	}
}

func TestOwnerHoldsBackoffAcrossSuccessfulChecks(t *testing.T) {
	for _, fault := range []string{"apply_error", "apply_reply", "check_reply"} {
		t.Run(fault, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			switch fault {
			case "apply_reply":
				blocks.shortResults = true
			case "check_reply":
				blocks.shortChecks = true
			default:
				blocks.applyErr = errors.New("blocked sets unavailable")
			}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			for i, wait := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
				wait *= time.Second
				queuedAt(t, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("192.0.2.%d", 11+i))
				mono.advance(wait - time.Nanosecond)
				f.host.advance(wait - time.Nanosecond)
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				checks, applies := blocks.calls()
				wantApply := i + 1
				if fault == "check_reply" {
					wantApply = 0
				}
				if len(checks) != i+1 || len(applies) != wantApply {
					t.Fatalf("probe %d ran early: checks=%d applies=%d", i+1, len(checks), len(applies))
				}
				mono.advance(time.Nanosecond)
				f.host.advance(time.Nanosecond)
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				checks, applies = blocks.calls()
				if fault != "check_reply" {
					wantApply++
				}
				if len(checks) != i+2 || len(applies) != wantApply || executionHeld(t, o) == "" {
					t.Fatalf("probe %d: checks=%d applies=%d held=%q", i+1, len(checks), len(applies), executionHeld(t, o))
				}
			}
			blocks.set(func(b *fakeBlocks) { b.applyErr = nil; b.shortResults = false; b.shortChecks = false })
			recovered, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.100")
			mono.advance(time.Minute)
			f.host.advance(time.Minute)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if c := candidate(t, o, recovered); c.State != admission.StateVerified || executionHeld(t, o) != "" {
				t.Fatalf("recovery: %+v held=%q", c, executionHeld(t, o))
			}
		})
	}
}

func TestOwnerHoldsAfterNoopStateRepair(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.checkErr = fmt.Errorf("%w: raw state unavailable", firewall.ErrBlockBatchState)
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	for i, wait := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
		wait *= time.Second
		mono.advance(wait - time.Nanosecond)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if blocks.probes() != i {
			t.Fatalf("probe %d ran early", i+1)
		}
		mono.advance(time.Nanosecond)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if blocks.probes() != i+1 || executionHeld(t, o) == "" {
			t.Fatalf("unsafe state released: probes=%d held=%q", blocks.probes(), executionHeld(t, o))
		}
	}
	checks, applies := blocks.calls()
	if c := candidate(t, o, id); c.Attempts != 0 || len(checks) != 1 || len(applies) != 0 {
		t.Fatalf("unsafe work: %+v checks=%d applies=%d", c, len(checks), len(applies))
	}
}

func TestOwnerHoldsProbeWhenNoBlockPicksRemain(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockUnknown, Err: fmt.Errorf("%w: state write failed", firewall.ErrBlockBatchState)}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error {
		o.scheduleDue, o.wakeAt = false, time.Time{}
		o.schedule()
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
	if blocks.probes() != 0 {
		t.Fatal("idle probe ran before its deadline")
	}
	mono.advance(time.Second)
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	checks, applies := blocks.calls()
	if blocks.probes() != 1 || len(checks) != 1 || len(applies) != 1 || executionHeld(t, o) != "" {
		t.Fatalf("idle recovery: probes=%d checks=%d applies=%d held=%q", blocks.probes(), len(checks), len(applies), executionHeld(t, o))
	}
	if c := candidate(t, o, id); c.State != admission.StateUnknown || c.Attempts != 1 || attemptOf(t, o, c).Disposition != admission.DispositionUnknown {
		t.Fatalf("probe changed uncertainty: %+v", c)
	}
}

func TestOwnerHoldsPublishCachedStatus(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	if err := o.do(func() error {
		before := o.Status()
		o.hold(errors.New("blocked sets unavailable"), true)
		held := o.Status()
		if held.Ledger != before.Ledger || !held.CheckedAt.Equal(before.CheckedAt) || before.Owner.ExecutionHeld != "" || held.Owner.ExecutionHeld == "" || held.Owner == before.Owner {
			return errors.New("hold changed or reread the cached ledger sample")
		}
		o.release()
		after := o.Status()
		if after.Ledger != before.Ledger || !after.CheckedAt.Equal(before.CheckedAt) || after.Owner.ExecutionHeld != "" || held.Owner.ExecutionHeld == "" {
			return errors.New("release changed the cached ledger sample or a published owner")
		}
		o.hold(errors.New("blocked sets unavailable"), true)
		o.refreshStatus()
		if o.Status().Owner.ExecutionHeld == "" {
			return errors.New("periodic refresh omitted the execution hold")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerHoldsIdleProtocolProbeBackoff(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.shortResults = true
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { o.scheduleDue = false; o.wakeAt = time.Time{}; return nil }); err != nil {
		t.Fatal(err)
	}
	for i, wait := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
		wait *= time.Second
		mono.advance(wait - time.Nanosecond)
		if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
			t.Fatal(err)
		}
		if blocks.stateProbes != i {
			t.Fatalf("idle protocol probe %d ran early", i+1)
		}
		mono.advance(time.Nanosecond)
		if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
			t.Fatal(err)
		}
		if blocks.stateProbes != i+1 || executionHeld(t, o) == "" {
			t.Fatalf("idle protocol probe %d: count=%d held=%q", i+1, blocks.stateProbes, executionHeld(t, o))
		}
	}
	checks, applies := blocks.calls()
	if c := candidate(t, o, id); c.State != admission.StateUnknown || c.Attempts != 1 || len(checks) != 1 || len(applies) != 1 {
		t.Fatalf("idle probe dispatched uncertain work: %+v checks=%d applies=%d", c, len(checks), len(applies))
	}
}

// Without an engine there is nothing to probe: an idle owner commits
// nothing until the engine starts, and then serves at once.
func TestOwnerWithoutAnEngineIdlesUntilItStarts(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	var running bool
	opts := previewOptions(f)
	opts.Blocks = func() BlockEngine {
		if !running {
			return nil
		}
		return blocks
	}
	o := f.start(opts)
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	run := func() error { o.schedule(); return o.scheduleErr }
	if err := o.do(run); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonInvalid); return err }); err != nil {
		t.Fatal(err)
	}
	mono.advance(time.Second)
	if err := o.do(run); err != nil {
		t.Fatal(err)
	}
	writes := f.db.WriteTxID()
	for i := 0; i < 5; i++ {
		mono.advance(maxProbeWait)
		if err := o.do(run); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.db.WriteTxID() - writes; got != 0 {
		t.Fatalf("an idle owner without an engine committed %d writes", got)
	}
	if err := o.do(func() error { running = true; return run() }); err != nil {
		t.Fatal(err)
	}
	if held := executionHeld(t, o); held != "" || f.db.WriteTxID() == writes {
		t.Fatalf("a started engine waited: held %q", held)
	}
}
