package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// An owner without the firewall engine cannot prove an unknown outcome,
// so its address stays held past expiry. Status names the engine as the
// cause; the next owner with an engine retires it on its first turn.
func TestEngineLessOwnerNamesItsRetirementHold(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(previewOptions(f))
	turn(t, o)
	if got := o.status().Owner.RetirementHeldBy; got != "" {
		t.Fatalf("an owner without the engine or unknown outcomes names %q", got)
	}
	o.Stop()
	blocks := newFakeBlocks()
	o = f.start(executeOptions(f, blocks))
	c, a := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	if got := o.status().Owner.RetirementHeldBy; got != "" {
		t.Fatalf("an owner that can retire names %q", got)
	}
	o.Stop()
	f.host.advance(25 * time.Hour)
	o = f.start(previewOptions(f))
	turn(t, o)
	if got := attemptOf(t, o, c); got.Retired || got.State != admission.StateUnknown {
		t.Fatalf("an owner without the engine changed the unknown: %+v", got)
	}
	if s := o.status().Owner; s.RetirementHeldBy != "engine" || s.RetirementError != "" {
		t.Fatalf("engine-less status: held by %q, error %q", s.RetirementHeldBy, s.RetirementError)
	}
	o.Stop()
	fresh := newFakeBlocks()
	o = f.start(executeOptions(f, fresh))
	turn(t, o)
	calls := fresh.retireCalls()
	if len(calls) != 1 || len(calls[0]) != 1 || calls[0][0] != (firewall.BlockAction{Action: string(a.Attempt.ID), IP: "192.0.2.10"}) {
		t.Fatalf("engine retirement calls = %+v", calls)
	}
	if got := attemptOf(t, o, c); !got.Retired {
		t.Fatalf("the engine's return left the unknown: %+v", got)
	}
	if got := o.status().Owner.RetirementHeldBy; got != "" {
		t.Fatalf("retired unknowns still name %q", got)
	}
}

// A refused execution policy stops retirement as well; status names the
// policy until a valid one is installed.
func TestRefusedPolicyNamesItsRetirementHold(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, mono := policyOwner(t, f, blocks, validPolicy(1))
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	invalid := validPolicy(2)
	invalid.AskVerdict = nil
	r.publish(invalid)
	if err := o.Reload(); !errors.Is(err, ErrPolicy) {
		t.Fatalf("invalid policy = %v", err)
	}
	mono.advance(25 * time.Hour)
	f.host.advance(25 * time.Hour)
	turn(t, o)
	if got := attemptOf(t, o, c); got.Retired {
		t.Fatalf("a refused policy retired the unknown: %+v", got)
	}
	if got := o.status().Owner.RetirementHeldBy; got != "policy" {
		t.Fatalf("refused policy: held by %q", got)
	}
	r.publish(validPolicy(3))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) { b.present["192.0.2.10"] = true })
	turn(t, o)
	if s := o.status(); s.Owner.RetirementHeldBy != "" || s.Ledger.Unresolved.Unknown != 1 || attemptOf(t, o, c).Retired {
		t.Fatalf("valid policy must clear only the cause, not the unknown: %+v", s)
	}
	blocks.set(func(b *fakeBlocks) { b.present["192.0.2.10"] = false })
	mono.advance(retireRecheck)
	f.host.advance(retireRecheck)
	turn(t, o)
	if got := attemptOf(t, o, c); !got.Retired {
		t.Fatalf("a valid policy left the unknown: %+v", got)
	}
	if got := o.status().Owner.RetirementHeldBy; got != "" {
		t.Fatalf("retired unknowns still name %q", got)
	}
}

// A configured engine that is not running is reported by the firewall's
// own startup error; retirement backs off and retries, so status names no
// retirement cause.
func TestMissingEngineNamesNoRetirementHold(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	var engine BlockEngine = blocks
	opts := executeOptions(f, blocks)
	opts.Blocks = func() BlockEngine { return engine }
	o := f.start(opts)
	mono := heldMono(t, o)
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	if err := o.do(func() error { engine = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	mono.advance(25 * time.Hour)
	f.host.advance(25 * time.Hour)
	turn(t, o)
	if got := attemptOf(t, o, c); got.Retired {
		t.Fatalf("retired without an engine: %+v", got)
	}
	if got := o.status().Owner.RetirementHeldBy; got != "" {
		t.Fatalf("missing engine: retirement held by %q", got)
	}
}

// Installing a usable engine removes the named cause, but expiry and a
// successful absence proof still decide when the address can be released.
func TestRetirementCauseClearsBeforeTheUnknown(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.50")
	o.Stop()
	o = f.start(previewOptions(f))
	turn(t, o)
	if got := o.status().Owner.RetirementHeldBy; got != "engine" {
		t.Fatalf("unexpired unknown without engine: held by %q", got)
	}
	o.Stop()
	fresh := newFakeBlocks()
	opts := executeOptions(f, fresh)
	opts.Policy = func() ExecutionPolicy { return dryPolicy(1) }
	o = f.start(opts)
	turn(t, o)
	if s := o.status(); s.Owner.RetirementHeldBy != "" || s.Ledger.Unresolved.Unknown != 1 || attemptOf(t, o, c).Retired || len(fresh.retireCalls()) != 0 {
		t.Fatalf("engine return bypassed expiry or kept a false cause: %+v", s)
	}
	mono := heldMono(t, o)
	mono.advance(25 * time.Hour)
	f.host.advance(25 * time.Hour)
	fresh.set(func(b *fakeBlocks) { b.retireErr = errors.New("snapshot unavailable") })
	turn(t, o)
	if s := o.status(); s.Owner.RetirementHeldBy != "" || s.Owner.RetirementError == "" || attemptOf(t, o, c).Retired || len(fresh.retireCalls()) != 1 {
		t.Fatalf("failed proof bypassed the hold or named a permanent cause: %+v", s)
	}
	fresh.set(func(b *fakeBlocks) { b.retireErr = nil })
	mono.advance(maxProbeWait)
	f.host.advance(maxProbeWait)
	turn(t, o)
	if !attemptOf(t, o, c).Retired || o.status().Owner.RetirementHeldBy != "" || len(fresh.retireCalls()) != 2 {
		t.Fatal("a successful proof did not retire the expired unknown")
	}
}
