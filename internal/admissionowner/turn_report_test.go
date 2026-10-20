package admissionowner

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// A retirement write that fails for any reason fails no turn (C4): the
// owner retries that attempt from a second, doubling to a minute, reports
// the fault once and keeps it in status until the attempt retires.
func TestOwnerRetirementFaultNeverFailsTheTurn(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, a := unknownBlock(t, o, p, f, blocks, "192.0.2.107")
	cause := errors.New("fixture storage fault")
	retire := retireLedger
	setOwnerHook(t, o, &retireLedger, func(*store.AdmissionLedger, admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
		return admission.Candidate{}, admission.AttemptRecord{}, false, cause
	})
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	if err := o.do(o.turn); err != nil {
		t.Fatalf("a retirement fault failed the turn: %v", err)
	}
	if got := o.status().Owner.RetirementError; !strings.Contains(got, cause.Error()) || !strings.Contains(got, string(a.Attempt.ID)) {
		t.Fatalf("retirement error = %q", got)
	}
	f.host.advance(time.Second)
	mono.advance(time.Second)
	if err := o.do(func() error {
		if err := o.tick(); err != nil {
			return err
		}
		if err := o.retire(); err != nil {
			t.Errorf("the fault was reported again: %v", err)
		}
		if got := o.retireRetry[a.Attempt.ID].Sub(mono.read()); got != 2*time.Second {
			t.Errorf("retry in %v, want 2s", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls := len(blocks.retireCalls()); calls != 2 {
		t.Fatalf("%d engine checks, want 2", calls)
	}
	// A later turn with the fault still standing keeps it in status.
	f.host.advance(2 * time.Second)
	mono.advance(2 * time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if got := o.status().Owner; !strings.Contains(got.RetirementError, cause.Error()) || got.Error != "" || got.TurnError != "" {
		t.Fatalf("a standing fault left status as %+v", got)
	}
	setOwnerHook(t, o, &retireLedger, retire)
	f.host.advance(4 * time.Second)
	mono.advance(4 * time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if !attemptOf(t, o, c).Retired {
		t.Fatal("a repaired write did not retire the attempt")
	}
	if got := o.status().Owner.RetirementError; got != "" {
		t.Fatalf("a retired attempt kept its fault: %q", got)
	}
}

// An intent list that cannot be read for a reason other than damage is
// reported once and backed off, not returned by every pass (C4).
func TestOwnerReportsAnUnreadableIntentListOnce(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(executeOptions(f, newFakeBlocks()))
	mono := heldMono(t, o)
	cause := errors.New("fixture list fault")
	list, scans := unresolvedIntents, 0
	setOwnerHook(t, o, &unresolvedIntents, func(*store.AdmissionLedger) ([]admission.Intent, error) {
		scans++
		return nil, cause
	})
	if err := o.do(o.turn); err != nil {
		t.Fatalf("an unreadable list failed the turn: %v", err)
	}
	if got := o.status().Owner.RetirementError; !strings.Contains(got, cause.Error()) {
		t.Fatalf("retirement error = %q", got)
	}
	mono.advance(time.Second)
	if err := o.do(o.retire); err != nil {
		t.Fatalf("the list fault was reported again: %v", err)
	}
	if scans != 2 {
		t.Fatalf("%d scans, want 2", scans)
	}
	// A later turn with the fault still standing keeps it in status.
	mono.advance(2 * time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if got := o.status().Owner.RetirementError; scans != 3 || !strings.Contains(got, cause.Error()) {
		t.Fatalf("after %d scans the standing fault reads %q", scans, got)
	}
	setOwnerHook(t, o, &unresolvedIntents, list)
	mono.advance(4 * time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if got := o.status().Owner.RetirementError; got != "" {
		t.Fatalf("a readable list kept its fault: %q", got)
	}
}

// Status names what holds execution, so doctor can say what to repair:
// the configuration for a refused policy, the firewall for an engine
// hold.
func TestOwnerStatusNamesWhatHoldsExecution(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, _ := policyOwner(t, f, blocks, validPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.108")
	blocks.set(func(b *fakeBlocks) { b.checkErr = errors.New("fixture snapshot unreadable") })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if s := o.Status().Owner; s.ExecutionHeld == "" || s.ExecutionHeldBy != "firewall" {
		t.Fatalf("engine hold: held %q by %q", s.ExecutionHeld, s.ExecutionHeldBy)
	}
	invalid := validPolicy(2)
	invalid.AskVerdict = nil
	r.publish(invalid)
	if err := o.Reload(); !errors.Is(err, ErrPolicy) {
		t.Fatalf("invalid policy = %v", err)
	}
	if s := o.Status().Owner; !strings.Contains(s.ExecutionHeld, "execution policy refused") || s.ExecutionHeldBy != "policy" {
		t.Fatalf("policy hold: held %q by %q", s.ExecutionHeld, s.ExecutionHeldBy)
	}
}

// Engine failures are reported once without failing the turn, including
// short replies. A clean list alone cannot clear a still-faulted check.
func TestOwnerRetirementReportsEngineFaultOnce(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "short"}[short], func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.109")
			blocks.set(func(b *fakeBlocks) {
				b.retireShort = short
				if !short {
					b.retireErr = errors.New("retirement engine unavailable")
				}
			})
			f.host.advance(25 * time.Hour)
			mono.advance(25 * time.Hour)
			if err := o.do(o.turn); err != nil {
				t.Fatalf("engine fault failed the turn: %v", err)
			}
			if got := o.Status().Owner; got.RetirementError == "" || got.TurnError != "" {
				t.Fatalf("engine fault status = %+v", got)
			}
			mono.advance(time.Second)
			if err := o.do(o.retire); err != nil {
				t.Fatalf("engine fault reported twice: %v", err)
			}
			if len(blocks.retireCalls()) != 2 || attemptOf(t, o, c).Retired {
				t.Fatal("retry did not check the engine or retired an uncertain block")
			}
			if err := o.do(o.turn); err != nil || o.Status().Owner.RetirementError == "" {
				t.Fatalf("a waiting turn cleared the fault: %v", err)
			}
			blocks.set(func(b *fakeBlocks) { b.retireErr, b.retireShort = nil, false })
			mono.advance(2 * time.Second)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if !attemptOf(t, o, c).Retired || o.Status().Owner.RetirementError != "" {
				t.Fatal("a successful retirement did not clear its engine fault")
			}
		})
	}
}

// A check fault remains visible while clock or engine recovery prevents a
// proof. Both keep a bounded wake, and a later proof clears the fault.
func TestOwnerRetirementFaultSurvivesUnavailableProof(t *testing.T) {
	for _, unavailable := range []string{"clock", "engine", "empty"} {
		t.Run(unavailable, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			running := true
			opts := executeOptions(f, blocks)
			opts.Blocks = func() BlockEngine {
				if running {
					return blocks
				}
				return nil
			}
			o := f.start(opts)
			mono := heldMono(t, o)
			c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.118")
			blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("fixture engine fault") })
			mono.advance(25 * time.Hour)
			f.host.advance(25 * time.Hour)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if o.Status().Owner.RetirementError == "" {
				t.Fatal("missing initial check fault")
			}
			if unavailable == "empty" {
				setOwnerHook(t, o, &unresolvedIntents, func(*store.AdmissionLedger) ([]admission.Intent, error) { return nil, nil })
			}
			mono.advance(time.Second)
			if err := o.do(func() error {
				running = unavailable != "engine"
				o.degraded = unavailable == "clock"
				o.reportRetirement(o.retire())
				if unavailable != "empty" && !o.retirementWake(mono.read()).Equal(mono.read().Add(2*time.Second)) {
					t.Error("unavailable proof lost its bounded retry wake")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(blocks.retireCalls()) != 1 || attemptOf(t, o, c).Retired {
				t.Fatal("unavailable proof called the engine or retired the attempt")
			}
			if got := o.Status().Owner.RetirementError; (got == "") != (unavailable == "empty") {
				t.Fatalf("%s proof left fault %q", unavailable, got)
			}
			if unavailable == "empty" {
				return
			}
			blocks.set(func(b *fakeBlocks) { b.retireErr = nil })
			mono.advance(2 * time.Second)
			if err := o.do(func() error {
				running, o.degraded = true, false
				o.reportRetirement(o.retire())
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(blocks.retireCalls()) != 2 || !attemptOf(t, o, c).Retired || o.Status().Owner.RetirementError != "" {
				t.Fatal("recovered proof left a stale fault or uncertain attempt")
			}
		})
	}
}
