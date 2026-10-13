package admissionowner

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// Send and readback faults are per-member results too. They must hold
// fresh work without losing the outcome or resetting the probe wait.
func TestOwnerHoldsPerMemberEngineFaults(t *testing.T) {
	for _, effect := range []firewall.BlockEffect{firewall.BlockFailed, firewall.BlockUnknown} {
		t.Run(string(effect), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			fault := errors.New("batch transport unavailable")
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: effect, Err: fault}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if held := executionHeld(t, o); !strings.Contains(held, fault.Error()) {
				t.Fatalf("member fault not held: %q", held)
			}
			want := admission.DispositionFailed
			if effect == firewall.BlockUnknown {
				want = admission.DispositionUnknown
			}
			if a := attemptOf(t, o, candidate(t, o, id)); a.Disposition != want {
				t.Fatalf("member outcome = %s", a.Disposition)
			}
			for i, wait := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
				ip := fmt.Sprintf("192.0.2.%d", 11+i)
				blocks.set(func(b *fakeBlocks) { b.results[ip] = firewall.BlockResult{Effect: effect, Err: fault} })
				queuedAt(t, o, p, f.host, admission.SeverityHigh, ip)
				mono.advance(wait*time.Second - time.Nanosecond)
				f.host.advance(wait*time.Second - time.Nanosecond)
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				if checks, applies := blocks.calls(); len(checks) != i+1 || len(applies) != i+1 {
					t.Fatalf("probe %d ran early: checks=%d applies=%d", i+1, len(checks), len(applies))
				}
				mono.advance(time.Nanosecond)
				f.host.advance(time.Nanosecond)
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				if _, applies := blocks.calls(); len(applies) != i+2 || !strings.Contains(executionHeld(t, o), fault.Error()) {
					t.Fatalf("probe %d: applies=%d held=%q", i+1, len(applies), executionHeld(t, o))
				}
			}
			blocks.set(func(b *fakeBlocks) { clear(b.results) })
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.100")
			mono.advance(time.Minute)
			f.host.advance(time.Minute)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if held := executionHeld(t, o); held != "" {
				t.Fatalf("successful apply still held: %q", held)
			}
		})
	}
}

func TestOwnerApplyHoldSurvivesStateRepair(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.applyErr = errors.New("batch transport unavailable")
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) { b.checkErr = firewall.ErrBlockBatchState })
	mono.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) { b.checkErr = nil })
	mono.advance(2 * time.Second)
	// No ready member: repair can prove the state, but not the failed apply.
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if held := executionHeld(t, o); !strings.Contains(held, "batch transport unavailable") {
		t.Fatalf("state repair lost the unproven apply fault: %q", held)
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	mono.advance(4*time.Second - time.Nanosecond)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 1 {
		t.Fatalf("state repair reset the wait: %d applies", len(applies))
	}
}

// An apply that only rechecks and refuses members never exercises the
// transport. Its nil error cannot prove that a transport fault recovered.
func TestOwnerApplyHoldSurvivesRefusedMembers(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.applyErr = errors.New("batch transport unavailable")
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) {
		b.applyErr = nil
		b.results["192.0.2.11"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedFull}
	})
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	mono.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if held := executionHeld(t, o); !strings.Contains(held, "batch transport unavailable") {
		t.Fatalf("refused members cleared an unproven apply fault: %q", held)
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	mono.advance(2*time.Second - time.Nanosecond)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 2 {
		t.Fatalf("refused members reset the wait: %d applies", len(applies))
	}
	mono.advance(time.Nanosecond)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if held := executionHeld(t, o); held != "" {
		t.Fatalf("successful apply still held: %q", held)
	}
}

// A healthy check followed by a ledger refusal proves nothing about the
// failed apply. It still consumes one probe and grows the wait.
func TestOwnerApplyHoldBacksOffLedgerRefusals(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.applyErr = errors.New("batch transport unavailable")
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	setOwnerHook(t, o, &executeLedger, func(*store.AdmissionLedger, []admission.ActionID) ([]admission.Intent, bool, error) {
		return nil, false, &admission.Error{Reason: admission.ReasonPendingRecovery}
	})
	for i, wait := range []time.Duration{1, 2, 4, 8} {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("192.0.2.%d", 11+i))
		mono.advance(wait*time.Second - time.Nanosecond)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if checks, _ := blocks.calls(); len(checks) != i+1 || blocks.stateProbes != i {
			t.Fatalf("probe %d ran early: checks=%d probes=%d", i+1, len(checks), blocks.stateProbes)
		}
		mono.advance(time.Nanosecond)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if checks, applies := blocks.calls(); len(checks) != i+2 || len(applies) != 1 || blocks.stateProbes != i+1 || executionHeld(t, o) == "" {
			t.Fatalf("probe %d: checks=%d applies=%d probes=%d held=%q", i+1, len(checks), len(applies), blocks.stateProbes, executionHeld(t, o))
		}
	}
}

type successfulSnapshotBlocks struct{ *fakeBlocks }

func (b successfulSnapshotBlocks) ProbeBlockState() error {
	_ = b.fakeBlocks.ProbeBlockState()
	return nil
}

func TestOwnerCheckHoldSurvivesSuccessfulSnapshot(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.checkErr = errors.New("blocked set read failed after the probe")
	opts := executeOptions(f, blocks)
	opts.Blocks = func() BlockEngine { return successfulSnapshotBlocks{blocks} }
	o := f.start(opts)
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	for i, wait := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
		mono.advance(wait*time.Second - time.Nanosecond)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if checks, _ := blocks.calls(); len(checks) != i+1 || blocks.stateProbes != i {
			t.Fatalf("probe %d ran early: checks=%d probes=%d", i+1, len(checks), blocks.stateProbes)
		}
		mono.advance(time.Nanosecond)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if checks, applies := blocks.calls(); len(checks) != i+2 || len(applies) != 0 || blocks.stateProbes != i+1 || executionHeld(t, o) == "" {
			t.Fatalf("probe %d: checks=%d applies=%d probes=%d held=%q", i+1, len(checks), len(applies), blocks.stateProbes, executionHeld(t, o))
		}
	}
	blocks.set(func(b *fakeBlocks) { b.checkErr = nil })
	mono.advance(time.Minute)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified || executionHeld(t, o) != "" {
		t.Fatalf("check recovery: %+v held=%q", c, executionHeld(t, o))
	}
}
