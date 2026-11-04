package admissionowner

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// verifiedOwner is a live owner with one verified block at addr, its
// engine and its clock.
func verifiedOwner(t *testing.T, addr string) (*Owner, *fakeBlocks, *ownerFixture, *fakeMono, admission.AttemptRecord) {
	t.Helper()
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
	turn(t, o)
	c := candidate(t, o, id)
	if c.State != admission.StateVerified {
		t.Fatalf("candidate = %+v, want a verified block", c)
	}
	return o, blocks, f, mono, attemptOf(t, o, c)
}

// later moves both clocks one held check on and runs a turn.
func later(t *testing.T, o *Owner, f *ownerFixture, mono *fakeMono) {
	t.Helper()
	mono.advance(heldEvery)
	f.host.advance(heldEvery)
	turn(t, o)
}

// A live owner asks the firewall, at most once a minute and only while
// the ledger counts a verified block, whether each is still held, and
// wakes for the next check. The second consecutive miss marks the block
// gone, which frees its slot; a gone block is not asked about again.
func TestOwnerMarksARemovedBlockGone(t *testing.T) {
	o, blocks, f, mono, a := verifiedOwner(t, "192.0.2.10")
	if calls := blocks.heldCalls(); len(calls) != 1 {
		t.Fatalf("first verified block did not start its checks: %+v", calls)
	}
	turn(t, o)
	turn(t, o)
	want := []firewall.BlockAction{{Action: string(a.Attempt.ID), IP: "192.0.2.10"}}
	if calls := blocks.heldCalls(); len(calls) != 1 || !reflect.DeepEqual(calls[0], want) {
		t.Fatalf("held checks = %+v, want one for %+v", calls, want)
	}
	if err := o.do(func() error {
		if by := mono.read().Add(heldEvery); o.wakeAt.IsZero() || o.wakeAt.After(by) {
			t.Errorf("turn wakes at %v, want by the next held check at %v", o.wakeAt, by)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := ledgerStatus(t, o); st.Effects.General != 1 {
		t.Fatalf("effects before the removal = %+v", st.Effects)
	}
	blocks.set(func(b *fakeBlocks) { b.removed["192.0.2.10"] = true })
	later(t, o, f, mono)
	if st := ledgerStatus(t, o); st.Effects.General != 1 {
		t.Fatalf("one miss freed the slot: %+v", st.Effects)
	}
	later(t, o, f, mono)
	if st := ledgerStatus(t, o); st.Effects.General != 0 || st.Effects.Error != "" {
		t.Fatalf("effects after two misses = %+v, want the slot free", st.Effects)
	}
	later(t, o, f, mono)
	if calls := blocks.heldCalls(); len(calls) != 3 {
		t.Fatalf("held checks = %d, want none about a gone block", len(calls))
	}
}

// A failed or short answer marks nothing and counts as no miss; the next
// check comes a minute later.
func TestOwnerHeldCheckFaultsMarkNothing(t *testing.T) {
	o, blocks, f, mono, _ := verifiedOwner(t, "192.0.2.11")
	blocks.set(func(b *fakeBlocks) {
		b.removed["192.0.2.11"] = true
		b.heldErr = errors.New("held check unavailable")
	})
	turn(t, o)
	turn(t, o)
	later(t, o, f, mono)
	blocks.set(func(b *fakeBlocks) { b.heldErr, b.heldShort = nil, true })
	later(t, o, f, mono)
	later(t, o, f, mono)
	if calls := blocks.heldCalls(); len(calls) != 4 {
		t.Fatalf("held checks = %d, want one a minute", len(calls))
	}
	if st := ledgerStatus(t, o); st.Effects.General != 1 {
		t.Fatalf("faulty answers freed the slot: %+v", st.Effects)
	}
	blocks.set(func(b *fakeBlocks) { b.heldShort = false })
	later(t, o, f, mono)
	later(t, o, f, mono)
	if st := ledgerStatus(t, o); st.Effects.General != 0 {
		t.Fatalf("two good misses after faults = %+v, want the slot free", st.Effects)
	}
}

// A valid first miss survives engine failures and short answers. Neither
// failure escapes the turn, starts a miss or changes its timestamp.
func TestOwnerHeldCheckFaultBetweenMisses(t *testing.T) {
	o, blocks, f, mono, _ := verifiedOwner(t, "192.0.2.10")
	blocks.set(func(b *fakeBlocks) { b.removed["192.0.2.10"] = true })
	later(t, o, f, mono)
	blocks.set(func(b *fakeBlocks) { b.heldErr = errors.New("held unavailable") })
	later(t, o, f, mono)
	blocks.set(func(b *fakeBlocks) { b.heldErr, b.heldShort = nil, true })
	later(t, o, f, mono)
	if st := ledgerStatus(t, o); st.Effects.General != 1 {
		t.Fatalf("fault between misses freed the slot: %+v", st.Effects)
	}
	blocks.set(func(b *fakeBlocks) { b.heldShort = false })
	later(t, o, f, mono)
	if st := ledgerStatus(t, o); st.Effects.General != 0 {
		t.Fatalf("fault lost the first miss: %+v", st.Effects)
	}
}

// Monotonic time spaces checks even across wall jumps. Retirement's own
// retry/backoff must neither erase nor postpone the held check's wake.
func TestOwnerHeldCheckKeepsItsOwnWake(t *testing.T) {
	o, blocks, f, mono, _ := verifiedOwner(t, "192.0.2.10")
	turn(t, o)
	due := mono.read().Add(heldEvery)
	f.host.advance(2 * time.Hour)
	turn(t, o)
	if len(blocks.heldCalls()) != 1 {
		t.Fatal("wall time advanced the held check")
	}
	if err := o.do(func() error {
		o.retireNext = time.Time{}
		o.retireAt = due.Add(time.Hour)
		o.wakeAt = time.Time{}
		if err := o.turn(); err != nil {
			return err
		}
		if o.wakeAt.IsZero() || o.wakeAt.After(due) {
			t.Errorf("retirement postponed held wake: %v, want by %v", o.wakeAt, due)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mono.advance(heldEvery - time.Nanosecond)
	turn(t, o)
	if len(blocks.heldCalls()) != 1 {
		t.Fatal("checked before the monotonic deadline")
	}
	mono.advance(time.Nanosecond)
	turn(t, o)
	if len(blocks.heldCalls()) != 2 {
		t.Fatal("did not check at the monotonic deadline")
	}
}

// The same gate as retirement governs checks of an existing live ledger;
// invalid policy never reaches the engine or frees a slot.
func TestOwnerHeldCheckRequiresRetirementPermission(t *testing.T) {
	o, blocks, _, _, _ := verifiedOwner(t, "192.0.2.10")
	before := len(blocks.heldCalls())
	if err := o.do(func() error {
		o.heldAt = time.Time{}
		o.policyErr = errors.New("policy unavailable")
		if err := o.observeHeld(); err != nil {
			return err
		}
		if !o.heldAt.IsZero() {
			t.Error("a refused check set a deadline")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(blocks.heldCalls()) != before || ledgerStatus(t, o).Effects.General != 1 {
		t.Fatal("a refused policy checked or freed a held block")
	}
}

// Shipped preview and forecast modes have no live effects and perform no
// held checks or schema raise. The production execution gate stays false.
func TestOwnerHeldCheckDoesNotChangeNonLiveModes(t *testing.T) {
	withLiveExecution(t, false)
	for _, mode := range []string{"preview", "forecast"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			opts := previewOptions(f)
			if mode == "forecast" {
				opts = executeOptions(f, blocks)
				policy := livePolicy(opts)()
				policy.DryRun = true
				opts.Policy = func() ExecutionPolicy { return policy }
			}
			o := f.start(opts)
			mono := heldMono(t, o)
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			turn(t, o)
			later(t, o, f, mono)
			later(t, o, f, mono)
			if len(blocks.heldCalls()) != 0 {
				t.Fatal("non-live mode reached the held check")
			}
			if err := o.do(func() error {
				if o.ledger.LiveStarted() || !o.heldAt.IsZero() {
					t.Error("non-live mode acquired live state or a held deadline")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A temporarily missing engine cannot lose an earlier miss or leave an
// expired deadline that spins turns. Reappearance waits for the same rate.
func TestOwnerHeldCheckMissingEngineKeepsRetry(t *testing.T) {
	o, blocks, f, mono, _ := verifiedOwner(t, "192.0.2.10")
	blocks.set(func(b *fakeBlocks) { b.removed["192.0.2.10"] = true })
	later(t, o, f, mono)
	mono.advance(heldEvery)
	if err := o.do(func() error {
		get := o.opts.Blocks
		o.opts.Blocks = func() BlockEngine { return nil }
		err := o.observeHeld()
		o.opts.Blocks = get
		if !o.heldAt.Equal(mono.read().Add(heldEvery)) {
			t.Errorf("missing engine lost retry: %v", o.heldAt)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	turn(t, o)
	if len(blocks.heldCalls()) != 2 || ledgerStatus(t, o).Effects.General != 1 {
		t.Fatal("engine reappearance bypassed the wait")
	}
	later(t, o, f, mono)
	if ledgerStatus(t, o).Effects.General != 0 {
		t.Fatal("missing engine lost the first miss")
	}
}

// A block marked gone may leave its firewall row behind (an element lost
// outside CSM). The owner retires that row as it retires an evicted
// victim's, so a firewall reload cannot restore what the ledger no longer
// counts; the startup readers cover a crash before it.
func TestOwnerRetiresTheRowOfAGoneBlock(t *testing.T) {
	o, blocks, f, mono, a := verifiedOwner(t, "192.0.2.10")
	blocks.set(func(b *fakeBlocks) { b.removed["192.0.2.10"] = true })
	later(t, o, f, mono)
	later(t, o, f, mono)
	if st := ledgerStatus(t, o); st.Effects.General != 0 {
		t.Fatalf("effects after two misses = %+v", st.Effects)
	}
	turn(t, o)
	want := firewall.BlockAction{Action: string(a.Attempt.ID), IP: "192.0.2.10"}
	retired := false
	for _, call := range blocks.retireCalls() {
		for _, r := range call {
			retired = retired || r == want
		}
	}
	marked := false
	blocks.set(func(b *fakeBlocks) {
		for _, call := range b.marked {
			for _, id := range call {
				marked = marked || id == want.Action
			}
		}
	})
	if !retired || !marked {
		t.Fatalf("gone block's row: retired %t (%+v), marked unverified %t", retired, blocks.retireCalls(), marked)
	}
	if err := o.do(func() error {
		if len(o.evicted) != 0 {
			t.Errorf("cleanup kept %+v after the row was clear", o.evicted)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
