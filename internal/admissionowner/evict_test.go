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

// evictionOwner is a live owner whose general partition holds one slot,
// taken by a verified Warning block of 192.0.2.10, and a Critical block of
// 192.0.2.11 queued behind it. The engine applies the block with result.
func evictionOwner(t *testing.T, result firewall.BlockResult) (*Owner, *fakeBlocks, admission.AttemptRecord, admission.CandidateID) {
	t.Helper()
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	// Three slots, one held by an operator block: one general, one reserved.
	blocks.limit, blocks.temp = 3, 1
	blocks.afterApply = func(b *fakeBlocks) { b.temp, b.admitted = 2, 1 }
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	low, _ := queuedAt(t, o, p, f.host, admission.SeverityWarning, "192.0.2.10")
	turn(t, o)
	mono.advance(batchEvery)
	victim := attemptOf(t, o, candidate(t, o, low))
	if victim.State != admission.StateVerified {
		t.Fatalf("the victim is %+v", victim)
	}
	high, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	blocks.set(func(b *fakeBlocks) { b.results["192.0.2.11"] = result })
	return o, blocks, victim, high
}

// A strictly higher block takes the full general partition from a lower
// verified block: the engine receives the victim the ledger claimed, a
// proven removal evicts it in the ledger, and the owner then marks and
// retires the victim's row, as startup would.
func TestOwnerEvictsALowerTierBlock(t *testing.T) {
	o, blocks, victim, high := evictionOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	turn(t, o)
	_, applies := blocks.calls()
	last := applies[len(applies)-1]
	if len(last) != 1 || last[0].IP != "192.0.2.11" || last[0].Victim.Action != string(victim.Attempt.ID) || last[0].Victim.IP != "192.0.2.10" || !last[0].Victim.ExpiresAt.Equal(victim.ExpiresAt) {
		t.Fatalf("the engine ran %+v, want the victim %s", last, victim.Attempt.ID)
	}
	if c := candidate(t, o, high); c.State != admission.StateVerified {
		t.Fatalf("the evicting block is %+v", c)
	}
	if s := ledgerStatus(t, o); s.Effects.General != 1 {
		t.Fatalf("the ledger counts %+v; the evicted block holds no slot", s.Effects)
	}
	retires := blocks.retireCalls()
	if len(retires) != 1 || len(retires[0]) != 1 || retires[0][0] != (firewall.BlockAction{Action: string(victim.Attempt.ID), IP: "192.0.2.10"}) {
		t.Fatalf("retired %v, want the victim's row", retires)
	}
	var marked [][]string
	blocks.set(func(b *fakeBlocks) { marked = b.marked })
	if len(marked) == 0 || len(marked[len(marked)-1]) != 1 || marked[len(marked)-1][0] != string(victim.Attempt.ID) {
		t.Fatalf("marked %v, want the victim's row marked before its removal", marked)
	}
}

// A victim the batch did not evict keeps its slot in the ledger, and its
// row is not retired: a spared victim, and any victim of an unknown
// member, even one the readback showed gone.
func TestOwnerKeepsAVictimItDidNotRemove(t *testing.T) {
	for _, r := range []firewall.BlockResult{
		{Effect: firewall.BlockApplied, Victim: firewall.VictimSpared},
		{Effect: firewall.BlockUnknown, Victim: firewall.VictimUnproven},
		{Effect: firewall.BlockUnknown, Victim: firewall.VictimRemoved},
	} {
		o, blocks, _, _ := evictionOwner(t, r)
		turn(t, o)
		if s := ledgerStatus(t, o); s.Effects.General != 2 {
			t.Fatalf("%+v: the ledger counts %+v; the victim keeps its slot", r, s.Effects)
		}
		if retires := blocks.retireCalls(); len(retires) != 0 {
			t.Fatalf("%+v: retired %v", r, retires)
		}
	}
}

// The engine's victim effect maps to the ledger's victim outcome; a
// member without a victim reports none and is finished as spared.
func TestVictimOutcomeOfAResult(t *testing.T) {
	for effect, want := range map[firewall.BlockVictimEffect]admission.VictimOutcome{
		firewall.VictimRemoved:  admission.VictimRemoved,
		firewall.VictimSpared:   admission.VictimSpared,
		firewall.VictimUnproven: admission.VictimUnproven,
		"":                      admission.VictimSpared,
	} {
		if got := victimOutcome(firewall.BlockResult{Victim: effect}); got != want {
			t.Fatalf("%q maps to %v, want %v", effect, got, want)
		}
	}
}

// A victim's row the engine cannot retire yet, after a failed call or
// while its element remains, is retried on later turns until it goes.
func TestOwnerRetriesAnEvictedRow(t *testing.T) {
	o, blocks, victim, _ := evictionOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	want := firewall.BlockAction{Action: string(victim.Attempt.ID), IP: "192.0.2.10"}
	blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("state write failed") })
	turn(t, o)
	blocks.set(func(b *fakeBlocks) { b.retireErr, b.present["192.0.2.10"] = nil, true })
	turn(t, o)
	blocks.set(func(b *fakeBlocks) { delete(b.present, "192.0.2.10") })
	turn(t, o)
	turn(t, o)
	retires := blocks.retireCalls()
	if len(retires) != 3 {
		t.Fatalf("retired %v, want three tries", retires)
	}
	for _, call := range retires {
		if len(call) != 1 || call[0] != want {
			t.Fatalf("retired %v, want only the victim's row", retires)
		}
	}
}

// With the verdict callback on, a pick the ledger can fund by evicting is
// asked about even though the set is physically full: room is the
// ledger's, so the panel's answer is not skipped as set_full.
func TestOwnerAsksAboutAPickThatEvicts(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp = 3, 1
	// The kernel then holds three timed elements, two of them admission
	// rows: physically full, with the ledger's general slot taken.
	blocks.afterApply = func(b *fakeBlocks) { b.temp, b.admitted = 3, 2 }
	panel := newFakePanel("block")
	o, _, mono := verdictOwner(t, f, blocks, panel)
	queuedAt(t, o, p, f.host, admission.SeverityWarning, "192.0.2.10")
	turn(t, o)
	readyAnswers(t, o, 1)
	turn(t, o)
	mono.advance(batchEvery)
	high, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	turn(t, o)
	if c := candidate(t, o, high); c.Reason == admission.ReasonSetFull {
		t.Fatalf("a pick the ledger funds by evicting waited as set_full: %+v", c)
	}
	eventually(t, "the evicting pick asked", func() bool {
		asked, _, _, _ := panel.state()
		return len(asked) == 2 && asked[1] == "192.0.2.11"
	})
}

// A failed victim mark is a shared state fault. Cleanup respects its probe
// wait, repairs it on an idle turn and never clears an independent apply fault.
func TestOwnerEvictedMarkFailureHoldsExecution(t *testing.T) {
	for _, applyHeld := range []bool{false, true} {
		t.Run(fmt.Sprint(applyHeld), func(t *testing.T) {
			o, blocks, _, _ := evictionOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
			mono := &fakeMono{now: monoNow()}
			setOwnerHook(t, o, &monoNow, mono.read)
			fault := errors.Join(firewall.ErrBlockBatchState, errors.New("victim mark failed"))
			blocks.set(func(b *fakeBlocks) { b.markErr = fault })
			turn(t, o)
			applyFault := errors.New("earlier apply fault")
			if err := o.do(func() error {
				if !errors.Is(o.execHold, firewall.ErrBlockBatchState) || len(o.evicted) != 1 {
					t.Errorf("hold %v, pending %v; want state hold and retained victim", o.execHold, o.evicted)
				}
				if applyHeld {
					o.applyHold = applyFault
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if got := o.Status().Owner.RetirementError; !strings.Contains(got, "victim mark failed") {
				t.Fatalf("cleanup failure not reported immediately: %q", got)
			}
			marks := blocks.probes()
			turn(t, o)
			if blocks.probes() != marks || len(blocks.retireCalls()) != 0 {
				t.Fatal("cleanup bypassed the state probe wait or retired an unmarked row")
			}
			blocks.set(func(b *fakeBlocks) { b.markErr = nil })
			mono.advance(firstProbeWait)
			turn(t, o)
			if len(blocks.retireCalls()) != 1 || o.Status().Owner.RetirementError != "" {
				t.Fatalf("cleanup did not recover: %v, %q", blocks.retireCalls(), o.Status().Owner.RetirementError)
			}
			if err := o.do(func() error {
				if applyHeld {
					if !errors.Is(o.applyHold, applyFault) || !errors.Is(o.execHold, applyFault) {
						t.Errorf("cleanup cleared the apply hold: %v, %v", o.execHold, o.applyHold)
					}
				} else if o.execHold != nil || o.applyHold != nil {
					t.Errorf("safe state stayed held: %v, %v", o.execHold, o.applyHold)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A failed or held head batch must not starve the tail. Mark failures,
// retirement errors and short replies all preserve the entire failed batch.
func TestOwnerEvictedRowsRotateAfterEveryCheck(t *testing.T) {
	for _, mode := range []string{"mark", "retire", "short", "present"} {
		t.Run(mode, func(t *testing.T) {
			withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			heldMono(t, o)
			rows := make([]firewall.BlockAction, firewall.MaxBlockBatchMembers+1)
			for i := range rows {
				rows[i] = firewall.BlockAction{Action: fmt.Sprintf("act_%032x", i+1), IP: fmt.Sprintf("192.0.2.%d", i+1)}
			}
			fault := errors.New("cleanup unavailable")
			blocks.set(func(b *fakeBlocks) {
				switch mode {
				case "mark":
					b.markErr = fault
				case "retire":
					b.retireErr = fault
				case "short":
					b.retireShort = true
				case "present":
					for _, row := range rows[:len(rows)-1] {
						b.present[row.IP] = true
					}
				}
			})
			if err := o.do(func() error {
				o.evicted = append([]firewall.BlockAction(nil), rows...)
				err := o.retireEvicted()
				if (err != nil) != (mode != "present") {
					t.Errorf("cleanup error %v for %s", err, mode)
				}
				if len(o.evicted) != len(rows) || o.evicted[0] != rows[len(rows)-1] {
					t.Errorf("failed or held batch did not rotate: %v", o.evicted)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			blocks.set(func(b *fakeBlocks) { b.markErr, b.retireErr, b.retireShort = nil, nil, false })
			if err := o.do(o.retireEvicted); err != nil {
				t.Fatal(err)
			}
			calls := blocks.retireCalls()
			last := calls[len(calls)-1]
			if len(last) != firewall.MaxBlockBatchMembers || last[0] != rows[len(rows)-1] {
				t.Fatalf("tail was not served next: %v", last)
			}
		})
	}
}

// Evicted-row cleanup follows the existing retirement policy, including
// cleanup of earlier real work during dry run, without becoming an apply probe.
func TestOwnerEvictedRowsRespectRetirementPolicy(t *testing.T) {
	for _, mode := range []string{"invalid", "preview", "dry-run"} {
		t.Run(mode, func(t *testing.T) {
			o, blocks, _, _ := evictionOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
			blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("wait") })
			turn(t, o)
			blocks.set(func(b *fakeBlocks) { b.retireErr = nil })
			marks, calls := blocks.probes(), len(blocks.retireCalls())
			if mode == "preview" {
				setOwnerHook(t, o, &liveExecution, false)
			}
			if err := o.do(func() error {
				switch mode {
				case "invalid":
					o.policyErr = errors.New("invalid policy")
				case "dry-run":
					o.policy.DryRun = true
				}
				return o.retireEvicted()
			}); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "dry-run" {
				want = 1
			}
			if blocks.probes()-marks != want || len(blocks.retireCalls())-calls != want {
				t.Fatalf("%s: %d marks and %d retirements; want %d", mode, blocks.probes()-marks, len(blocks.retireCalls())-calls, want)
			}
		})
	}
}

// Unknown-attempt retirement and evicted-row cleanup retain their own
// failures. A healthy pass cannot erase the other pass's outstanding fault.
func TestOwnerRetirementFaultsRemainIndependent(t *testing.T) {
	o, blocks, _, _ := evictionOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("evicted cleanup failed") })
	turn(t, o)
	if err := o.do(func() error { o.reportRetirement(nil); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := o.status().Owner.RetirementError; !strings.Contains(got, "evicted cleanup failed") {
		t.Fatalf("healthy unknown pass erased cleanup fault: %q", got)
	}
	if err := o.do(func() error {
		o.retireReadFault = true
		o.reportRetirement(errors.New("unknown intent read failed"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := o.status().Owner.RetirementError; !strings.Contains(got, "evicted cleanup failed") || !strings.Contains(got, "unknown intent read failed") {
		t.Fatalf("one retirement fault hid the other: %q", got)
	}
	blocks.set(func(b *fakeBlocks) { b.retireErr = nil })
	if err := o.do(o.retireEvicted); err != nil {
		t.Fatal(err)
	}
	if got := o.status().Owner.RetirementError; strings.Contains(got, "evicted cleanup failed") || !strings.Contains(got, "unknown intent read failed") {
		t.Fatalf("cleanup recovery erased or retained the wrong fault: %q", got)
	}
	if err := o.do(func() error {
		o.retireReadFault = false
		o.reportRetirement(nil)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := o.status().Owner.RetirementError; got != "" {
		t.Fatalf("recovered retirements still faulted: %q", got)
	}
}

// A refused outcome write retries only the ledger write. The victim row
// cannot retire before that write commits, and the batch is never replayed.
func TestOwnerRetriesEvictionFinishBeforeRetiringRow(t *testing.T) {
	o, blocks, _, high := evictionOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	finish := finishEvictionLedger
	fault := errors.New("outcome write failed")
	calls := 0
	setOwnerHook(t, o, &finishEvictionLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition, v admission.VictimOutcome, lead time.Duration) (admission.Candidate, admission.AttemptRecord, error) {
		calls++
		if calls == 1 {
			return admission.Candidate{}, admission.AttemptRecord{}, fault
		}
		return finish(l, id, d, v, lead)
	})
	if err := o.do(o.turn); !errors.Is(err, fault) {
		t.Fatalf("finish error %v, want %v", err, fault)
	}
	if c := candidate(t, o, high); c.State != admission.StateExecuting || len(blocks.retireCalls()) != 0 {
		t.Fatalf("cleanup preceded the outcome: %+v, %v", c, blocks.retireCalls())
	}
	turn(t, o)
	_, applies := blocks.calls()
	if c := candidate(t, o, high); c.State != admission.StateVerified || calls != 2 || len(applies) != 2 || len(blocks.retireCalls()) != 1 {
		t.Fatalf("finish retry: %+v, %d writes, %d applies, %v retirements", c, calls, len(applies), blocks.retireCalls())
	}
}

// Cleanup gets another turn without new ingress or queued candidates.
func TestOwnerEvictedCleanupWakesAnIdleTurn(t *testing.T) {
	o, blocks, _, _ := evictionOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	mono := &fakeMono{now: monoNow()}
	setOwnerHook(t, o, &monoNow, mono.read)
	blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("cleanup write failed") })
	turn(t, o)
	if err := o.do(func() error {
		want := mono.read().Add(defaultScheduleEvery)
		if o.retireNext.IsZero() || o.retireNext.After(want) || o.wakeAt.IsZero() || o.wakeAt.After(want) {
			t.Errorf("idle cleanup wakes at %v, retirement at %v; want by %v", o.wakeAt, o.retireNext, want)
		}
		o.scheduleDue = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) { b.retireErr = nil })
	mono.advance(defaultScheduleEvery)
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if calls := blocks.retireCalls(); len(calls) != 2 || o.Status().Owner.RetirementError != "" {
		t.Fatalf("idle cleanup did not recover: %v, %q", calls, o.Status().Owner.RetirementError)
	}
}
