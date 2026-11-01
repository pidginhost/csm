package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// Every dispatched eviction retains its victim outcome through a delayed
// finish, including whole-batch failures and an already-running intent.
func TestOwnerEvictionFinishPathsRetainTheirVictim(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result firewall.BlockResult
		want   admission.Disposition
		victim admission.VictimOutcome
	}{
		{"removed", firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved}, admission.DispositionApplied, admission.VictimRemoved},
		{"committed", firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved}, admission.DispositionApplied, admission.VictimRemoved},
		{"spared", firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimSpared}, admission.DispositionApplied, admission.VictimSpared},
		{"failed", firewall.BlockResult{Effect: firewall.BlockFailed, Victim: firewall.VictimSpared}, admission.DispositionFailed, admission.VictimSpared},
		{"unknown", firewall.BlockResult{Effect: firewall.BlockUnknown, Victim: firewall.VictimUnproven}, admission.DispositionUnknown, admission.VictimUnproven},
		{"unknown_removed", firewall.BlockResult{Effect: firewall.BlockUnknown, Victim: firewall.VictimRemoved}, admission.DispositionUnknown, admission.VictimRemoved},
		{"existing", firewall.BlockResult{Effect: firewall.BlockFailed, Victim: firewall.VictimSpared, Refusal: firewall.BlockRefusedExisting}, admission.DispositionFailed, admission.VictimSpared},
		{"apply_error", firewall.BlockResult{}, admission.DispositionFailed, admission.VictimSpared},
		{"short_reply", firewall.BlockResult{}, admission.DispositionUnknown, admission.VictimUnproven},
		{"execute_readback", firewall.BlockResult{}, admission.DispositionUnknown, admission.VictimUnproven},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, blocks, victim, high := evictionOwner(t, tc.result)
			const lead = 30 * time.Second
			blocks.set(func(b *fakeBlocks) {
				lease := b.lease
				b.lease = func() time.Time { return lease().Add(lead) }
				switch tc.name {
				case "apply_error":
					b.applyErr = errors.New("batch unavailable")
				case "short_reply":
					b.shortResults = true
				}
			})
			if tc.name == "execute_readback" {
				execute := executeLedger
				setOwnerHook(t, o, &executeLedger, func(l *store.AdmissionLedger, ids []admission.ActionID) ([]admission.Intent, bool, error) {
					intents, _, err := execute(l, ids)
					return intents, false, err
				})
			}
			fault := errors.New("outcome write unavailable")
			finish := finishEvictionLedger
			calls := 0
			setOwnerHook(t, o, &finishEvictionLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition, v admission.VictimOutcome, gotLead time.Duration) (admission.Candidate, admission.AttemptRecord, error) {
				calls++
				if d != tc.want || v != tc.victim || gotLead != lead {
					t.Errorf("finish %d: %s, %v, %s; want %s, %v, %s", calls, d, v, gotLead, tc.want, tc.victim, lead)
				}
				if calls == 1 {
					if tc.name == "committed" {
						if _, _, err := finish(l, id, d, v, gotLead); err != nil {
							return admission.Candidate{}, admission.AttemptRecord{}, err
						}
					}
					return admission.Candidate{}, admission.AttemptRecord{}, fault
				}
				return finish(l, id, d, v, gotLead)
			})
			setOwnerHook(t, o, &finishLedger, func(*store.AdmissionLedger, admission.ActionID, admission.Disposition, time.Duration) (admission.Candidate, admission.AttemptRecord, error) {
				t.Error("an intent naming a victim used FinishOnLease")
				return admission.Candidate{}, admission.AttemptRecord{}, fault
			})
			finishExisting := finishExistingLedger
			links := 0
			setOwnerHook(t, o, &finishExistingLedger, func(l *store.AdmissionLedger, id admission.ActionID, link admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
				links++
				if calls != 2 {
					t.Errorf("existing link bypassed the eviction outcome: %d writes", calls)
				}
				return finishExisting(l, id, link)
			})
			if err := o.do(o.turn); !errors.Is(err, fault) {
				t.Fatalf("finish error = %v, want %v", err, fault)
			}
			before := admission.StateExecuting
			if tc.name == "committed" {
				before = admission.StateVerified
			}
			if c := candidate(t, o, high); c.State != before || len(blocks.retireCalls()) != 0 {
				t.Fatalf("outcome lost before commit: %+v, retirements %v", c, blocks.retireCalls())
			}
			if err := o.do(o.finishPending); err != nil {
				t.Fatal(err)
			}
			c := candidate(t, o, high)
			if a := attemptOf(t, o, c); calls != 2 || a.Disposition != tc.want || a.Attempt.Seq != 1 {
				t.Fatalf("finish retry: %d calls, attempt %+v", calls, a)
			}
			wantApplies := 2
			if tc.name == "execute_readback" {
				wantApplies = 1
			}
			if _, applies := blocks.calls(); len(applies) != wantApplies {
				t.Fatalf("finish retry dispatched work: %d applies, want %d", len(applies), wantApplies)
			}
			if err := o.do(o.retireEvicted); err != nil {
				t.Fatal(err)
			}
			wantRetires, wantSlots := 0, 2
			if tc.want == admission.DispositionFailed {
				wantSlots = 1
			}
			if tc.want == admission.DispositionApplied && tc.victim == admission.VictimRemoved {
				wantRetires, wantSlots = 1, 1
			}
			if retires := blocks.retireCalls(); len(retires) != wantRetires {
				t.Fatalf("retirements = %v, want %d", retires, wantRetires)
			} else if wantRetires == 1 && (len(retires[0]) != 1 || retires[0][0].Action != string(victim.Attempt.ID)) {
				t.Fatalf("retired the wrong victim: %v", retires)
			}
			if s := ledgerStatus(t, o); s.Effects.General != wantSlots {
				t.Fatalf("general slots = %d, want %d", s.Effects.General, wantSlots)
			}
			if tc.name == "existing" {
				if c := candidate(t, o, high); links != 1 || c.State != admission.StateRefused || c.Reason != admission.ReasonExistingEffect || c.Attempts != 1 {
					t.Fatalf("existing block was not linked: %+v", c)
				}
			}
		})
	}
}

// A link failure must not discard the eviction outcome or retain it as
// unfinished work once the ledger has returned the victim's claim.
func TestOwnerEvictionOutcomeSurvivesAFailedLink(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "budget"}[refused], func(t *testing.T) {
			o, blocks, _, high := evictionOwner(t, firewall.BlockResult{
				Effect: firewall.BlockFailed, Victim: firewall.VictimSpared, Refusal: firewall.BlockRefusedExisting,
			})
			fault := errors.New("link write unavailable")
			if refused {
				fault = &admission.Error{Reason: admission.ReasonStorageShare}
			}
			setOwnerHook(t, o, &finishExistingLedger, func(l *store.AdmissionLedger, id admission.ActionID, _ admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
				a, err := l.Attempt(id)
				if err != nil || a.State != admission.StateFailed {
					t.Errorf("link preceded the eviction outcome: %+v, %v", a, err)
				}
				return admission.Candidate{}, admission.AttemptRecord{}, fault
			})
			err := o.do(o.turn)
			if refused && err != nil || !refused && !errors.Is(err, fault) {
				t.Fatalf("link failure = %v, refused = %v", err, refused)
			}
			c := candidate(t, o, high)
			if c.State != admission.StateQueued || c.Attempts != 1 || attemptOf(t, o, c).Disposition != admission.DispositionFailed {
				t.Fatalf("link failure lost the failed attempt: %+v", c)
			}
			if s := ledgerStatus(t, o); s.Effects.General != 1 || s.Unresolved.Running != 0 {
				t.Fatalf("link failure retained the eviction claim: %+v", s)
			}
			if err := o.do(func() error {
				if len(o.finishes) != 0 || len(o.evicted) != 0 {
					t.Errorf("link failure retained finished work: %v, %v", o.finishes, o.evicted)
				}
				return o.finishPending()
			}); err != nil {
				t.Fatal(err)
			}
			if len(blocks.retireCalls()) != 0 {
				t.Fatal("link failure retired a spared victim")
			}
		})
	}
}

// A dry-run owner still cleans up earlier evictions. Losing the engine
// must leave an idle wake so its return needs no new candidate or policy.
func TestOwnerEvictedCleanupWaitsForMissingEngine(t *testing.T) {
	o, blocks, _, _ := evictionOwner(t, firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved})
	mono := &fakeMono{now: monoNow()}
	setOwnerHook(t, o, &monoNow, mono.read)
	blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("cleanup unavailable") })
	turn(t, o)
	setOwnerHook(t, o, &o.opts.Blocks, func() BlockEngine { return nil })
	var policy ExecutionPolicy
	if err := o.do(func() error {
		policy = o.policy
		policy.Epoch++
		policy.DryRun = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	setOwnerHook(t, o, &o.opts.Policy, func() ExecutionPolicy { return policy })
	mono.advance(defaultScheduleEvery)
	if err := o.do(func() error {
		o.scheduleDue = false
		o.schedule()
		want := mono.read().Add(defaultScheduleEvery)
		if o.wakeAt.IsZero() || o.wakeAt.After(want) {
			t.Errorf("missing engine lost cleanup wake: %v, want by %v", o.wakeAt, want)
		}
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) { b.retireErr = nil })
	setOwnerHook(t, o, &o.opts.Blocks, func() BlockEngine { return blocks })
	mono.advance(defaultScheduleEvery)
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if calls := blocks.retireCalls(); len(calls) != 2 || o.Status().Owner.RetirementError != "" {
		t.Fatalf("returning engine did not clean up: %v, %q", calls, o.Status().Owner.RetirementError)
	}
}
