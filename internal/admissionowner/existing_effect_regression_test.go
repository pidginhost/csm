package admissionowner

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// A successful linked finish must not expose a queued retry between the
// attempt's failure and the candidate's ending, including permanent blocks.
func TestOwnerExistingEffectEndsInOneWrite(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(map[bool]string{false: "timed", true: "permanent"}[permanent], func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
			proof := fakeExisting
			if permanent {
				proof.ExpiresAt = time.Time{}
			}
			blocks.existing["192.0.2.10"] = proof
			o := f.start(executeOptions(f, blocks))
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			finishExisting := finishExistingLedger
			writes := 0
			setOwnerHook(t, o, &finishExistingLedger, func(l *store.AdmissionLedger, action admission.ActionID, link admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
				writes++
				before, err := l.Candidate(id)
				if err != nil {
					return admission.Candidate{}, admission.AttemptRecord{}, err
				}
				if before.State != admission.StateExecuting {
					t.Errorf("linked ending started from %s, want executing", before.State)
				}
				return finishExisting(l, action, link)
			})
			setOwnerHook(t, o, &finishLedger, func(*store.AdmissionLedger, admission.ActionID, admission.Disposition, time.Duration) (admission.Candidate, admission.AttemptRecord, error) {
				t.Error("successful linked ending used a separate outcome write")
				return admission.Candidate{}, admission.AttemptRecord{}, errors.New("unexpected plain finish")
			})
			setOwnerHook(t, o, &terminateExistingLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.EffectLink) (admission.Candidate, error) {
				t.Error("apply-time ending used a separate candidate write")
				return admission.Candidate{}, errors.New("unexpected termination")
			})
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			c := candidate(t, o, id)
			wantLink := admission.EffectLink{Effect: proof.ID, ExpiresAt: proof.ExpiresAt}
			if writes != 1 || c.State != admission.StateRefused || c.Reason != admission.ReasonExistingEffect || c.Attempts != 1 || c.Link != wantLink || attemptOf(t, o, c).State != admission.StateFailed {
				t.Fatalf("linked writes=%d candidate=%+v", writes, c)
			}
			if s := ledgerStatus(t, o); s.Ceiling.General.Used != 1 || s.Unresolved.Running != 0 {
				t.Fatalf("linked ending changed charges or retained an intent: %+v", s)
			}
		})
	}
}

// A delayed outcome may acknowledge its own failure but must never link
// or finish a newer attempt, even when a fresh block proof is available.
func TestOwnerExistingEffectPendingCannotEndNewerAttempt(t *testing.T) {
	for _, state := range []string{"reserved", "executing", "queued", "linked"} {
		t.Run(state, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
			o := f.start(executeOptions(f, blocks))
			heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			failure := errors.New("outcome write unavailable")
			finish, finishExisting := finishLedger, finishExistingLedger
			failWrites := true
			setOwnerHook(t, o, &finishExistingLedger, func(l *store.AdmissionLedger, action admission.ActionID, link admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
				if failWrites {
					return admission.Candidate{}, admission.AttemptRecord{}, failure
				}
				return finishExisting(l, action, link)
			})
			setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, action admission.ActionID, d admission.Disposition, lead time.Duration) (admission.Candidate, admission.AttemptRecord, error) {
				if failWrites {
					return admission.Candidate{}, admission.AttemptRecord{}, failure
				}
				return finish(l, action, d, lead)
			})
			if err := o.do(o.turn); !errors.Is(err, failure) {
				t.Fatalf("missing outcome failure: %v", err)
			}
			if err := o.do(func() error {
				if len(o.finishes) != 1 {
					return errors.New("missing pending outcome")
				}
				old := o.finishes[0].id
				c, _, err := finish(o.ledger, old, admission.DispositionFailed, 0)
				if err != nil {
					return err
				}
				f.host.advance(admission.RetryBackoff(1) + time.Second)
				if err = o.tick(); err != nil {
					return err
				}
				_, a, granted, err := o.ledger.Reserve(id, admission.LaneGeneral, c.ExpiresAt)
				if err != nil {
					return err
				}
				if !granted || a.Attempt.Seq != 2 {
					return errors.New("newer attempt was not reserved")
				}
				switch state {
				case "executing":
					_, _, _, err = o.ledger.Execute(a.Attempt.ID)
				case "queued", "linked":
					_, _, err = finish(o.ledger, a.Attempt.ID, admission.DispositionFailed, 0)
					if err == nil && state == "linked" {
						_, err = o.ledger.TerminateExisting(id, admission.EffectLink{Effect: "eff_0123456789abcdef0123456789abcdef"})
					}
				}
				failWrites = false
				return err
			}); err != nil {
				t.Fatal(err)
			}
			before := candidate(t, o, id)
			attemptBefore := attemptOf(t, o, before)
			statusBefore := ledgerStatus(t, o)
			if err := o.do(o.finishPending); !errors.Is(err, admission.ErrTransitionConflict) {
				t.Fatalf("historical linked finish = %v, want conflict", err)
			}
			if after := candidate(t, o, id); !reflect.DeepEqual(after, before) || !reflect.DeepEqual(attemptOf(t, o, after), attemptBefore) {
				t.Fatalf("old outcome changed the newer attempt: before=%+v after=%+v", before, after)
			}
			if after := ledgerStatus(t, o); !reflect.DeepEqual(after, statusBefore) {
				t.Fatal("old outcome changed ledger accounting")
			}
			if err := o.do(func() error {
				if len(o.finishes) != 0 {
					t.Errorf("historical outcome retained %d pending writes", len(o.finishes))
				}
				return o.finishPending()
			}); err != nil {
				t.Fatal(err)
			}
			if checks, applies := blocks.calls(); len(checks) != 3 || len(applies) != 1 {
				t.Fatalf("old outcome retried work: checks=%d applies=%d", len(checks), len(applies))
			}
		})
	}
}
