package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// Every outcome path must retain a failed write and retry it on the owner,
// without dispatching the action again or abandoning the other members.
func TestOwnerRetriesUnwrittenOutcomes(t *testing.T) {
	for _, phase := range []string{"execute_refused", "execute_error", "execute_readback", "apply_error", "apply_reply", "applied", "failed", "unknown", "rejected", "committed"} {
		t.Run(phase, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			want := admission.DispositionApplied
			switch phase {
			case "execute_refused", "execute_error", "apply_error", "failed", "rejected":
				want = admission.DispositionFailed
			case "execute_readback", "apply_reply", "unknown":
				want = admission.DispositionUnknown
			}
			switch phase {
			case "apply_error":
				blocks.applyErr = errors.New("batch transport unavailable")
			case "apply_reply":
				blocks.shortResults = true
			case "failed", "unknown":
				effect := firewall.BlockFailed
				if phase == "unknown" {
					effect = firewall.BlockUnknown
				}
				for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
					blocks.results[ip] = firewall.BlockResult{Effect: effect}
				}
			case "rejected":
				blocks.reject = 1
			}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			execute := executeLedger
			setOwnerHook(t, o, &executeLedger, func(l *store.AdmissionLedger, ids []admission.ActionID) ([]admission.Intent, bool, error) {
				switch phase {
				case "execute_refused":
					return nil, false, &admission.Error{Reason: admission.ReasonPendingRecovery}
				case "execute_error":
					return nil, false, errors.New("intent store unavailable")
				}
				intents, granted, err := execute(l, ids)
				if phase == "execute_readback" {
					granted = false
				}
				return intents, granted, err
			})
			finish := finishLedger
			failure := errors.New("outcome store unavailable")
			var held admission.ActionID
			tries := 0
			setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
				if held == "" {
					held = id
				}
				if id == held {
					tries++
					if d != want {
						t.Errorf("outcome changed to %s, want %s", d, want)
					}
					if tries <= 2 {
						if phase == "committed" {
							if _, _, err := finish(l, id, d); err != nil {
								return admission.Candidate{}, admission.AttemptRecord{}, err
							}
						}
						return admission.Candidate{}, admission.AttemptRecord{}, failure
					}
				}
				return finish(l, id, d)
			})
			var ids []admission.CandidateID
			for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
				id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, ip)
				ids = append(ids, id)
			}
			run := func() error { o.schedule(); return o.scheduleErr }
			if err := o.do(run); !errors.Is(err, failure) {
				t.Fatalf("first outcome failure: %v", err)
			}
			checks, applies := blocks.calls()
			firstChecks, firstApplies := len(checks), len(applies)
			mono.advance(time.Second)
			if err := o.do(run); !errors.Is(err, failure) {
				t.Fatalf("outcome write was not retried: %v", err)
			}
			mono.advance(2 * time.Second)
			if err := o.do(run); err != nil {
				t.Fatal(err)
			}
			checks, applies = blocks.calls()
			if tries != 3 || len(checks) != firstChecks || len(applies) != firstApplies {
				t.Fatalf("outcome retry dispatched work: tries=%d checks=%d applies=%d", tries, len(checks), len(applies))
			}
			for _, id := range ids {
				c := candidate(t, o, id)
				if c.Attempts != 1 || attemptOf(t, o, c).Disposition != want {
					t.Fatalf("unfinished member: %+v", c)
				}
			}
			if s := ledgerStatus(t, o); s.Ceiling.General.Used != 2 || outcomes(s, want) != 2 || s.Unresolved.Running != 0 {
				t.Fatalf("outcome accounting: charges=%d outcomes=%d unresolved=%+v", s.Ceiling.General.Used, outcomes(s, want), s.Unresolved)
			}
			if phase == "rejected" && isolatedCount(t, o) != 2 {
				t.Fatal("retried outcome lost kernel rejection isolation")
			}
		})
	}
}

func TestOwnerStopRetriesUnwrittenOutcome(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	finish := finishLedger
	tries := 0
	setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
		tries++
		if tries == 1 {
			return admission.Candidate{}, admission.AttemptRecord{}, errors.New("outcome store unavailable")
		}
		return finish(l, id, d)
	})
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err == nil {
		t.Fatal("expected an outcome write failure")
	}
	o.Stop()
	if s := o.Status(); tries != 2 || s.Ledger.Unresolved.Running != 0 || outcomes(*s.Ledger, admission.DispositionApplied) != 1 {
		t.Fatalf("stop abandoned the outcome: tries=%d status=%+v", tries, s.Ledger)
	}
}

func TestOwnerPendingOutcomesBlockNewWorkAndSurviveClockFailure(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	finish := finishLedger
	tries := 0
	failure := errors.New("outcome store unavailable")
	setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
		tries++
		if tries <= 2 {
			return admission.Candidate{}, admission.AttemptRecord{}, failure
		}
		return finish(l, id, d)
	})
	first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); !errors.Is(err, failure) {
		t.Fatalf("first finish: %v", err)
	}
	next, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	mono.advance(time.Second)
	if err := o.do(o.turn); !errors.Is(err, failure) {
		t.Fatalf("pending finish: %v", err)
	}
	if checks, applies := blocks.calls(); len(checks) != 1 || len(applies) != 1 || candidate(t, o, next).Attempts != 0 {
		t.Fatal("new work started with an unwritten outcome")
	}
	clockFailure := errors.New("clock unavailable")
	f.host.set(func(h *fakeHost) { h.clockErr = clockFailure })
	if err := o.do(o.turn); !errors.Is(err, clockFailure) {
		t.Fatalf("failed clock: %v", err)
	}
	if c := candidate(t, o, first); c.State != admission.StateVerified || c.Attempts != 1 {
		t.Fatalf("failed clock abandoned an applied outcome: %+v", c)
	}
	if checks, applies := blocks.calls(); len(checks) != 1 || len(applies) != 1 || candidate(t, o, next).Attempts != 0 {
		t.Fatal("failed clock authorized fresh work")
	}
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, next); c.State != admission.StateVerified || c.Attempts != 1 {
		t.Fatalf("work did not resume: %+v", c)
	}
	if checks, applies := blocks.calls(); len(checks) != 2 || len(applies) != 2 || len(applies[1]) != 1 || applies[1][0].IP != "192.0.2.11" {
		t.Fatal("recovery dispatched something other than the waiting member")
	}
}
