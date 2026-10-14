package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// A failed linked ending attempts the plain outcome write in the same
// turn. A retained proof ends the pick without another charge or dispatch;
// a disappeared proof permits a bounded retry. A successful fallback also
// prevents a restart from settling the attempt unknown.
func TestOwnerExistingEffectWriteFailuresConverge(t *testing.T) {
	for _, mode := range []string{"linked", "linked_committed", "both", "both_proof_gone", "restart", "terminate", "terminate_committed"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			checkTime := mode == "terminate" || mode == "terminate_committed"
			if checkTime {
				blocks.refuse["192.0.2.10"] = firewall.BlockRefusedExisting
			} else {
				blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
			}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			failure := errors.New("fixture outcome write failure")
			finishExisting, finish, terminateExisting := finishExistingLedger, finishLedger, terminateExistingLedger
			failLinked := !checkTime
			failFinish := mode == "both" || mode == "both_proof_gone"
			failTerminate := checkTime
			setOwnerHook(t, o, &finishExistingLedger, func(l *store.AdmissionLedger, id admission.ActionID, link admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
				if failLinked {
					failLinked = false
					if mode == "linked_committed" {
						if _, _, err := finishExisting(l, id, link); err != nil {
							return admission.Candidate{}, admission.AttemptRecord{}, err
						}
					}
					return admission.Candidate{}, admission.AttemptRecord{}, failure
				}
				return finishExisting(l, id, link)
			})
			setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
				if failFinish {
					failFinish = false
					return admission.Candidate{}, admission.AttemptRecord{}, failure
				}
				return finish(l, id, d)
			})
			setOwnerHook(t, o, &terminateExistingLedger, func(l *store.AdmissionLedger, id admission.CandidateID, link admission.EffectLink) (admission.Candidate, error) {
				if failTerminate {
					failTerminate = false
					if mode == "terminate_committed" {
						if _, err := terminateExisting(l, id, link); err != nil {
							return admission.Candidate{}, err
						}
					}
					return admission.Candidate{}, failure
				}
				return terminateExisting(l, id, link)
			})
			if err := o.do(o.turn); !errors.Is(err, failure) {
				t.Fatalf("missing injected write failure: %v", err)
			}
			if c := candidate(t, o, id); !checkTime && mode != "both" && mode != "both_proof_gone" && attemptOf(t, o, c).State == admission.StateExecuting {
				t.Fatalf("a failed linked ending left the attempt running: %+v", c)
			}
			proofGone := mode == "both_proof_gone"
			if proofGone {
				blocks.set(func(b *fakeBlocks) {
					delete(b.results, "192.0.2.10")
					delete(b.refuse, "192.0.2.10")
				})
			}
			if mode == "restart" {
				o.halt(false)
				o = f.start(executeOptions(f, blocks))
			}
			mono.advance(admission.RetryBackoff(1) + time.Second)
			f.host.advance(admission.RetryBackoff(1) + time.Second)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			c := candidate(t, o, id)
			wantState, wantAttempts, wantDisposition := admission.StateRefused, uint32(1), admission.DispositionFailed
			wantLink := admission.EffectLink{Effect: fakeExisting.ID, ExpiresAt: fakeExisting.ExpiresAt}
			switch {
			case proofGone:
				wantState, wantAttempts, wantDisposition, wantLink = admission.StateVerified, 2, admission.DispositionApplied, admission.EffectLink{}
			case checkTime:
				wantAttempts = 0
			}
			if c.State != wantState || c.Attempts != wantAttempts || c.Link != wantLink {
				t.Fatalf("write recovery: state=%s attempts=%d link=%+v", c.State, c.Attempts, c.Link)
			}
			if wantAttempts > 0 && attemptOf(t, o, c).Disposition != wantDisposition {
				t.Fatalf("write recovery: attempt %+v", attemptOf(t, o, c))
			}
			if !proofGone && (c.Reason != admission.ReasonExistingEffect || !c.NotBefore.IsZero()) {
				t.Fatalf("invalid refused candidate: reason=%s retry=%v", c.Reason, c.NotBefore)
			}
			if _, applies := blocks.calls(); len(applies) != int(wantAttempts) {
				t.Fatalf("recovery repeated a charged attempt: %d applies", len(applies))
			}
			if st := ledgerStatus(t, o); st.Ceiling.General.Used != wantAttempts || st.Unresolved.Running != 0 {
				t.Fatalf("recovery changed charges or left intent: %+v", st)
			}
			// Reopening runs the persisted candidate/attempt/storage proof.
			o.Stop()
			o = f.start(executeOptions(f, blocks))
			if reopened := candidate(t, o, id); reopened.State != wantState || reopened.Attempts != wantAttempts || reopened.Link != wantLink {
				t.Fatalf("reopened ending changed: %+v", reopened)
			}
		})
	}
}

// An existing block found when the batch applies ends the pick only after
// a fresh proof names it; any other answer or a failed check writes the
// failure, and the ordinary bounded retry runs.
func TestOwnerExistingEffectNeedsAFreshProof(t *testing.T) {
	for _, mode := range []string{"gone", "pending", "expired", "error", "short", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting, Existing: fakeExisting}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			blocks.afterApply = func(b *fakeBlocks) {
				b.afterApply = nil
				delete(b.refuse, "192.0.2.10")
				switch mode {
				case "pending":
					b.refuse["192.0.2.10"] = firewall.BlockRefusedPending
				case "expired":
					b.refuse["192.0.2.10"] = firewall.BlockRefusedExpired
				case "error":
					b.checkErr = errors.New("fixture proof unavailable")
				case "short":
					b.shortChecks = true
				case "unavailable":
					o.opts.Blocks = func() BlockEngine { return nil }
				}
			}
			linked := 0
			finishExisting := finishExistingLedger
			setOwnerHook(t, o, &finishExistingLedger, func(l *store.AdmissionLedger, id admission.ActionID, link admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
				linked++
				return finishExisting(l, id, link)
			})
			err := o.do(o.turn)
			wantError := mode == "error" || mode == "short" || mode == "unavailable"
			if (err != nil) != wantError {
				t.Fatalf("proof error=%v, want error=%t", err, wantError)
			}
			if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 1 || c.Reason == admission.ReasonExistingEffect || c.Link != (admission.EffectLink{}) || linked != 0 {
				t.Fatalf("unproven existing effect ended the candidate: %+v after %d linked endings", c, linked)
			}
			blocks.set(func(b *fakeBlocks) {
				delete(b.refuse, "192.0.2.10")
				delete(b.results, "192.0.2.10")
				b.checkErr, b.shortChecks = nil, false
			})
			if err := o.do(func() error { o.opts.Blocks = func() BlockEngine { return blocks }; return nil }); err != nil {
				t.Fatal(err)
			}
			mono.advance(admission.RetryBackoff(1) + time.Second)
			f.host.advance(admission.RetryBackoff(1) + time.Second)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if c := candidate(t, o, id); c.State != admission.StateVerified || c.Attempts != 2 {
				t.Fatalf("missing proof did not converge through bounded retry: %+v", c)
			}
			if st := ledgerStatus(t, o); st.Ceiling.General.Used != 2 || st.Unresolved.Running != 0 {
				t.Fatalf("proof retry changed charge or intent: %+v", st)
			}
			if _, applies := blocks.calls(); len(applies) != 2 {
				t.Fatalf("unexpected kernel dispatches: %d", len(applies))
			}
		})
	}
}

// On the last attempt the linked ending fails the pick as Finish does; a
// lost acknowledgement of that write converges without a second dispatch.
func TestOwnerExistingEffectLastFinishAckFailure(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	for seq := 1; seq < admission.MaxAttempts; seq++ {
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		mono.advance(admission.RetryBackoff(admission.MaxAttempts))
		f.host.advance(admission.RetryBackoff(admission.MaxAttempts))
	}
	blocks.set(func(b *fakeBlocks) {
		b.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
	})
	finishExisting := finishExistingLedger
	failure := errors.New("fixture committed finish acknowledgement lost")
	failed := false
	setOwnerHook(t, o, &finishExistingLedger, func(l *store.AdmissionLedger, id admission.ActionID, link admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
		c, a, err := finishExisting(l, id, link)
		if err == nil && !failed {
			failed = true
			return admission.Candidate{}, admission.AttemptRecord{}, failure
		}
		return c, a, err
	})
	if err := o.do(o.turn); !errors.Is(err, failure) || !failed {
		t.Fatalf("missing committed-finish failure: %v", err)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	o.halt(false)
	o = f.start(executeOptions(f, blocks))
	c := candidate(t, o, id)
	if c.State != admission.StateFailed || c.Attempts != admission.MaxAttempts || c.Reason != 0 || c.Link != (admission.EffectLink{}) || attemptOf(t, o, c).Disposition != admission.DispositionFailed {
		t.Fatalf("last finish could not reopen: %+v", c)
	}
	if st := ledgerStatus(t, o); st.Ceiling.General.Used != admission.MaxAttempts || st.Unresolved.Running != 0 {
		t.Fatalf("last finish changed charge or retained intent: %+v", st)
	}
	if _, applies := blocks.calls(); len(applies) != admission.MaxAttempts {
		t.Fatalf("last finish dispatched again: %d", len(applies))
	}
}

// A successful plain fallback clears a pending outcome even if the linked
// write keeps failing. Later turns must use the ordinary check-time path.
func TestOwnerExistingEffectFallbackClearsPending(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediate", true: "pending_retry"}[delayed], func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			failure := errors.New("fixture linked ending unavailable")
			linkedCalls, plainCalls, terminateCalls := 0, 0, 0
			finish, terminateExisting := finishLedger, terminateExistingLedger
			setOwnerHook(t, o, &finishExistingLedger, func(*store.AdmissionLedger, admission.ActionID, admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
				linkedCalls++
				return admission.Candidate{}, admission.AttemptRecord{}, failure
			})
			setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, action admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
				plainCalls++
				if delayed && plainCalls == 1 {
					return admission.Candidate{}, admission.AttemptRecord{}, failure
				}
				return finish(l, action, d)
			})
			setOwnerHook(t, o, &terminateExistingLedger, func(l *store.AdmissionLedger, candidateID admission.CandidateID, link admission.EffectLink) (admission.Candidate, error) {
				terminateCalls++
				return terminateExisting(l, candidateID, link)
			})
			if turnErr := o.do(o.turn); !errors.Is(turnErr, failure) {
				t.Fatalf("missing linked write failure: %v", turnErr)
			}
			wantWrites := 1
			if delayed {
				if inspectErr := o.do(func() error {
					if len(o.finishes) != 1 {
						t.Errorf("failed writes retained %d outcomes, want 1", len(o.finishes))
					}
					return nil
				}); inspectErr != nil {
					t.Fatal(inspectErr)
				}
				if c := candidate(t, o, id); c.State != admission.StateExecuting {
					t.Fatalf("both failed writes lost the executing attempt: %+v", c)
				}
				if turnErr := o.do(o.turn); !errors.Is(turnErr, failure) {
					t.Fatalf("pending retry lost linked write failure: %v", turnErr)
				}
				wantWrites++
			}
			if inspectErr := o.do(func() error {
				if len(o.finishes) != 0 || linkedCalls != wantWrites || plainCalls != wantWrites || terminateCalls != 0 {
					t.Errorf("fallback pending=%d linked=%d plain=%d terminate=%d; want 0, %d, %d, 0", len(o.finishes), linkedCalls, plainCalls, terminateCalls, wantWrites, wantWrites)
				}
				return nil
			}); inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 1 || c.Link != (admission.EffectLink{}) || attemptOf(t, o, c).State != admission.StateFailed {
				t.Fatalf("plain fallback did not persist the failure: %+v", c)
			}
			mono.advance(admission.RetryBackoff(1) + time.Second)
			f.host.advance(admission.RetryBackoff(1) + time.Second)
			if turnErr := o.do(o.turn); turnErr != nil {
				t.Fatalf("stale pending outcome blocked the next turn: %v", turnErr)
			}
			if inspectErr := o.do(func() error {
				if len(o.finishes) != 0 || linkedCalls != wantWrites || plainCalls != wantWrites || terminateCalls != 1 {
					t.Errorf("next turn pending=%d linked=%d plain=%d terminate=%d; want 0, %d, %d, 1", len(o.finishes), linkedCalls, plainCalls, terminateCalls, wantWrites, wantWrites)
				}
				return nil
			}); inspectErr != nil {
				t.Fatal(inspectErr)
			}
			wantLink := admission.EffectLink{Effect: fakeExisting.ID, ExpiresAt: fakeExisting.ExpiresAt}
			if c := candidate(t, o, id); c.State != admission.StateRefused || c.Attempts != 1 || c.Link != wantLink {
				t.Fatalf("check-time termination after fallback = %+v", c)
			}
			if st := ledgerStatus(t, o); st.Ceiling.General.Used != 1 || st.Unresolved.Running != 0 {
				t.Fatalf("fallback retried an action or retained its intent: %+v", st)
			}
			if _, applies := blocks.calls(); len(applies) != 1 {
				t.Fatalf("fallback dispatched %d batches, want 1", len(applies))
			}
		})
	}
}
