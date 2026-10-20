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
			setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition, lead time.Duration) (admission.Candidate, admission.AttemptRecord, error) {
				if failFinish {
					failFinish = false
					return admission.Candidate{}, admission.AttemptRecord{}, failure
				}
				return finish(l, id, d, lead)
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
	for _, mode := range []string{"gone", "unnamed", "pending", "expired", "error", "short", "unavailable"} {
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
				case "unnamed":
					b.refuse["192.0.2.10"] = firewall.BlockRefusedExisting
					b.existing["192.0.2.10"] = firewall.ExistingBlock{}
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
// write keeps failing or refusing. A failed fallback still fails the turn.
// Later turns must use the ordinary check-time path.
func TestOwnerExistingEffectFallbackClearsPending(t *testing.T) {
	for _, tc := range []struct {
		name             string
		delayed, refused bool
	}{
		{name: "immediate"},
		{name: "pending_retry", delayed: true},
		{name: "refused_pending_retry", delayed: true, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
				if tc.refused {
					return admission.Candidate{}, admission.AttemptRecord{}, &admission.Error{Reason: admission.ReasonStorageShare}
				}
				return admission.Candidate{}, admission.AttemptRecord{}, failure
			})
			setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, action admission.ActionID, d admission.Disposition, lead time.Duration) (admission.Candidate, admission.AttemptRecord, error) {
				plainCalls++
				if tc.delayed && plainCalls == 1 {
					return admission.Candidate{}, admission.AttemptRecord{}, failure
				}
				return finish(l, action, d, lead)
			})
			setOwnerHook(t, o, &terminateExistingLedger, func(l *store.AdmissionLedger, candidateID admission.CandidateID, link admission.EffectLink) (admission.Candidate, error) {
				terminateCalls++
				return terminateExisting(l, candidateID, link)
			})
			if turnErr := o.do(o.turn); !errors.Is(turnErr, failure) {
				t.Fatalf("missing linked write failure: %v", turnErr)
			}
			wantWrites := 1
			if tc.delayed {
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
				turnErr := o.do(o.turn)
				if tc.refused {
					if turnErr != nil {
						t.Fatalf("refused link failed a successful fallback: %v", turnErr)
					}
				} else if !errors.Is(turnErr, failure) {
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

// A link the ledger refuses (no history budget for it, or no name to
// record) leaves that pick queued, with a deferral reason when it has one,
// and the rest of the batch runs; the turn does not fail. At apply time a
// refused linked ending falls back to the plain failure without failing
// the turn either.
func TestOwnerRefusedLinkDefersOnlyItsPick(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		retry      bool
	}{
		{name: "budget", mode: "budget"},
		{name: "unnamed", mode: "unnamed"},
		{name: "apply", mode: "apply"},
		{name: "retry_budget", mode: "budget", retry: true},
		{name: "retry_unnamed", mode: "unnamed", retry: true},
		{name: "retry_apply", mode: "apply", retry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			held, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
			priorAttempts := uint32(0)
			if tc.retry {
				blocks.set(func(b *fakeBlocks) {
					b.results["192.0.2.11"] = firewall.BlockResult{Effect: firewall.BlockFailed}
				})
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				if c := candidate(t, o, held); c.State != admission.StateQueued || c.Attempts != 1 || attemptOf(t, o, c).State != admission.StateFailed {
					t.Fatalf("retry was not queued after a failed attempt: %+v", c)
				}
				priorAttempts = 1
				mono.advance(admission.RetryBackoff(1) + time.Second)
				f.host.advance(admission.RetryBackoff(1) + time.Second)
				if err := o.do(o.tick); err != nil {
					t.Fatal(err)
				}
			}
			before := candidate(t, o, held)
			blocks.set(func(b *fakeBlocks) {
				delete(b.results, "192.0.2.11")
				switch tc.mode {
				case "apply":
					b.results["192.0.2.11"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
				case "unnamed":
					b.refuse["192.0.2.11"] = firewall.BlockRefusedExisting
					b.existing["192.0.2.11"] = firewall.ExistingBlock{}
				default:
					b.refuse["192.0.2.11"] = firewall.BlockRefusedExisting
				}
			})
			other, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			budget := &admission.Error{Reason: admission.ReasonStorageShare, Detail: "fixture lane has no history budget for the link"}
			refuseLink := true
			terminateExisting, finishExisting := terminateExistingLedger, finishExistingLedger
			setOwnerHook(t, o, &terminateExistingLedger, func(l *store.AdmissionLedger, id admission.CandidateID, link admission.EffectLink) (admission.Candidate, error) {
				if tc.mode == "budget" && refuseLink {
					return admission.Candidate{}, budget
				}
				return terminateExisting(l, id, link)
			})
			setOwnerHook(t, o, &finishExistingLedger, func(l *store.AdmissionLedger, id admission.ActionID, link admission.EffectLink) (admission.Candidate, admission.AttemptRecord, error) {
				if tc.mode == "apply" {
					return admission.Candidate{}, admission.AttemptRecord{}, budget
				}
				return finishExisting(l, id, link)
			})
			if err := o.do(o.turn); err != nil {
				t.Fatalf("a refused link failed the turn: %v", err)
			}
			checks, applies := blocks.calls()
			wantChecks, wantMembers := int(priorAttempts)+1, 1
			if tc.mode == "apply" {
				wantChecks++ // The apply-time refusal needs a fresh proof.
				wantMembers++
			}
			if len(checks) != wantChecks || len(checks[priorAttempts]) != 2 || checks[priorAttempts][0].IP != "192.0.2.11" {
				t.Fatalf("the refused pick was not checked first: %+v", checks)
			}
			if len(applies) != int(priorAttempts)+1 || len(applies[priorAttempts]) != wantMembers {
				t.Fatalf("refused link dispatched unexpected work: %+v", applies)
			}
			if c := candidate(t, o, other); c.State != admission.StateVerified || c.Attempts != 1 {
				t.Fatalf("the rest of the batch did not run: %+v", c)
			}
			c := candidate(t, o, held)
			wantAttempts, wantReason := priorAttempts, admission.Reason(0)
			switch tc.mode {
			case "budget":
				wantReason = admission.ReasonStorageShare
			case "apply":
				wantAttempts++
			}
			if c.State != admission.StateQueued || c.Attempts != wantAttempts || c.Reason != wantReason || c.Link != (admission.EffectLink{}) {
				t.Fatalf("refused link = %+v, want queued with %d attempts and reason %s", c, wantAttempts, wantReason)
			}
			if wantAttempts > 0 && attemptOf(t, o, c).State != admission.StateFailed {
				t.Fatalf("refused apply-time link left the attempt %+v", attemptOf(t, o, c))
			}
			if tc.mode != "apply" && (!c.NotBefore.Equal(before.NotBefore) || !c.ExpiresAt.Equal(before.ExpiresAt)) {
				t.Fatalf("refused link changed retry deadlines: before=%+v after=%+v", before, c)
			}
			if st := ledgerStatus(t, o); st.Ceiling.General.Used != wantAttempts+1 || st.Unresolved.Running != 0 {
				t.Fatalf("refused link changed charges or retained an intent: %+v", st)
			}
			if err := o.do(func() error {
				if len(o.finishes) != 0 {
					t.Errorf("refused link retained %d pending outcomes", len(o.finishes))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if tc.mode != "apply" {
				// With no other picks left, a persistent refusal must still
				// return after one check, without reserving another attempt.
				mono.advance(batchEvery)
				f.host.advance(batchEvery)
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				wantChecks++
				if again := candidate(t, o, held); again.State != admission.StateQueued || again.Attempts != wantAttempts || again.Reason != wantReason {
					t.Fatalf("persistent refusal changed the queued pick: %+v", again)
				}
				if checks, laterApplies := blocks.calls(); len(checks) != wantChecks || len(laterApplies) != len(applies) {
					t.Fatalf("persistent refusal repeated work: checks=%d applies=%d", len(checks), len(laterApplies))
				}
			}
			if err := o.do(func() error { refuseLink = false; return nil }); err != nil {
				t.Fatal(err)
			}
			blocks.set(func(b *fakeBlocks) { delete(b.existing, "192.0.2.11") })
			mono.advance(admission.RetryBackoff(wantAttempts) + batchEvery)
			f.host.advance(admission.RetryBackoff(wantAttempts) + batchEvery)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			wantLink := admission.EffectLink{Effect: fakeExisting.ID, ExpiresAt: fakeExisting.ExpiresAt}
			if c := candidate(t, o, held); c.State != admission.StateRefused || c.Reason != admission.ReasonExistingEffect || c.Attempts != wantAttempts || c.Link != wantLink {
				t.Fatalf("refused link did not converge after recovery: %+v", c)
			}
			if checks, laterApplies := blocks.calls(); len(checks) != wantChecks+1 || len(laterApplies) != len(applies) {
				t.Fatalf("link recovery repeated work: checks=%d applies=%d", len(checks), len(laterApplies))
			}
			if st := ledgerStatus(t, o); st.Ceiling.General.Used != wantAttempts+1 || st.Unresolved.Running != 0 {
				t.Fatalf("link recovery changed charges or retained an intent: %+v", st)
			}
		})
	}
}

// A write failure is not a refused link: later picks stay untouched and
// the turn reports the storage error.
func TestOwnerExistingLinkWriteFailureStopsBatch(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.11"] = firewall.BlockRefusedExisting
	o := f.start(executeOptions(f, blocks))
	held, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	other, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	failure := errors.New("fixture linked ending write failure")
	setOwnerHook(t, o, &terminateExistingLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.EffectLink) (admission.Candidate, error) {
		return admission.Candidate{}, failure
	})
	if err := o.do(o.turn); !errors.Is(err, failure) {
		t.Fatalf("missing linked write failure: %v", err)
	}
	if checks, applies := blocks.calls(); len(checks) != 1 || len(checks[0]) != 2 || checks[0][0].IP != "192.0.2.11" || len(applies) != 0 {
		t.Fatalf("write failure did not stop the batch: checks=%+v applies=%+v", checks, applies)
	}
	for _, id := range []admission.CandidateID{held, other} {
		if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 0 || c.Reason != 0 || c.Link != (admission.EffectLink{}) {
			t.Fatalf("write failure changed the queued pick: %+v", c)
		}
	}
	if st := ledgerStatus(t, o); st.Ceiling.General.Used != 0 || st.Unresolved.Running != 0 {
		t.Fatalf("write failure charged or started an attempt: %+v", st)
	}
}
