package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

func TestOwnerExistingEffectWriteFailuresConverge(t *testing.T) {
	for _, mode := range []string{"finish", "finish_committed", "finish_proof_gone", "terminate", "terminate_committed", "restart", "proof_gone"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			failure := errors.New("fixture outcome write failure")
			finish, terminate := finishLedger, terminateLedger
			failed := false
			setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
				if (mode == "finish" || mode == "finish_committed" || mode == "finish_proof_gone") && !failed {
					failed = true
					if mode == "finish_committed" {
						if _, _, err := finish(l, id, d); err != nil {
							return admission.Candidate{}, admission.AttemptRecord{}, err
						}
					}
					return admission.Candidate{}, admission.AttemptRecord{}, failure
				}
				return finish(l, id, d)
			})
			setOwnerHook(t, o, &terminateLedger, func(l *store.AdmissionLedger, id admission.CandidateID, r admission.Reason) (admission.Candidate, error) {
				if mode != "finish" && mode != "finish_committed" && mode != "finish_proof_gone" && !failed {
					failed = true
					if mode == "terminate_committed" {
						if _, err := terminate(l, id, r); err != nil {
							return admission.Candidate{}, err
						}
					}
					return admission.Candidate{}, failure
				}
				return terminate(l, id, r)
			})
			if err := o.do(o.turn); !errors.Is(err, failure) {
				t.Fatalf("missing injected write failure: %v", err)
			}
			proofGone := mode == "proof_gone" || mode == "finish_proof_gone"
			if proofGone {
				blocks.mu.Lock()
				delete(blocks.results, "192.0.2.10")
				delete(blocks.refuse, "192.0.2.10")
				blocks.mu.Unlock()
			} else {
				blocks.mu.Lock()
				blocks.refuse["192.0.2.10"] = firewall.BlockRefusedExisting
				blocks.mu.Unlock()
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
			if mode == "finish_proof_gone" {
				// The retried finish may let the next attempt run in the same
				// turn; it must never end the pick on the stale apply proof.
				c := candidate(t, o, id)
				if c.State == admission.StateRefused || c.Reason == admission.ReasonExistingEffect {
					t.Fatalf("stale apply proof ended a delayed finish: %+v", c)
				}
				mono.advance(admission.RetryBackoff(1) + time.Second)
				f.host.advance(admission.RetryBackoff(1) + time.Second)
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
			}
			c := candidate(t, o, id)
			wantState, wantAttempts, wantDisposition := admission.StateRefused, uint32(1), admission.DispositionFailed
			if proofGone {
				wantState, wantAttempts, wantDisposition = admission.StateVerified, 2, admission.DispositionApplied
			}
			if c.State != wantState || c.Attempts != wantAttempts || attemptOf(t, o, c).Disposition != wantDisposition {
				t.Fatalf("write recovery: state=%s attempts=%d", c.State, c.Attempts)
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
			if reopened := candidate(t, o, id); reopened.State != wantState || reopened.Attempts != wantAttempts {
				t.Fatalf("reopened ending changed: %+v", reopened)
			}
		})
	}
}

func TestOwnerExistingEffectRequiresProofAfterFinish(t *testing.T) {
	for _, mode := range []string{"gone", "pending", "expired", "error", "short", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			finish := finishLedger
			changed := false
			setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
				c, a, err := finish(l, id, d)
				if err == nil && !changed {
					changed = true
					blocks.set(func(b *fakeBlocks) {
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
					})
				}
				return c, a, err
			})
			err := o.do(o.turn)
			wantError := mode == "error" || mode == "short" || mode == "unavailable"
			if (err != nil) != wantError {
				t.Fatalf("proof error=%v, want error=%t", err, wantError)
			}
			if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 1 || c.Reason == admission.ReasonExistingEffect {
				t.Fatalf("unproven finish ended candidate: %+v", c)
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
	finish := finishLedger
	failure := errors.New("fixture committed finish acknowledgement lost")
	failed := false
	setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
		c, a, err := finish(l, id, d)
		if err == nil && !failed {
			failed = true
			return admission.Candidate{}, admission.AttemptRecord{}, failure
		}
		return c, a, err
	})
	if err := o.do(o.turn); !errors.Is(err, failure) {
		t.Fatalf("missing committed-finish failure: %v", err)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	o.halt(false)
	o = f.start(executeOptions(f, blocks))
	c := candidate(t, o, id)
	if c.State != admission.StateFailed || c.Attempts != admission.MaxAttempts || c.Reason != 0 || attemptOf(t, o, c).Disposition != admission.DispositionFailed {
		t.Fatalf("last finish could not reopen: %+v", c)
	}
	if st := ledgerStatus(t, o); st.Ceiling.General.Used != admission.MaxAttempts || st.Unresolved.Running != 0 {
		t.Fatalf("last finish changed charge or retained intent: %+v", st)
	}
	if _, applies := blocks.calls(); len(applies) != admission.MaxAttempts {
		t.Fatalf("last finish dispatched again: %d", len(applies))
	}
}
