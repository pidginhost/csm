package admissionowner

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

func completedVerdict(t *testing.T) (*Owner, *verdictJob, verdictResult, *fakeMono) {
	t.Helper()
	mono := &fakeMono{now: time.Unix(1000, 0)}
	previous := monoNow
	monoNow = mono.read
	t.Cleanup(func() { monoNow = previous })
	o := &Owner{policy: validPolicy(1)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	j := &verdictJob{
		id: 1, key: jobKey{Candidate: "cand_00112233445566778899aabbccddeeff", Attempt: 1, Epoch: 1},
		ip: "192.0.2.10", reason: "CSM auto-block: ssh_brute", ctx: ctx, cancel: cancel,
		timeout: time.Second, ask: newFakePanel("allow").ask,
	}
	o.verdicts.pending = map[admission.CandidateID]*verdictJob{j.key.Candidate: j}
	s := &verdictStage{ctx: ctx, tally: &o.verdicts.tally}
	return o, j, s.run(j), mono
}

// Call accounting belongs to HTTP completion, not to the owner's later
// receipt. Duplicate deliveries cannot count another call or underflow.
func TestVerdictCompletionCountsOnceBeforeReceipt(t *testing.T) {
	o, _, r, _ := completedVerdict(t)
	for i := range 3 {
		s := o.verdictStatus()
		if s.Asked != 1 || s.InFlight != 0 || s.ResponsesAllow != 1 || s.Failed != 0 || s.Cancelled != 0 {
			t.Fatalf("after %d receipts: %+v", i, s)
		}
		o.receiveVerdict(r)
	}
}

// An answer delayed in the result channel has already spent that part of
// its lifetime. Receiving it at the deadline must not renew an allow.
func TestVerdictExpiresWhileAwaitingReceipt(t *testing.T) {
	o, _, r, mono := completedVerdict(t)
	mono.advance(verdictTTL)
	o.receiveVerdict(r)
	if s := o.verdictStatus(); s.Ready != 0 || s.Pending != 0 || s.Discarded != 1 || !o.scheduleDue {
		t.Fatalf("expired completion retained or failed to wake its candidate: %+v", s)
	}
}

// A matching job number alone cannot consume pending work. Every pinned
// field must match, and rejection must leave the real completion usable.
func TestVerdictReceiptChecksTheWholeIdentity(t *testing.T) {
	for name, change := range map[string]func(*verdictResult){
		"attempt": func(r *verdictResult) { r.Key.Attempt++ },
		"epoch":   func(r *verdictResult) { r.Key.Epoch++ },
		"target":  func(r *verdictResult) { r.IP = "192.0.2.11" },
		"reason":  func(r *verdictResult) { r.Reason = "CSM auto-block: other" },
	} {
		t.Run(name, func(t *testing.T) {
			o, j, r, _ := completedVerdict(t)
			wrong := r
			change(&wrong)
			o.receiveVerdict(wrong)
			if o.verdicts.pending[j.key.Candidate] != j || len(o.verdicts.ready) != 0 {
				t.Fatal("mismatched result consumed the pending job")
			}
			o.receiveVerdict(r)
			if s := o.verdictStatus(); s.Pending != 0 || s.Ready != 1 || s.ResponsesAllow != 1 || s.InFlight != 0 {
				t.Fatalf("valid completion after a mismatch: %+v", s)
			}
		})
	}
}

func TestVerdictStopCountsUnusedReadyAnswers(t *testing.T) {
	o, _, r, _ := completedVerdict(t)
	o.receiveVerdict(r)
	o.stopVerdicts()
	if s := o.verdictStatus(); s.Ready != 0 || s.Discarded != 1 || s.ResponsesAllow != 1 {
		t.Fatalf("stop accounting: %+v", s)
	}
}
