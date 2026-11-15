package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// refusedCounts are the block refusals the comparison counted, by reason.
func refusedCounts(o *Owner) map[admission.Reason]uint64 {
	o.compare.mu.Lock()
	defer o.compare.mu.Unlock()
	out := map[admission.Reason]uint64{}
	for k, n := range o.compare.counts {
		if k.kind == admission.KindBlockIP && k.decision == decisionRefused {
			out[k.reason] += n
		}
	}
	return out
}

// A live pick that ends refused is counted in the hourly comparison, as a
// refused preview is: at the engine's check before any reservation (a
// protected or allowed address, an invalid, expired or unsupported member)
// and at the reservation itself (work that aged out meanwhile). A pick the
// engine only defers and one an existing block answers are not refusals
// and count nothing.
func TestOwnerCountsLiveRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refusal firewall.BlockRefusal
		reserve error
		reason  admission.Reason
		want    uint64
	}{
		{"protected address", firewall.BlockRefusedProtected, nil, admission.ReasonProtected, 1},
		{"allowed address", firewall.BlockRefusedAllowed, nil, admission.ReasonProtected, 1},
		{"invalid member", firewall.BlockRefusedInvalid, nil, admission.ReasonInvalid, 1},
		{"expired member", firewall.BlockRefusedExpired, nil, admission.ReasonStale, 1},
		{"unsupported containment", firewall.BlockRefusedUnsupported, nil, admission.ReasonUnsupportedContainment, 1},
		{"aged out at the reservation", "", &admission.Error{Reason: admission.ReasonStale, Detail: "candidate aged out of the queue"}, admission.ReasonStale, 1},
		{"full set", firewall.BlockRefusedFull, nil, admission.ReasonSetFull, 0},
		{"existing block", firewall.BlockRefusedExisting, nil, admission.ReasonExistingEffect, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			if tc.refusal != "" {
				blocks.refuse["192.0.2.10"] = tc.refusal
			}
			o := f.start(executeOptions(f, blocks))
			if tc.reserve != nil {
				setOwnerHook(t, o, &reserveLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Lane, time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
					return admission.Candidate{}, admission.AttemptRecord{}, false, tc.reserve
				})
			}
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			turn(t, o)
			c := candidate(t, o, id)
			if c.Reason != tc.reason || c.Attempts != 0 || (tc.want == 1 || tc.refusal == firewall.BlockRefusedExisting) != c.State.Terminal() {
				t.Fatalf("pick = state %s reason %s attempts %d, want reason %s", c.State, c.Reason, c.Attempts, tc.reason)
			}
			counts := refusedCounts(o)
			var total uint64
			for _, n := range counts {
				total += n
			}
			if counts[tc.reason] != tc.want || total != tc.want {
				t.Fatalf("comparison counted refusals %v, want %d as %s", counts, tc.want, tc.reason)
			}
			if _, applies := blocks.calls(); len(applies) != 0 {
				t.Fatalf("a refused pick was applied: %v", applies)
			}
		})
	}
}

// A refusal that cannot be written counts nothing: the pick is still
// queued and the next turn ends and counts it once.
func TestOwnerCountsALiveRefusalOnlyOnceItCommits(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.10"] = firewall.BlockRefusedProtected
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	terminate := terminateLedger
	setOwnerHook(t, o, &terminateLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Reason) (admission.Candidate, error) {
		return admission.Candidate{}, errors.New("fixture write failure")
	})
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err == nil {
		t.Fatal("a failed ending did not fail the turn")
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || len(refusedCounts(o)) != 0 {
		t.Fatalf("after a failed ending: state %s, refusals %v", c.State, refusedCounts(o))
	}
	setOwnerHook(t, o, &terminateLedger, terminate)
	for range 2 {
		mono.advance(time.Minute)
		turn(t, o)
	}
	if n := refusedCounts(o)[admission.ReasonProtected]; n != 1 {
		t.Fatalf("comparison counted %d protected refusals over two turns, want 1", n)
	}
}

// A refusal that committed stays counted when a later pick of the same
// turn fails to end: the failed turn counts the one that committed and no
// more, and the retry ends and counts only the pick still queued.
func TestOwnerCountsCommittedRefusalAcrossLaterFailure(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	addrs := []string{"192.0.2.10", "192.0.2.11"}
	for _, addr := range addrs {
		blocks.refuse[addr] = firewall.BlockRefusedProtected
	}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	terminate := terminateLedger
	calls := 0
	setOwnerHook(t, o, &terminateLedger, func(l *store.AdmissionLedger, id admission.CandidateID, r admission.Reason) (admission.Candidate, error) {
		if calls++; calls == 2 {
			return admission.Candidate{}, errors.New("fixture write failure")
		}
		return terminate(l, id, r)
	})
	var ids []admission.CandidateID
	for _, addr := range addrs {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		ids = append(ids, id)
	}
	states := func() (terminal, queued int) {
		for _, id := range ids {
			switch c := candidate(t, o, id); {
			case c.Attempts != 0:
				t.Fatalf("a refused pick made an attempt: %+v", c)
			case c.State.Terminal():
				terminal++
			case c.State == admission.StateQueued:
				queued++
			}
		}
		return terminal, queued
	}
	if err := o.do(o.turn); err == nil {
		t.Fatal("the failed ending did not fail the turn")
	}
	if terminal, queued := states(); terminal != 1 || queued != 1 || refusedCounts(o)[admission.ReasonProtected] != 1 {
		t.Fatalf("after the failed turn: %d terminal, %d queued, refusals %v; want one of each", terminal, queued, refusedCounts(o))
	}
	setOwnerHook(t, o, &terminateLedger, terminate)
	for range 2 {
		mono.advance(time.Minute)
		turn(t, o)
	}
	if terminal, _ := states(); terminal != 2 || refusedCounts(o)[admission.ReasonProtected] != 2 || len(refusedCounts(o)) != 1 {
		t.Fatalf("after the retry: %d terminal, refusals %v; want two protected refusals", terminal, refusedCounts(o))
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("a refused pick was applied: %v", applies)
	}
}
