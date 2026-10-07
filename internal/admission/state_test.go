package admission

import "testing"

func TestStateLifecycle(t *testing.T) {
	allowed := map[State][]State{
		StateQueued:    {StateQueued, StateReserved, StateRefused, StateWithheld, StateDropped},
		StateReserved:  {StateExecuting, StateFailed, StateQueued, StateObserved},
		StateExecuting: {StateVerified, StateFailed, StateUnknown, StateQueued},
	}
	for from := State(0); from <= stateEnd; from++ {
		for to := State(0); to <= stateEnd; to++ {
			want := false
			for _, s := range allowed[from] {
				want = want || s == to
			}
			if CanTransition(from, to) != want {
				t.Errorf("CanTransition(%s, %s) = %v, want %v", from, to, !want, want)
			}
		}
	}
	for s := StateQueued; s < stateEnd; s++ {
		if s.Terminal() != (len(allowed[s]) == 0) {
			t.Errorf("%s.Terminal() = %v", s, s.Terminal())
		}
	}
	if State(0).Valid() || stateEnd.Valid() || State(0).Terminal() || stateEnd.Terminal() {
		t.Error("an out-of-range state is valid or terminal")
	}
}

// A terminal state carries exactly the disposition of its outcome, and a
// pre-attempt ending carries a reason from its own group.
func TestStateDispositionAndReason(t *testing.T) {
	for _, c := range []struct {
		s  State
		d  Disposition
		r  Reason
		ok bool
	}{
		{StateQueued, 0, 0, true},
		{StateQueued, 0, ReasonCeiling, true},
		{StateQueued, DispositionDeferred, ReasonCeiling, false},
		{StateQueued, 0, ReasonProtected, false},
		{StateReserved, 0, 0, true},
		{StateExecuting, 0, ReasonCeiling, false},
		{StateVerified, DispositionApplied, 0, true},
		{StateVerified, DispositionNarrowed, 0, true},
		{StateVerified, DispositionDryRun, 0, false},
		{StateVerified, DispositionApplied, ReasonStale, false},
		{StateFailed, DispositionFailed, 0, true},
		{StateUnknown, DispositionUnknown, 0, true},
		{StateUnknown, DispositionFailed, 0, false},
		{StateRefused, DispositionRefused, ReasonProtected, true},
		{StateRefused, DispositionRefused, 0, false},
		{StateRefused, DispositionRefused, ReasonCollateral, false},
		{StateWithheld, DispositionWithheld, ReasonCollateral, true},
		{StateDropped, DispositionDropped, ReasonQueueOverflow, true},
		{StateDropped, DispositionRefused, ReasonQueueOverflow, false},
		{StateObserved, DispositionObserve, 0, true},
		{StateObserved, DispositionApplied, 0, false},
		{StateObserved, DispositionObserve, ReasonStale, false},
		{StateVerified, DispositionObserve, 0, false},
	} {
		if got := terminalDisposition(c.s, c.d) && stateReason(c.s, c.r); got != c.ok {
			t.Errorf("state %s disposition %s reason %s: valid = %v, want %v", c.s, c.d, c.r, got, c.ok)
		}
	}
}
