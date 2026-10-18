package reconcile

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func learningDesired() Desired {
	d := desired(true)
	d.Settings.Learning, d.Settings.LearningDir = true, antispam.DefaultLearningDir
	return d
}

// After a learning check failure, learning stays off until its
// configuration changes: no reload loop with unchanged failing config.
func TestPassHoldsLearningAfterCheck(t *testing.T) {
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install},
		result: antispam.Result{Operation: antispam.OpApply, FailedStep: antispam.LearningCheckStep,
			Rollback: antispam.RollbackVerified, Error: "rspamd's loaded learning configuration could not be verified"},
	}
	r := h.reconciler()
	r.Learning = NewLearningState()
	d := learningDesired()
	r.Pass(context.Background(), d)
	if len(h.requests) != 1 || h.requests[0].Learning == nil || !*h.requests[0].Learning {
		t.Fatalf("first pass requests = %+v, want learning", h.requests)
	}
	h.result = antispam.Result{Operation: antispam.OpApply, OK: true}
	out := r.Pass(context.Background(), d)
	if len(h.requests) != 2 || h.requests[1].Learning != nil {
		t.Fatalf("second pass request = %+v, want core only", h.requests[1])
	}
	held := false
	for _, p := range out.LearningProblems {
		held = held || p.Key == antispam.ReasonApplyFailed
	}
	if !held {
		t.Fatalf("held learning reported no apply_failed problem: %+v", out.LearningProblems)
	}
	// A changed learning configuration lifts the hold.
	d.Settings.LearningDir = "/var/lib/csm/antispam/learning2"
	r.Pass(context.Background(), d)
	if len(h.requests) != 3 || h.requests[2].Learning == nil {
		t.Fatalf("changed configuration still held: %+v", h.requests[2])
	}
}

func TestLearningStateNilIsInert(t *testing.T) {
	var st *LearningState
	st.hold("g")
	if st.held("g") {
		t.Fatal("nil state held learning")
	}
}
