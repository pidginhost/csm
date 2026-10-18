package reconcile

import (
	"context"
	"strings"
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

// An include that did not take effect stays off, with learning on, until
// the learning configuration changes: no reinstall loop.
func TestPassHoldsRoundcubeAfterUnavailable(t *testing.T) {
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install},
		result: antispam.Result{Operation: antispam.OpApply, OK: true, Generation: "g",
			Roundcube: antispam.RoundcubeUnavailable + "Roundcube does not load the include's Junk folder"},
	}
	r := h.reconciler()
	r.Learning = NewLearningState()
	d := learningDesired()
	d.Settings.Roundcube = true
	r.Pass(context.Background(), d)
	if h.requests[0].Roundcube == nil || !*h.requests[0].Roundcube {
		t.Fatalf("first request = %+v, want Roundcube", h.requests[0])
	}
	h.result = antispam.Result{Operation: antispam.OpApply, OK: true, Generation: "g"}
	out := r.Pass(context.Background(), d)
	second := h.requests[1]
	if second.Roundcube != nil || second.Learning == nil || !*second.Learning {
		t.Fatalf("second request = %+v, want learning without Roundcube", second)
	}
	reported := false
	for _, p := range out.LearningProblems {
		reported = reported || p.Key == antispam.ReasonRoundcube
	}
	if !reported {
		t.Fatalf("problems = %+v", out.LearningProblems)
	}
}

func TestPassReportsLearningHoldWithoutRepeatedApplies(t *testing.T) {
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep, Installed: true}}
	r := h.reconciler()
	r.Learning = NewLearningState()
	d := learningDesired()
	r.Learning.hold(learningGeneration(d.Settings))
	for i := 0; i < 2; i++ {
		out := r.Pass(context.Background(), d)
		found := 0
		for _, f := range out.Findings {
			if f.Check == CheckPrecondition && strings.Contains(f.Details, "learning") {
				found++
			}
		}
		if found != 1 || len(h.requests) != 0 {
			t.Fatalf("held pass: findings=%+v requests=%d", out.Findings, len(h.requests))
		}
	}
}

func TestPassDisablingAntispamClearsLearningHold(t *testing.T) {
	h := &fakeHost{}
	r := h.reconciler()
	r.Learning = NewLearningState()
	d := learningDesired()
	r.Learning.hold(learningGeneration(d.Settings))
	d.Enabled = false
	r.Pass(context.Background(), d)
	d.Enabled = true
	if out := r.Pass(context.Background(), d); len(out.LearningProblems) != 0 {
		t.Fatal("disable and re-enable retained the old learning hold")
	}
}
