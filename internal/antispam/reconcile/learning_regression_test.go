package reconcile

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/eximlock"
)

func TestPassLearningHoldsResetOnDisable(t *testing.T) {
	for _, disableCore := range []bool{false, true} {
		for _, roundcube := range []bool{false, true} {
			h := newLearningHost(antispam.Assessment{Action: antispam.Install})
			r := h.reconciler()
			d := learningDesired()
			s := d.Settings
			s.LearningKeys = syntheticKeys()
			if roundcube {
				r.Learning.holdRoundcube(learningGeneration(s), "include overridden")
			} else {
				r.Learning.hold(learningGeneration(s))
			}
			held := r.Pass(context.Background(), d)
			if len(learningFindings(held)) != 1 {
				t.Fatalf("hold was not active before disable: %+v", held)
			}
			off := d
			if disableCore {
				off.Enabled = false
			} else {
				off.Settings.Learning = false
			}
			h.assessment.Action = antispam.Keep
			r.Pass(context.Background(), off)
			h.assessment.Action = antispam.Install
			out := r.Pass(context.Background(), d)
			if len(learningFindings(out)) != 0 || !out.LearningGate.Install || !out.LearningGate.Roundcube {
				t.Errorf("disableCore=%t roundcube=%t retained hold: %+v", disableCore, roundcube, out)
			}
		}
	}
}

func TestPassRoundcubeHoldSurvivesPrerequisiteFailure(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.result.Roundcube = antispam.RoundcubeUnavailable + "include overridden"
	r := h.reconciler()
	d := learningDesired()
	r.Pass(context.Background(), d)
	h.result.Roundcube = ""
	h.resolve = func(s antispam.Settings, _ antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
		s.Learning, s.Roundcube = false, false
		return s, antispam.LearningGate{}, []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonUnsafe}}
	}
	r.Pass(context.Background(), d)
	h.resolve = nil
	out := r.Pass(context.Background(), d)
	if len(h.requests) != 3 || h.requests[2].Roundcube != nil || out.LearningGate.Roundcube {
		t.Fatalf("unchanged failed include retried: requests=%+v gate=%+v", h.requests, out.LearningGate)
	}
	if _, ok := learningFindings(out)[antispam.ReasonRoundcube]; !ok {
		t.Fatal("recovered prerequisites lost the Roundcube warning")
	}
}

func TestPassLearningWorkerResultsSettleImmediately(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result antispam.Result
		reason string
		gate   antispam.LearningGate
	}{
		{"learning check", antispam.Result{Operation: antispam.OpApply, FailedStep: antispam.LearningCheckStep, Rollback: antispam.RollbackVerified}, antispam.ReasonApplyFailed, antispam.LearningGate{}},
		{"Roundcube check", antispam.Result{Operation: antispam.OpApply, OK: true, Generation: "g", Roundcube: antispam.RoundcubeUnavailable + "include overridden"}, antispam.ReasonRoundcube, antispam.LearningGate{Install: true, Publish: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLearningHost(antispam.Assessment{Action: antispam.Install})
			h.result = tc.result
			out := h.reconciler().Pass(context.Background(), learningDesired())
			findings := learningFindings(out)
			f, ok := findings[tc.reason]
			if !ok || len(findings) != 1 || f.Severity != alert.Warning || f.Timestamp != testNow ||
				len(out.LearningProblems) != 1 || out.LearningProblems[0].Key != tc.reason ||
				!slices.Contains(out.Checks, CheckLearning) || out.LearningGate != tc.gate {
				t.Fatalf("worker result not reflected in the completed pass: %+v", out)
			}
		})
	}
}

func TestPassLearningPublicationRequiresCurrentIntegration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		assessment antispam.Assessment
		observe    bool
		result     antispam.Result
		err        error
		publish    bool
	}{
		{name: "current", assessment: antispam.Assessment{Action: antispam.Keep, Installed: true}, publish: true},
		{name: "absent", assessment: antispam.Assessment{Action: antispam.Keep}},
		{name: "blocked", assessment: antispam.Assessment{Action: antispam.Keep, Installed: true, Problems: []antispam.Problem{{Code: "probe", Severity: antispam.Temporary}}}},
		{name: "observe", assessment: antispam.Assessment{Action: antispam.Keep, Installed: true}, observe: true},
		{name: "removed", assessment: antispam.Assessment{Action: antispam.Uninstall, Installed: true}, result: antispam.Result{Operation: antispam.OpRemove, OK: true}},
		{name: "applied", assessment: antispam.Assessment{Action: antispam.Install}, result: antispam.Result{Operation: antispam.OpApply, OK: true, Generation: "g"}, publish: true},
		{name: "failed", assessment: antispam.Assessment{Action: antispam.Install}, result: antispam.Result{Operation: antispam.OpApply, FailedStep: "reload", Rollback: antispam.RollbackVerified}},
		{name: "busy", assessment: antispam.Assessment{Action: antispam.Install}, result: antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone}},
		{name: "unknown", assessment: antispam.Assessment{Action: antispam.Install}, err: errors.New("worker unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLearningHost(tc.assessment)
			h.result, h.err = tc.result, tc.err
			d := learningDesired()
			d.Observe = tc.observe
			out := h.reconciler().Pass(context.Background(), d)
			if out.LearningGate.Publish != tc.publish {
				t.Fatalf("publish=%t, want %t", out.LearningGate.Publish, tc.publish)
			}
		})
	}
}

func TestPassRemovalIncompleteRequiresSuccessfulRemoval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  antispam.Action
		observe bool
		result  antispam.Result
		readErr error
		want    bool
	}{
		{name: "left in place", action: antispam.Keep, want: true},
		{name: "observe apply", action: antispam.Install, observe: true, want: true},
		{name: "observe remove", action: antispam.Uninstall, observe: true, want: true},
		{name: "failed apply", action: antispam.Install, result: antispam.Result{FailedStep: "reload", Rollback: antispam.RollbackVerified}, want: true},
		{name: "successful apply", action: antispam.Install, result: antispam.Result{OK: true, Generation: "g"}},
		{name: "successful removal", action: antispam.Uninstall, result: antispam.Result{OK: true}},
		{name: "busy", action: antispam.Install, result: antispam.Result{Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone}},
		{name: "failed configdump", action: antispam.Keep, readErr: errors.New("configdump failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLearningHost(antispam.Assessment{Action: tc.action, Installed: true})
			h.result = tc.result
			r := h.reconciler()
			r.Collect = func(context.Context, string) antispam.HostFacts {
				f := goodFeedFacts()
				f.RspamdConfig = antispam.CommandResult{Stdout: `{"fuzzy_check":{"rule":{"csm":{}}}}`, Err: tc.readErr}
				return f
			}
			d := desired(true)
			d.Observe = tc.observe
			out := r.Pass(context.Background(), d)
			_, got := learningFindings(out)[antispam.ReasonRemovalIncomplete]
			if got != tc.want {
				t.Fatalf("removal warning=%t, want %t: %+v", got, tc.want, out)
			}
		})
	}
}

func TestPassLearningInvalidationDoesNotSettle(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, err := range []error{eximlock.ErrBusy, errors.New("state unavailable")} {
			h := newLearningHost(antispam.Assessment{})
			r := h.reconciler()
			r.Invalidate = func(context.Context) error { return err }
			out := r.Pass(context.Background(), desired(enabled))
			if slices.Contains(out.Checks, CheckLearning) {
				t.Errorf("enabled=%t err=%v settled an incomplete pass", enabled, err)
			}
		}
	}
}

func TestPassBusyDoesNotPublishLearningFindings(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.result = antispam.Result{Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone}
	h.resolve = func(s antispam.Settings, _ antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
		s.Learning = false
		return s, antispam.LearningGate{}, []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonUnsafe}}
	}
	out := h.reconciler().Pass(context.Background(), learningDesired())
	if len(learningFindings(out)) != 0 || len(out.LearningProblems) != 0 || slices.Contains(out.Checks, CheckLearning) {
		t.Fatalf("busy pass published unsettled learning findings: %+v", out)
	}
}

func TestPassCanceledLearningDoesNotSettle(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.resolve = func(s antispam.Settings, _ antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
		return s, antispam.LearningGate{Install: true}, []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonBackendUnavailable}}
	}
	r := h.reconciler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Run = func(context.Context, antispam.Request) (antispam.Result, error) {
		cancel()
		return antispam.Result{}, ctx.Err()
	}
	out := r.Pass(ctx, learningDesired())
	if !errors.Is(out.Err, context.Canceled) || len(out.Findings) != 0 || len(out.Checks) != 0 ||
		len(out.LearningProblems) != 0 || out.LearningGate != (antispam.LearningGate{}) {
		t.Fatalf("canceled pass published learning state: %+v", out)
	}
}
