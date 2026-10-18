package reconcile

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
)

const syntheticControllerPassword = "syntheticControllerSecret99"

func stockControllerFacts() antispam.HostFacts {
	f := goodFeedFacts()
	f.Controller = antispam.ControllerConfig{
		Present:      true,
		Listeners:    []antispam.ControllerListener{{Raw: "localhost:11334", HostPort: "localhost:11334"}},
		TrustEntries: []string{"127.0.0.1", "::1"},
		PasswordSet:  true,
	}
	return f
}

func passWithFacts(f antispam.HostFacts, action antispam.Action) Outcome {
	h := &fakeHost{assessment: antispam.Assessment{Action: action}}
	r := h.reconciler()
	r.Collect = func(context.Context, string) antispam.HostFacts { return f }
	return r.Pass(context.Background(), desired(true))
}

func controllerFindings(out Outcome) []alert.Finding {
	var got []alert.Finding
	for _, f := range out.Findings {
		if f.Check == CheckControllerOpen {
			got = append(got, f)
		}
	}
	return got
}

func TestPassReportsControllerOpen(t *testing.T) {
	out := passWithFacts(stockControllerFacts(), antispam.Keep)
	got := controllerFindings(out)
	if len(got) != 1 {
		t.Fatalf("controller findings = %+v, want one", got)
	}
	f := got[0]
	if f.Severity != alert.Warning || f.DedupKey != "localhost:11334" ||
		!strings.Contains(f.Message+f.Details, "localhost:11334") ||
		!strings.Contains(f.Details, "trusted address reachable by local processes") {
		t.Fatalf("finding = %+v", f)
	}
	if !slices.Contains(out.Checks, CheckControllerOpen) {
		t.Fatalf("Checks = %v, want %s settled", out.Checks, CheckControllerOpen)
	}
}

func TestPassClearsControllerOpen(t *testing.T) {
	f := stockControllerFacts()
	f.Controller.TrustEntries = nil
	out := passWithFacts(f, antispam.Keep)
	if got := controllerFindings(out); len(got) != 0 {
		t.Fatalf("controller findings = %+v, want none", got)
	}
	if !slices.Contains(out.Checks, CheckControllerOpen) {
		t.Fatalf("Checks = %v, want %s settled so old findings clear", out.Checks, CheckControllerOpen)
	}
}

func TestPassControllerDumpErrorKeepsPreviousState(t *testing.T) {
	f := goodFeedFacts()
	f.ControllerErr = errors.New("rspamadm configdump failed")
	out := passWithFacts(f, antispam.Keep)
	if slices.Contains(out.Checks, CheckControllerOpen) {
		t.Fatalf("Checks = %v: an unreadable controller must not clear earlier findings", out.Checks)
	}
	if got := controllerFindings(out); len(got) != 0 {
		t.Fatalf("controller findings = %+v, want none", got)
	}
}

func TestPassControllerSettledWhenBusy(t *testing.T) {
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install},
		result:     antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone},
	}
	r := h.reconciler()
	r.Collect = func(context.Context, string) antispam.HostFacts { return stockControllerFacts() }
	out := r.Pass(context.Background(), desired(true))
	if !slices.Contains(out.Checks, CheckControllerOpen) || len(controllerFindings(out)) != 1 {
		t.Fatalf("busy pass: Checks = %v, findings = %+v", out.Checks, out.Findings)
	}
}

func TestPassControllerClearedWhenDisabled(t *testing.T) {
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep}}
	out := h.reconciler().Pass(context.Background(), desired(false))
	if !slices.Contains(out.Checks, CheckControllerOpen) || len(controllerFindings(out)) != 0 {
		t.Fatalf("disabled pass: Checks = %v, findings = %+v; want the check settled with no findings", out.Checks, out.Findings)
	}
}

func TestControllerFindingNeverCarriesPassword(t *testing.T) {
	f := stockControllerFacts()
	out := passWithFacts(f, antispam.Keep)
	for _, finding := range out.Findings {
		for _, s := range []string{finding.Message, finding.Details, finding.DedupKey} {
			if strings.Contains(s, syntheticControllerPassword) {
				t.Fatalf("finding carries a password: %+v", finding)
			}
		}
	}
	p := antispam.Problem{Code: antispam.CodeControllerOpen, Severity: antispam.Warning, Key: "localhost:11334\x1b[2J", Detail: "no passwords configured"}
	cf := controllerFinding(p, testNow)
	if strings.ContainsRune(cf.Message+cf.Details+cf.DedupKey, '\x1b') {
		t.Fatalf("finding keeps a control character: %+v", cf)
	}
}
