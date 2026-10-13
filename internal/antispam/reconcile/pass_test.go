package reconcile

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/config"
)

// fakeHost records what a pass asked of the host.
type fakeHost struct {
	assessment antispam.Assessment
	result     antispam.Result
	err        error
	collected  []string
	installed  int
	requests   []antispam.Request
	enabled    []bool
}

func (h *fakeHost) reconciler() Reconciler {
	return Reconciler{
		Collect: func(_ context.Context, socket string) antispam.HostFacts {
			h.collected = append(h.collected, socket)
			return antispam.HostFacts{}
		},
		Installed: func() antispam.HostFacts {
			h.installed++
			return antispam.HostFacts{}
		},
		Run: func(_ context.Context, req antispam.Request) (antispam.Result, error) {
			h.requests = append(h.requests, req)
			return h.result, h.err
		},
		Now: func() time.Time { return testNow },
		assess: func(enabled bool, _ antispam.Settings, _ antispam.HostFacts) antispam.Assessment {
			h.enabled = append(h.enabled, enabled)
			return h.assessment
		},
	}
}

func desired(enabled bool) Desired {
	return Desired{Enabled: enabled, Settings: antispam.Settings{Socket: antispam.DefaultSocket, RejectScore: 15, TagScore: 6}}
}

func TestPassReadsWhatTheStateNeeds(t *testing.T) {
	h := &fakeHost{}
	h.reconciler().Pass(context.Background(), desired(false))
	if h.installed != 1 || len(h.collected) != 0 || !reflect.DeepEqual(h.enabled, []bool{false}) {
		t.Errorf("disabled pass: installed %d, collected %q, assessed %v", h.installed, h.collected, h.enabled)
	}
	h = &fakeHost{}
	h.reconciler().Pass(context.Background(), desired(true))
	if h.installed != 0 || !reflect.DeepEqual(h.collected, []string{antispam.DefaultSocket}) || !reflect.DeepEqual(h.enabled, []bool{true}) {
		t.Errorf("enabled pass: installed %d, collected %q, assessed %v", h.installed, h.collected, h.enabled)
	}
}

func TestPassSendsTheAssessedRequest(t *testing.T) {
	d := desired(true)
	for _, tc := range []struct {
		action antispam.Action
		want   []antispam.Request
	}{
		{antispam.Keep, nil},
		{antispam.Install, []antispam.Request{antispam.ApplyRequest(d.Settings)}},
		{antispam.Uninstall, []antispam.Request{antispam.RemoveRequest()}},
	} {
		h := &fakeHost{assessment: antispam.Assessment{Action: tc.action}, result: antispam.Result{OK: true}}
		out := h.reconciler().Pass(context.Background(), d)
		if !reflect.DeepEqual(h.requests, tc.want) || len(out.Findings) != 0 || out.Retry != 0 || out.Err != nil {
			t.Errorf("action %d: requests %+v, outcome %+v", tc.action, h.requests, out)
		}
	}
}

func TestPassReportsProblemsAndResults(t *testing.T) {
	problem := antispam.Problem{Code: antispam.CodeSocket, Severity: antispam.Temporary, Detail: "rspamd did not answer"}
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install, Problems: []antispam.Problem{problem}},
		result:     antispam.Result{Operation: antispam.OpApply, FailedStep: "exim_probe", Rollback: antispam.RollbackVerified, Error: "exim SMTP greeting probe failed"},
	}
	out := h.reconciler().Pass(context.Background(), desired(true))
	if len(out.Findings) != 2 || out.Findings[0].Check != CheckPrecondition || out.Findings[1].Check != CheckApplyFailed {
		t.Fatalf("findings %+v", out.Findings)
	}
}

// A held lock is retried soon and is not a failure (spec section 6.5).
func TestPassRetriesBusyLock(t *testing.T) {
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install},
		result:     antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone},
	}
	out := h.reconciler().Pass(context.Background(), desired(true))
	if out.Retry != BusyRetry || len(out.Findings) != 0 {
		t.Fatalf("outcome %+v", out)
	}
}

// A worker that returns no result is reported and its error kept for the
// daemon log; the next regular pass runs it again.
func TestPassKeepsWorkerError(t *testing.T) {
	boom := errors.New("antispam worker returned no result")
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Uninstall}, err: boom}
	out := h.reconciler().Pass(context.Background(), desired(false))
	if !errors.Is(out.Err, boom) || out.Retry != 0 || len(out.Findings) != 1 || out.Findings[0].Check != CheckApplyFailed {
		t.Fatalf("outcome %+v", out)
	}
}

// Observe mode reports and never changes the host, even when the
// assessment asks for a change (spec section 4.3).
func TestPassObserveReportsOnly(t *testing.T) {
	d := desired(false)
	d.Observe = true
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Uninstall, Installed: true}}
	out := h.reconciler().Pass(context.Background(), d)
	if len(h.requests) != 0 || len(out.Findings) != 1 || !strings.Contains(out.Findings[0].Message, codeObserve) {
		t.Fatalf("requests %+v, findings %+v", h.requests, out.Findings)
	}
	h = &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep}}
	if out := h.reconciler().Pass(context.Background(), d); len(out.Findings) != 0 {
		t.Fatalf("observe mode without an installation reported %+v", out.Findings)
	}
}

func TestDesiredFromConfig(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeObserve}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, DryRun: true, RspamdSocket: "/run/x.sock", RejectScore: 20, TagScore: 5}
	want := Desired{Enabled: true, Observe: true, Settings: antispam.Settings{DryRun: true, Socket: "/run/x.sock", RejectScore: 20, TagScore: 5}}
	if got := DesiredFromConfig(cfg); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// Without an injected assessment a pass uses antispam.Assess: a disabled
// host with nothing installed is left alone.
func TestPassUsesAssess(t *testing.T) {
	h := &fakeHost{}
	r := h.reconciler()
	r.assess = nil
	r.Installed = func() antispam.HostFacts { return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}} }
	if out := r.Pass(context.Background(), desired(false)); len(h.requests) != 0 || len(out.Findings) != 0 {
		t.Fatalf("requests %+v, outcome %+v", h.requests, out)
	}
}

// A condition that lasts is the same finding on every pass, so the 15
// minute schedule does not alert on it again.
func TestPassFindingsKeepTheirIdentity(t *testing.T) {
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install, Problems: []antispam.Problem{
			{Code: antispam.CodeSocket, Severity: antispam.Temporary, Detail: "rspamd did not answer /ping on the socket; check the rspamd service"},
			{Code: antispam.CodeGlobalEnable, Severity: antispam.Warning, Detail: "/etc/global_spamassassin_enable exists, so no account can opt out"},
		}},
		result: antispam.Result{Operation: antispam.OpApply, FailedStep: "exim_probe", Rollback: antispam.RollbackVerified, Error: "exim SMTP greeting probe failed"},
	}
	r := h.reconciler()
	first := r.Pass(context.Background(), desired(true))
	r.Now = func() time.Time { return testNow.Add(15 * time.Minute) }
	second := r.Pass(context.Background(), desired(true))
	if len(first.Findings) != 3 || len(second.Findings) != 3 {
		t.Fatalf("findings %d and %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		a, b := first.Findings[i], second.Findings[i]
		if a.Key() != b.Key() || a.Fingerprint() != b.Fingerprint() {
			t.Errorf("finding %d changed identity: %q / %q", i, a.Key(), b.Key())
		}
	}
}

// An enabled observe-mode configuration cannot pass validation, but a pass
// must still never change the host in observe mode.
func TestPassObserveNeverRunsTheWorker(t *testing.T) {
	d := desired(true)
	d.Observe = true
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Install}}
	h.reconciler().Pass(context.Background(), d)
	if len(h.requests) != 0 {
		t.Fatalf("observe mode sent %+v", h.requests)
	}
}
