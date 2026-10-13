package reconcile

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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

func TestPassCanceledBeforeHostRead(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Install}}
			out := h.reconciler().Pass(ctx, desired(enabled))
			if !errors.Is(out.Err, context.Canceled) || len(out.Findings) != 0 || out.Retry != 0 {
				t.Fatalf("outcome %+v", out)
			}
			if len(h.collected) != 0 || h.installed != 0 || len(h.enabled) != 0 || len(h.requests) != 0 {
				t.Fatalf("canceled pass used the host: %+v", h)
			}
		})
	}
}

// Interrupted probes are not evidence of a host problem and must not
// drive a worker request.
func TestPassCanceledDuringHostRead(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := &fakeHost{assessment: antispam.Assessment{
				Action: antispam.Install,
				Problems: []antispam.Problem{{Code: antispam.CodeSocket, Severity: antispam.Temporary,
					Detail: "rspamd did not answer"}},
			}}
			r := h.reconciler()
			collect, installed := r.Collect, r.Installed
			r.Collect = func(ctx context.Context, socket string) antispam.HostFacts {
				cancel()
				return collect(ctx, socket)
			}
			r.Installed = func() antispam.HostFacts {
				cancel()
				return installed()
			}
			out := r.Pass(ctx, desired(enabled))
			if !errors.Is(out.Err, context.Canceled) || len(out.Findings) != 0 || out.Retry != 0 {
				t.Fatalf("outcome %+v", out)
			}
			if len(h.collected)+h.installed != 1 || len(h.enabled) != 0 || len(h.requests) != 0 {
				t.Fatalf("canceled pass assessed incomplete facts or ran the worker: %+v", h)
			}
		})
	}
}

func TestPassCanceledDuringWorker(t *testing.T) {
	for _, action := range []antispam.Action{antispam.Install, antispam.Uninstall} {
		t.Run(fmt.Sprint(action), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			workerErr := fmt.Errorf("worker terminated: %w", context.Canceled)
			h := &fakeHost{
				assessment: antispam.Assessment{Action: action,
					Problems: []antispam.Problem{{Code: antispam.CodeGlobalEnable, Severity: antispam.Warning,
						Detail: "no account can opt out"}}},
				err: workerErr,
			}
			r := h.reconciler()
			run := r.Run
			r.Run = func(ctx context.Context, req antispam.Request) (antispam.Result, error) {
				cancel()
				return run(ctx, req)
			}
			out := r.Pass(ctx, desired(action == antispam.Install))
			if out.Err != workerErr || len(out.Findings) != 0 || out.Retry != 0 || len(h.requests) != 1 {
				t.Fatalf("requests %+v, outcome %+v", h.requests, out)
			}
		})
	}
}

// The worker's own deadline is a failure while the pass is still active.
func TestPassReportsWorkerTimeout(t *testing.T) {
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Install}, err: context.DeadlineExceeded}
	out := h.reconciler().Pass(context.Background(), desired(true))
	if !errors.Is(out.Err, context.DeadlineExceeded) || out.Retry != 0 || len(out.Findings) != 1 ||
		out.Findings[0].Check != CheckApplyFailed || out.Findings[0].Message != "Antispam apply returned no result" {
		t.Fatalf("outcome %+v", out)
	}
}

// Cancellation does not invalidate a completed worker report, especially
// when it warns that rollback failed.
func TestPassKeepsWorkerResultAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install},
		result: antispam.Result{Operation: antispam.OpApply, FailedStep: "exim_probe",
			Rollback: antispam.RollbackFailed, Error: "exim SMTP greeting probe failed"},
	}
	r := h.reconciler()
	run := r.Run
	r.Run = func(ctx context.Context, req antispam.Request) (antispam.Result, error) {
		cancel()
		return run(ctx, req)
	}
	out := r.Pass(ctx, desired(true))
	if out.Err != nil || out.Retry != 0 || len(out.Findings) != 1 ||
		out.Findings[0].Check != CheckApplyFailed || out.Findings[0].Severity != alert.Critical ||
		!strings.Contains(out.Findings[0].Details, "could not confirm") {
		t.Fatalf("outcome %+v", out)
	}
}

func TestPassObservePreconditionsDescribeNoChanges(t *testing.T) {
	for _, severity := range []antispam.Severity{antispam.Temporary, antispam.Definite, antispam.Warning} {
		t.Run(fmt.Sprint(severity), func(t *testing.T) {
			d := desired(false)
			d.Observe = true
			problem := antispam.Problem{Code: antispam.CodeTargets, Severity: severity,
				Detail: "unsafe directory /home/user/bad\nname"}
			h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep, Installed: true,
				Problems: []antispam.Problem{problem}}}
			r := h.reconciler()
			out := r.Pass(context.Background(), d)
			if len(h.requests) != 0 || out.Err != nil || out.Retry != 0 || len(out.Findings) != 2 {
				t.Fatalf("requests %+v, outcome %+v", h.requests, out)
			}
			f := out.Findings[0]
			if f.Check != CheckPrecondition || f.Severity != alert.Warning ||
				!strings.Contains(f.Message, problem.Code) || strings.Contains(f.Details, "removes") ||
				!strings.Contains(f.Details, "observe mode") || !strings.Contains(f.Details, `bad\nname`) ||
				strings.Contains(f.Details, "\n") {
				t.Fatalf("observe precondition %+v", f)
			}
			if !strings.Contains(out.Findings[1].Message, codeObserve) {
				t.Fatalf("missing installed observe finding: %+v", out.Findings[1])
			}
			r.Now = func() time.Time { return testNow.Add(15 * time.Minute) }
			again := r.Pass(context.Background(), d)
			if len(again.Findings) != 2 {
				t.Fatalf("next pass findings %+v", again.Findings)
			}
			for i, next := range again.Findings {
				if next.Key() != out.Findings[i].Key() || next.Fingerprint() != out.Findings[i].Fingerprint() {
					t.Errorf("finding %d changed identity", i)
				}
			}
		})
	}
}
