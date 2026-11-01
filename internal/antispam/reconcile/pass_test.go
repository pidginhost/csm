package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/eximlock"
)

// fakeHost records what a pass asked of the host.
type fakeHost struct {
	assessment  antispam.Assessment
	result      antispam.Result
	err         error
	collected   []string
	installed   int
	requests    []antispam.Request
	enabled     []bool
	invalidated int
}

func (h *fakeHost) reconciler() Reconciler {
	return Reconciler{
		Invalidate: func(context.Context) error { h.invalidated++; return nil },
		Collect: func(_ context.Context, socket string) antispam.HostFacts {
			h.collected = append(h.collected, socket)
			return goodFeedFacts()
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

func TestPassInvalidatesBeforeReadingHost(t *testing.T) {
	h := &fakeHost{}
	r := h.reconciler()
	reads := 0
	r.Collect = func(context.Context, string) antispam.HostFacts {
		reads++
		if h.invalidated != 1 {
			t.Fatalf("read host after %d invalidations, want 1", h.invalidated)
		}
		return antispam.HostFacts{}
	}
	if out := r.Pass(context.Background(), desired(true)); out.Err != nil || out.Retry != 0 || h.invalidated != 1 || reads != 1 {
		t.Fatalf("invalidations=%d reads=%d outcome=%+v", h.invalidated, reads, out)
	}
}

// A busy lock retries in 20 seconds. A failed invalidation also retries in
// 20 seconds while antispam is enabled; while it is disabled, a broken state
// directory retries on the normal interval, so a host that never used
// antispam does not log a warning every 20 seconds.
func TestPassRetriesInvalidationBeforeReadingHost(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, failure := range []error{eximlock.ErrBusy, errors.New("read-only file system")} {
			t.Run(fmt.Sprintf("enabled=%t/%s", enabled, failure), func(t *testing.T) {
				h := &fakeHost{}
				r := h.reconciler()
				r.Invalidate = func(context.Context) error { h.invalidated++; return failure }
				out := r.Pass(context.Background(), desired(enabled))
				busy := errors.Is(failure, eximlock.ErrBusy)
				wantRetry := BusyRetry
				if !busy && !enabled {
					wantRetry = 0
				}
				var wantChecks []string
				if !enabled {
					wantChecks = []string{CheckControllerOpen}
				}
				if out.Retry != wantRetry || !reflect.DeepEqual(out.Checks, wantChecks) ||
					h.invalidated != 1 || h.installed != 0 || len(h.collected) != 0 || len(h.requests) != 0 {
					t.Fatalf("outcome=%+v host=%+v, want retry %v", out, h, wantRetry)
				}
				switch {
				case busy:
					if out.Err != nil || len(out.Findings) != 0 {
						t.Fatalf("busy became a failure: %v", out.Err)
					}
				case !errors.Is(out.Err, failure):
					t.Fatalf("lost invalidation error: %v", out.Err)
				case len(out.Findings) != 1 || out.Findings[0].Check != CheckApplyFailed ||
					out.Findings[0].Severity != alert.Warning || !out.Findings[0].Timestamp.Equal(testNow) ||
					!strings.Contains(out.Findings[0].Details, "may still change"):
					t.Fatalf("invalidation failure was not reported: %+v", out.Findings)
				}
			})
		}
	}
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
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, DryRun: true, RspamdSocket: "/run/x.sock", RejectScore: 20, TagScore: 5,
		Feeds: config.AntispamFeedsConfig{Enabled: []string{"uribl", "psbl"}, SpamhausDQSKeyFile: "/etc/csm/k"}}
	want := Desired{Enabled: true, Observe: true, Settings: antispam.Settings{DryRun: true, Socket: "/run/x.sock", RejectScore: 20, TagScore: 5,
		Feeds: []string{"psbl", "uribl"}, DQSKeyFile: "/etc/csm/k"}}
	if got := DesiredFromConfig(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// Resolvers listed in infra_ips count as the operator's own; hostnames are
// never resolved on this path.
func TestDesiredFromConfigInfraNets(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"198.51.100.53", "fw.example.com"}}
	got := DesiredFromConfig(cfg).InfraNets
	if want := []netip.Prefix{netip.MustParsePrefix("198.51.100.53/32")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
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
			if !errors.Is(out.Err, context.Canceled) || len(out.Findings) != 0 || len(out.Checks) != 0 || out.Retry != 0 {
				t.Fatalf("outcome %+v", out)
			}
			if h.invalidated != 0 || len(h.collected) != 0 || h.installed != 0 || len(h.enabled) != 0 || len(h.requests) != 0 {
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
			if !errors.Is(out.Err, context.Canceled) || len(out.Findings) != 0 || len(out.Checks) != 0 || out.Retry != 0 {
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
			if out.Err != workerErr || len(out.Findings) != 0 || len(out.Checks) != 0 || out.Retry != 0 || len(h.requests) != 1 {
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
		out.Findings[0].Check != CheckApplyFailed || out.Findings[0].Message != "Antispam apply returned no result" ||
		!reflect.DeepEqual(out.Checks, []string{CheckPrecondition, CheckApplyFailed, CheckFeed, CheckLearning, CheckControllerOpen}) {
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
		!strings.Contains(out.Findings[0].Details, "could not confirm") ||
		!reflect.DeepEqual(out.Checks, []string{CheckPrecondition, CheckApplyFailed, CheckFeed, CheckLearning, CheckControllerOpen}) {
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

// A reporter replaces the latest findings of exactly the checks a pass
// settled. A canceled pass settles nothing, and a busy one leaves the last
// apply result in place until the retry.
func TestPassNamesTheChecksItSettled(t *testing.T) {
	both := []string{CheckPrecondition, CheckApplyFailed, CheckFeed, CheckLearning, CheckControllerOpen}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		host *fakeHost
		ctx  context.Context
		d    Desired
		want []string
	}{
		{"keep", &fakeHost{}, context.Background(), desired(true), both},
		{"applied", &fakeHost{assessment: antispam.Assessment{Action: antispam.Install}, result: antispam.Result{OK: true}},
			context.Background(), desired(true), both},
		{"failed", &fakeHost{assessment: antispam.Assessment{Action: antispam.Install},
			result: antispam.Result{Operation: antispam.OpApply, FailedStep: "exim_probe", Rollback: antispam.RollbackVerified}},
			context.Background(), desired(true), both},
		{"no result", &fakeHost{assessment: antispam.Assessment{Action: antispam.Uninstall}, err: errors.New("no result")},
			context.Background(), desired(false), both},
		{"observe", &fakeHost{assessment: antispam.Assessment{Action: antispam.Uninstall, Installed: true}},
			context.Background(), Desired{Observe: true}, both},
		{"busy", &fakeHost{assessment: antispam.Assessment{Action: antispam.Install},
			result: antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone}},
			context.Background(), desired(true), []string{CheckPrecondition, CheckFeed, CheckControllerOpen}},
		{"canceled", &fakeHost{}, canceled, desired(true), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.host.reconciler().Pass(tc.ctx, tc.d)
			if !reflect.DeepEqual(out.Checks, tc.want) {
				t.Fatalf("checks %q, want %q (outcome %+v)", out.Checks, tc.want, out)
			}
		})
	}
}

func TestDesiredFromConfigLearning(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, RspamdSocket: antispam.DefaultSocket, RejectScore: 15, TagScore: 6,
		Learning: config.AntispamLearningConfig{Enabled: true}}
	got := DesiredFromConfig(cfg).Settings
	if !got.Learning || got.LearningDir != antispam.DefaultLearningDir || got.Roundcube {
		t.Fatalf("learning on: %+v", got)
	}
	cfg.EmailProtection.Antispam.Learning.Enabled = false
	got = DesiredFromConfig(cfg).Settings
	if got.Learning || got.LearningDir != "" || got.Roundcube {
		t.Fatalf("learning off: %+v", got)
	}
}

// Each backup the worker kept is one warning until the operator deletes it,
// whether antispam is enabled, disabled or observed, and while a busy lock
// holds the apply back. An unreadable backup directory keeps the last
// findings; a reconciler without the hook settles nothing.
func TestPassReportsReplacedFiles(t *testing.T) {
	rep := antispam.Replacement{Path: "/etc/rspamd/local.d/actions.conf",
		Backup: antispam.ReplacedDir + "/20260102T030405Z_%2Fetc%2Frspamd%2Flocal.d%2Factions.conf"}
	for _, tc := range []struct {
		name string
		host *fakeHost
		d    Desired
	}{
		{"enabled", &fakeHost{}, desired(true)},
		{"applied", &fakeHost{assessment: antispam.Assessment{Action: antispam.Install}, result: antispam.Result{OK: true}}, desired(true)},
		{"disabled", &fakeHost{}, desired(false)},
		{"observe", &fakeHost{assessment: antispam.Assessment{Action: antispam.Uninstall, Installed: true}}, Desired{Observe: true}},
		{"busy", &fakeHost{assessment: antispam.Assessment{Action: antispam.Install},
			result: antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone}}, desired(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replacedFindings := func(out Outcome) []alert.Finding {
				var found []alert.Finding
				for _, f := range out.Findings {
					if f.Check == CheckFileReplaced {
						found = append(found, f)
					}
				}
				return found
			}
			r := tc.host.reconciler()
			r.Replaced = func() ([]antispam.Replacement, error) { return []antispam.Replacement{rep}, nil }
			out := r.Pass(context.Background(), tc.d)
			found := replacedFindings(out)
			if !slices.Contains(out.Checks, CheckFileReplaced) || len(found) != 1 {
				t.Fatalf("checks %q, findings %+v", out.Checks, out.Findings)
			}
			if f := found[0]; f.Severity != alert.Warning || f.DedupKey != rep.Backup || !f.Timestamp.Equal(testNow) ||
				!strings.Contains(f.Message, rep.Path) || !strings.Contains(f.Details, rep.Path) || !strings.Contains(f.Details, rep.Backup) {
				t.Fatalf("finding %+v", f)
			}
			if !tc.d.Enabled && strings.Contains(found[0].Details, "now owns") {
				t.Fatal("a historical backup claims the removed integration still owns the target")
			}

			r = tc.host.reconciler()
			r.Replaced = func() ([]antispam.Replacement, error) { return nil, errors.New("permission denied") }
			out = r.Pass(context.Background(), tc.d)
			if slices.Contains(out.Checks, CheckFileReplaced) || len(replacedFindings(out)) != 0 {
				t.Fatalf("unreadable directory settled: checks %q, findings %+v", out.Checks, out.Findings)
			}

			out = tc.host.reconciler().Pass(context.Background(), tc.d)
			if slices.Contains(out.Checks, CheckFileReplaced) || len(replacedFindings(out)) != 0 {
				t.Fatalf("no hook settled: checks %q, findings %+v", out.Checks, out.Findings)
			}
		})
	}
}

// A pass must report the copies its worker left, not the directory listing
// from before the worker started.
func TestPassReportsReplacementsAfterWorker(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result antispam.Result
	}{
		{"applied", antispam.Result{OK: true}},
		{"rollback failed", antispam.Result{FailedStep: "rspamd_check", Rollback: antispam.RollbackFailed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Install}}
			r := h.reconciler()
			var replaced []antispam.Replacement
			rep := antispam.Replacement{Path: antispam.ScoresPath, Backup: antispam.ReplacedDir + "/copy"}
			r.Run = func(context.Context, antispam.Request) (antispam.Result, error) {
				replaced = []antispam.Replacement{rep}
				return tc.result, nil
			}
			r.Replaced = func() ([]antispam.Replacement, error) { return replaced, nil }
			out := r.Pass(context.Background(), desired(true))
			var found []alert.Finding
			for _, f := range out.Findings {
				if f.Check == CheckFileReplaced {
					found = append(found, f)
				}
			}
			if !slices.Contains(out.Checks, CheckFileReplaced) || len(found) != 1 || found[0].DedupKey != rep.Backup {
				t.Fatalf("worker's replacement was not reported: checks %v, findings %+v", out.Checks, found)
			}
		})
	}
}

// The host's mail stack, found by the collector, picks the files CSM
// renders; configuration never names it.
func TestPassRendersForTheCollectedStack(t *testing.T) {
	h := &fakeHost{}
	r := h.reconciler()
	r.Collect = func(context.Context, string) antispam.HostFacts {
		f := goodFeedFacts()
		f.Stack = antispam.StackPostfix
		return f
	}
	var got []antispam.MailStack
	r.assess = func(_ bool, s antispam.Settings, _ antispam.HostFacts) antispam.Assessment {
		got = append(got, s.Stack)
		return antispam.Assessment{}
	}
	r.Pass(context.Background(), desired(true))
	if !slices.Equal(got, []antispam.MailStack{antispam.StackPostfix}) {
		t.Fatalf("assessed stacks %q, want postfix", got)
	}
}

// A pass on a Postfix host says where its scan records come from; a pass
// that could not read that keeps the last answer, and every other pass
// clears it.
func TestPassReportsPostfixScanSource(t *testing.T) {
	postfix := func(f *antispam.HostFacts) {
		f.Stack = antispam.StackPostfix
		f.Postconf = antispam.CommandResult{Stdout: "inet:127.0.0.1:11332\naccept\n0\n/var/spool/postfix\n3.7.11\n"}
		f.RspamdWorkers = antispam.CommandResult{Stdout: `{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": true}}`}
	}
	want := &antispam.ScanSource{Log: "/var/log/rspamd/rspamd.log", Milters: []string{"inet:127.0.0.1:11332"}}
	for _, tc := range []struct {
		name    string
		enabled bool
		mutate  func(*antispam.HostFacts)
		want    *antispam.ScanSource
	}{
		{"postfix", true, postfix, want},
		{"postfix, logging unreadable", true, func(f *antispam.HostFacts) {
			postfix(f)
			f.RspamdLog = antispam.LogFacts{Err: errors.New("rspamd's logging settings are not readable")}
		}, nil},
		{"exim", true, func(f *antispam.HostFacts) { f.Stack = antispam.StackExim }, &antispam.ScanSource{}},
		{"disabled", false, postfix, &antispam.ScanSource{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHost{}
			r := h.reconciler()
			r.Collect = func(context.Context, string) antispam.HostFacts {
				f := goodFeedFacts()
				tc.mutate(&f)
				return f
			}
			r.Installed = func() antispam.HostFacts { return r.Collect(context.Background(), "") }
			out := r.Pass(context.Background(), desired(tc.enabled))
			if !reflect.DeepEqual(out.ScanSource, tc.want) {
				t.Fatalf("scan source %+v, want %+v", out.ScanSource, tc.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out := (&fakeHost{}).reconciler().Pass(ctx, desired(true)); out.ScanSource != nil {
		t.Fatalf("canceled pass replaced the scan source with %+v", out.ScanSource)
	}
}

// Exemptions come from csm.yaml in the order written; the config loader has
// already lowered their case.
func TestDesiredFromConfigExempt(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, RspamdSocket: antispam.DefaultSocket, RejectScore: 15, TagScore: 6,
		Exempt: []string{"example.org", "a@example.com"}}
	if got := DesiredFromConfig(cfg).Settings.Exempt; !slices.Equal(got, []string{"example.org", "a@example.com"}) {
		t.Fatalf("exempt = %q", got)
	}
}

// Mail from infra_ips is never enforced on a Postfix host: the pass hands
// the infra networks to rendering, disabled passes included.
func TestPassScopesInfraNets(t *testing.T) {
	nets := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	for _, enabled := range []bool{true, false} {
		h := &fakeHost{}
		r := h.reconciler()
		var got [][]netip.Prefix
		r.assess = func(_ bool, s antispam.Settings, _ antispam.HostFacts) antispam.Assessment {
			got = append(got, s.ScopeNets)
			return antispam.Assessment{}
		}
		d := desired(enabled)
		d.InfraNets = nets
		r.Pass(context.Background(), d)
		if len(got) != 1 || !slices.Equal(got[0], nets) {
			t.Fatalf("enabled %t: assessed scope networks %v, want %v", enabled, got, nets)
		}
	}
}

// The worker renders from the request alone, so on Postfix it must carry
// the exemptions and infra networks: the generation the worker installs is
// the one the next pass expects.
func TestPassSendsPostfixScopeToWorker(t *testing.T) {
	h := &fakeHost{result: antispam.Result{OK: true, Generation: "g"}}
	r := h.reconciler()
	r.Collect = func(context.Context, string) antispam.HostFacts {
		f := goodFeedFacts()
		f.Stack = antispam.StackPostfix
		return f
	}
	var assessed antispam.Settings
	r.assess = func(_ bool, s antispam.Settings, _ antispam.HostFacts) antispam.Assessment {
		assessed = s
		return antispam.Assessment{Action: antispam.Install}
	}
	d := desired(true)
	d.Settings.Exempt = []string{"example.org", "a@example.com"}
	d.InfraNets = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	r.Pass(context.Background(), d)
	if len(h.requests) != 1 {
		t.Fatalf("requests %+v", h.requests)
	}
	body, err := json.Marshal(h.requests[0])
	if err != nil {
		t.Fatal(err)
	}
	_, worker, err := antispam.DecodeRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	worker.Stack = antispam.StackPostfix
	want, err := antispam.ManagedContent(assessed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := antispam.ManagedContent(worker)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(worker.Exempt, d.Settings.Exempt) || !slices.Equal(worker.ScopeNets, d.InfraNets) || antispam.Generation(got) != antispam.Generation(want) {
		t.Fatalf("worker settings %+v render another generation than the daemon's %+v", worker, assessed)
	}
}
