package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// usePanel makes platform detection report panel for one test.
func usePanel(t *testing.T, panel platform.Panel) {
	t.Helper()
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{Panel: &panel})
}

// useActiveConfig publishes cfg as the live config for one test.
func useActiveConfig(t *testing.T, cfg *config.Config) {
	t.Helper()
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	config.SetActive(cfg)
}

// useAntispamHost replaces the host the reconcile loop works on with one
// where nothing of CSM's is installed, and counts its disabled passes.
func useAntispamHost(t *testing.T) <-chan struct{} {
	t.Helper()
	passes := make(chan struct{}, 16)
	prev := antispamReconciler
	t.Cleanup(func() { antispamReconciler = prev })
	antispamReconciler = func() reconcile.Reconciler {
		return reconcile.Reconciler{
			Collect: func(context.Context, string) antispam.HostFacts { return antispam.HostFacts{} },
			Installed: func() antispam.HostFacts {
				passes <- struct{}{}
				return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}}
			},
			Run: func(context.Context, antispam.Request) (antispam.Result, error) {
				t.Error("a host with nothing installed sent a worker request")
				return antispam.Result{}, nil
			},
			Now: time.Now,
		}
	}
	return passes
}

func waitPass(t *testing.T, passes <-chan struct{}) {
	t.Helper()
	select {
	case <-passes:
	case <-time.After(5 * time.Second):
		t.Fatal("antispam pass did not run")
	}
}

func TestStartAntispamSkipsHostsWithoutCPanel(t *testing.T) {
	usePanel(t, platform.PanelNone)
	useAntispamHost(t)
	d := newTestDaemon(t)
	d.startAntispam()
	if d.antispamLoop.Load() != nil {
		t.Fatal("antispam reconcile started on a host without cPanel")
	}
	d.reconcileAntispam() // must not block or panic without a loop
}

// A pass runs at start and after each reload, and shutdown stops the loop.
func TestAntispamLoopPassesAtStartAndOnReload(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	passes := useAntispamHost(t)
	d := newTestDaemon(t)
	useActiveConfig(t, d.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	d.scanCtx, d.scanCancel = ctx, cancel
	d.startAntispam()
	waitPass(t, passes)
	d.reconcileAntispam()
	waitPass(t, passes)
	cancel()
	stopped := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("antispam loop outlived shutdown")
	}
}

func antispamFinding(check, message string) alert.Finding {
	return alert.Finding{Severity: alert.Warning, Check: check, Message: message, Timestamp: time.Now()}
}

func latestChecks(d *Daemon) map[string]int {
	out := make(map[string]int)
	for _, f := range d.store.LatestFindings() {
		out[f.Check]++
	}
	return out
}

// A pass replaces the latest findings of the checks it settled and alerts
// on them; a busy pass keeps the last apply result, and a canceled one
// changes nothing.
func TestReportAntispamReplacesSettledChecks(t *testing.T) {
	d := newTestDaemon(t)
	both := []string{reconcile.CheckPrecondition, reconcile.CheckApplyFailed}
	d.reportAntispam(reconcile.Outcome{Checks: both, Findings: []alert.Finding{
		antispamFinding(reconcile.CheckPrecondition, "Antispam precondition not met: rspamd_socket"),
		antispamFinding(reconcile.CheckApplyFailed, "Antispam apply failed at exim_probe"),
	}})
	if got := latestChecks(d); got[reconcile.CheckPrecondition] != 1 || got[reconcile.CheckApplyFailed] != 1 {
		t.Fatalf("latest after a failed pass: %v", got)
	}
	if got := drainAlertCh(d); len(got) != 2 {
		t.Fatalf("alerts after a failed pass: %+v", got)
	}

	d.reportAntispam(reconcile.Outcome{Checks: []string{reconcile.CheckPrecondition}, Retry: reconcile.BusyRetry})
	if got := latestChecks(d); got[reconcile.CheckPrecondition] != 0 || got[reconcile.CheckApplyFailed] != 1 {
		t.Fatalf("latest after a busy pass: %v", got)
	}

	d.reportAntispam(reconcile.Outcome{Err: context.Canceled})
	if got := latestChecks(d); got[reconcile.CheckApplyFailed] != 1 {
		t.Fatalf("latest after a canceled pass: %v", got)
	}

	d.reportAntispam(reconcile.Outcome{Checks: both})
	if got := latestChecks(d); got[reconcile.CheckPrecondition] != 0 || got[reconcile.CheckApplyFailed] != 0 {
		t.Fatalf("latest after a clean pass: %v", got)
	}
}

const (
	testScanSocket = "/run/rspamd/csm-normal.sock"
	scanErrorLine  = `2026-10-13 09:00:00 1xF5ol-00000000SdK-2TMA CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`
)

// enableAntispam publishes a config with antispam enabled on the test
// socket and syncs health tracking to it.
func enableAntispam(t *testing.T, d *Daemon, enabled bool) {
	t.Helper()
	cfg := &config.Config{StatePath: d.cfg.StatePath}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: enabled, DryRun: true, RspamdSocket: testScanSocket, RejectScore: 15, TagScore: 6}
	useActiveConfig(t, cfg)
	d.syncAntispamHealth()
}

// usePing replaces the rspamd probe; each call takes the next result.
func usePing(t *testing.T, results ...error) *int {
	t.Helper()
	calls := new(int)
	prev := antispamPing
	t.Cleanup(func() { antispamPing = prev })
	antispamPing = func(_ context.Context, socket string) (int, error) {
		if socket != testScanSocket {
			t.Errorf("probed %q", socket)
		}
		if *calls >= len(results) {
			t.Fatalf("unexpected probe %d", *calls+1)
		}
		*calls++
		return 0, results[*calls-1]
	}
	return calls
}

// captureDispatch records what reaches notification.
func captureDispatch(t *testing.T) *[]alert.Finding {
	t.Helper()
	var delivered []alert.Finding
	prev := alert.CentralHook
	t.Cleanup(func() { alert.SetCentralHook(prev) })
	alert.SetCentralHook(func(f alert.Finding) {
		if f.Check == reconcile.CheckRspamdDown || f.Check == reconcile.CheckRspamdRecovered {
			delivered = append(delivered, f)
		}
	})
	return &delivered
}

func probeTimes(d *Daemon, n int, start time.Time, last string) string {
	for i := range n {
		last = d.probeAntispam(context.Background(), start.Add(time.Duration(i)*20*time.Second), last)
	}
	return last
}

// An outage notifies once and a recovery once, through history and
// notification directly: alert-state dedup would hide a second outage on
// the same day. The latest set shows the outage while it lasts.
func TestAntispamProbeReportsOutageAndRecovery(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	refused := errors.New("connection refused")
	usePing(t, refused, refused, refused, refused, nil, nil, refused, refused, refused)
	delivered := captureDispatch(t)
	now := time.Now()

	last := probeTimes(d, 4, now, "")
	if len(*delivered) != 1 || (*delivered)[0].Check != reconcile.CheckRspamdDown {
		t.Fatalf("down notices %+v", *delivered)
	}
	if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 1 {
		t.Fatalf("latest during the outage: %v", got)
	}
	last = probeTimes(d, 2, now.Add(time.Minute), last)
	if len(*delivered) != 2 || (*delivered)[1].Check != reconcile.CheckRspamdRecovered {
		t.Fatalf("recovery notices %+v", *delivered)
	}
	if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 0 || got[reconcile.CheckRspamdRecovered] != 0 {
		t.Fatalf("latest after recovery: %v", got)
	}
	probeTimes(d, 3, now.Add(2*time.Minute), last)
	if len(*delivered) != 3 || (*delivered)[2].Check != reconcile.CheckRspamdDown {
		t.Fatalf("second outage the same day: %+v", *delivered)
	}
	history, _ := d.store.ReadHistory(10, 0)
	if len(history) != 3 {
		t.Fatalf("history %+v", history)
	}
}

// Disabled antispam sends no probe, and disabling clears the outage and
// scan-error findings without a recovery notice (spec section 7).
func TestAntispamProbeStopsWhenDisabled(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	refused := errors.New("connection refused")
	calls := usePing(t, refused, refused, refused)
	delivered := captureDispatch(t)
	d.antispamHealth.Line(scanErrorLine, time.Now())
	last := probeTimes(d, 3, time.Now(), "")
	if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 1 || got[reconcile.CheckScanError] != 1 {
		t.Fatalf("latest while enabled: %v", got)
	}

	enableAntispam(t, d, false)
	probeTimes(d, 2, time.Now().Add(time.Minute), last)
	if *calls != 3 {
		t.Fatalf("probes sent while disabled: %d", *calls-3)
	}
	if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 0 || got[reconcile.CheckScanError] != 0 {
		t.Fatalf("latest after disable: %v", got)
	}
	if len(*delivered) != 1 {
		t.Fatalf("notices %+v", *delivered)
	}
}

// A probe cut short by shutdown is not an rspamd failure.
func TestAntispamProbeIgnoresCanceledProbe(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	prev := antispamPing
	t.Cleanup(func() { antispamPing = prev })
	antispamPing = func(ctx context.Context, _ string) (int, error) { return -1, ctx.Err() }
	delivered := captureDispatch(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 5 {
		d.probeAntispam(ctx, time.Now().Add(time.Duration(i)*time.Second), "")
	}
	if len(*delivered) != 0 || len(d.antispamHealth.Active()) != 0 {
		t.Fatalf("canceled probes raised %+v", *delivered)
	}
}

// Health findings left from before a restart describe a state no longer
// tracked; startup clears them.
func TestStartAntispamClearsStaleHealthFindings(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	passes := useAntispamHost(t)
	d := newTestDaemon(t)
	useActiveConfig(t, d.cfg)
	checks.StoreLatestScanFindings(d.store, nil, []alert.Finding{
		{Severity: alert.Warning, Check: reconcile.CheckRspamdDown, DedupKey: "rspamd", Message: "rspamd does not answer", Timestamp: time.Now()},
	})
	ctx, cancel := context.WithCancel(context.Background())
	d.scanCtx, d.scanCancel = ctx, cancel
	d.startAntispam()
	waitPass(t, passes)
	cancel()
	d.wg.Wait()
	if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 0 {
		t.Fatalf("stale health finding survived startup: %v", got)
	}
}

// A reload applies the antispam switch to health tracking at once: scan
// markers count after enabling, and disabling forgets them (spec section 7).
func TestReconcileAntispamFollowsTheReloadedSwitch(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	useAntispamHost(t)
	d := newTestDaemon(t)
	useActiveConfig(t, d.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	d.scanCtx, d.scanCancel = ctx, cancel
	t.Cleanup(func() {
		cancel()
		d.wg.Wait()
	})
	d.startAntispam()
	if got := d.antispamHealth.Line(scanErrorLine, time.Now()); len(got) != 0 {
		t.Fatalf("disabled antispam counted a scan error: %+v", got)
	}

	cfg := &config.Config{}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, DryRun: true, RspamdSocket: testScanSocket, RejectScore: 15, TagScore: 6}
	config.SetActive(cfg)
	d.reconcileAntispam()
	if got := d.antispamHealth.Line(scanErrorLine, time.Now()); len(got) != 1 || got[0].Check != reconcile.CheckScanError {
		t.Fatalf("enabled antispam missed a scan error: %+v", got)
	}

	config.SetActive(d.cfg)
	d.reconcileAntispam()
	if active := d.antispamHealth.Active(); len(active) != 0 {
		t.Fatalf("disable kept %+v", active)
	}
}
