package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
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
