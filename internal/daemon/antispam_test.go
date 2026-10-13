package daemon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/adapter"
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
// where nothing of CSM's is installed, and signals each pass.
func useAntispamHost(t *testing.T) <-chan struct{} {
	t.Helper()
	passes := make(chan struct{}, 16)
	useAntispamReconciler(t, reconcile.Reconciler{
		Collect: func(context.Context, string) antispam.HostFacts {
			passes <- struct{}{}
			return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}}
		},
		Installed: func() antispam.HostFacts {
			passes <- struct{}{}
			return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}}
		},
		Run: func(context.Context, antispam.Request) (antispam.Result, error) {
			t.Error("a host with nothing installed sent a worker request")
			return antispam.Result{}, nil
		},
		Now: time.Now,
	})
	return passes
}

func useAntispamReconciler(t *testing.T, r reconcile.Reconciler) {
	t.Helper()
	prev := antispamReconciler
	t.Cleanup(func() { antispamReconciler = prev })
	antispamReconciler = func() reconcile.Reconciler { return r }
}

func waitPass(t *testing.T, passes <-chan struct{}) {
	t.Helper()
	select {
	case <-passes:
	case <-time.After(5 * time.Second):
		t.Fatal("antispam pass did not run")
	}
}

func antispamTestShutdown(t *testing.T, d *Daemon) func() {
	t.Helper()
	d.scanCtx, d.scanCancel = context.WithCancel(context.Background())
	stop := sync.OnceFunc(func() {
		close(d.stopCh)
		d.scanCancel()
		stopped := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("antispam loop outlived shutdown")
		}
	})
	// Stop before the state store and host stubs are torn down, even if a
	// pass assertion fails before the test reaches its shutdown check.
	t.Cleanup(stop)
	return stop
}

func TestStartAntispamSkipsHostsWithoutCPanel(t *testing.T) {
	usePanel(t, platform.PanelNone)
	passes := useAntispamHost(t)
	d := newTestDaemon(t)
	stop := antispamTestShutdown(t, d)
	d.startAntispam()
	if d.antispamLoop.Load() != nil {
		t.Fatal("antispam reconcile started on a host without cPanel")
	}
	d.reconcileAntispam() // must not block or panic without a loop
	stop()
	if len(passes) != 0 {
		t.Fatal("antispam collected host facts without cPanel")
	}
}

// A pass runs at start and after each reload, and shutdown stops the loop.
func TestAntispamLoopPassesAtStartAndOnReload(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	passes := useAntispamHost(t)
	d := newTestDaemon(t)
	useActiveConfig(t, d.cfg)
	stop := antispamTestShutdown(t, d)
	d.startAntispam()
	waitPass(t, passes)
	d.reconcileAntispam()
	waitPass(t, passes)
	stop()
}

func TestAntispamReloadDuringPassUsesLatestConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		usePanel(t, platform.PanelCPanel)
		d := newTestDaemon(t)
		cfg := &config.Config{}
		cfg.EmailProtection.Antispam.Enabled = true
		cfg.EmailProtection.Antispam.RspamdSocket = "/run/rspamd/first.sock"
		useActiveConfig(t, cfg)
		var sockets []string
		release := make(chan struct{})
		useAntispamReconciler(t, reconcile.Reconciler{
			Collect: func(ctx context.Context, socket string) antispam.HostFacts {
				sockets = append(sockets, socket)
				select {
				case <-release:
				case <-ctx.Done():
				}
				return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}}
			},
			Now: time.Now,
		})
		stop := antispamTestShutdown(t, d)
		d.startAntispam()
		synctest.Wait()
		if !reflect.DeepEqual(sockets, []string{"/run/rspamd/first.sock"}) {
			t.Fatalf("startup sockets: %v", sockets)
		}
		reloaded := *cfg
		reloaded.EmailProtection.Antispam.RspamdSocket = "/run/rspamd/latest.sock"
		config.SetActive(&reloaded)
		for range 20 {
			go d.reconcileAntispam()
		}
		synctest.Wait()
		if len(sockets) != 1 {
			t.Fatalf("reload overlapped the running pass: %v", sockets)
		}
		close(release)
		synctest.Wait()
		if want := []string{"/run/rspamd/first.sock", "/run/rspamd/latest.sock"}; !reflect.DeepEqual(sockets, want) {
			t.Fatalf("pass sockets: %v, want %v", sockets, want)
		}
		stop()
	})
}

func TestAntispamShutdownDuringPassPreservesFindings(t *testing.T) {
	for _, stage := range []string{"collection", "worker"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				usePanel(t, platform.PanelCPanel)
				d := newTestDaemon(t)
				cfg := &config.Config{}
				cfg.EmailProtection.Antispam.Enabled = stage == "collection"
				useActiveConfig(t, cfg)
				d.reportAntispam(reconcile.Outcome{Findings: []alert.Finding{
					antispamFinding(reconcile.CheckPrecondition, "precondition"),
					antispamFinding(reconcile.CheckApplyFailed, "apply failed"),
				}})
				before := d.store.LatestFindings()
				drainAlertCh(d)
				passes := 0
				useAntispamReconciler(t, reconcile.Reconciler{
					Collect: func(ctx context.Context, _ string) antispam.HostFacts {
						passes++
						<-ctx.Done()
						return antispam.HostFacts{}
					},
					Installed: func() antispam.HostFacts {
						// A stale record still needs removal after the other
						// integration directories have disappeared.
						facts := antispam.HostFacts{Record: antispam.RecordFacts{Content: "stale"}}
						for _, target := range antispam.MutationTargets() {
							facts.Targets = append(facts.Targets, antispam.TargetFacts{Target: target, Err: fs.ErrNotExist})
						}
						return facts
					},
					Run: func(ctx context.Context, req antispam.Request) (antispam.Result, error) {
						if req.Operation != antispam.OpRemove {
							t.Errorf("disabled pass requested %q, want remove", req.Operation)
						}
						passes++
						<-ctx.Done()
						return antispam.Result{}, ctx.Err()
					},
					Now: time.Now,
				})
				stop := antispamTestShutdown(t, d)
				d.startAntispam()
				synctest.Wait()
				if passes != 1 {
					t.Fatalf("running passes: %d, want 1", passes)
				}
				d.reconcileAntispam()
				stop()
				if passes != 1 {
					t.Fatalf("shutdown ran a queued pass: %d", passes)
				}
				if got := d.store.LatestFindings(); !reflect.DeepEqual(got, before) {
					t.Fatalf("canceled pass changed findings: %+v, want %+v", got, before)
				}
				if got := drainAlertCh(d); len(got) != 0 {
					t.Fatalf("canceled pass sent alerts: %+v", got)
				}
			})
		})
	}
}

func TestAntispamReloadConcurrentWithStartup(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	d := newTestDaemon(t)
	useActiveConfig(t, d.cfg)
	firstPass := make(chan struct{})
	recordPass := sync.OnceFunc(func() { close(firstPass) })
	useAntispamReconciler(t, reconcile.Reconciler{
		Installed: func() antispam.HostFacts {
			recordPass()
			return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}}
		},
		Now: time.Now,
	})
	stop := antispamTestShutdown(t, d)
	started := make(chan struct{})
	go func() {
		d.startAntispam()
		close(started)
	}()
	for range 100 {
		d.reconcileAntispam()
	}
	<-started
	if d.antispamLoop.Load() == nil {
		t.Fatal("startup did not publish the loop")
	}
	waitPass(t, firstPass)
	stop()
}

func TestReportAntispamLogsErrorsOnOneLine(t *testing.T) {
	for _, err := range []error{
		errors.New("worker failed\nforged log\r\x1b[31m"),
		context.DeadlineExceeded,
		fmt.Errorf("worker: %w", context.Canceled),
	} {
		t.Run(strconv.Quote(err.Error()), func(t *testing.T) {
			d := newTestDaemon(t)
			finish := captureCSMLog(t)
			t.Cleanup(func() { finish() })
			d.reportAntispam(reconcile.Outcome{Err: err})
			got := finish()
			if errors.Is(err, context.Canceled) {
				if got != "" {
					t.Fatalf("shutdown error was logged: %q", got)
				}
				return
			}
			if strings.Count(got, "\n") != 1 || strings.ContainsAny(got, "\r\x1b") ||
				!strings.Contains(got, strconv.Quote(err.Error())) {
				t.Fatalf("worker error was not safely logged: %q", got)
			}
		})
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
	d.store.PurgeAndMergeFindings(nil, []alert.Finding{
		antispamFinding(reconcile.CheckRspamdDown, "rspamd down"),
		antispamFinding("disk_usage", "disk nearly full"),
	})
	want := map[string]int{
		reconcile.CheckRspamdDown:   1,
		"disk_usage":                1,
		reconcile.CheckPrecondition: 1,
		reconcile.CheckApplyFailed:  1,
	}
	both := []string{reconcile.CheckPrecondition, reconcile.CheckApplyFailed}
	d.reportAntispam(reconcile.Outcome{Checks: both, Findings: []alert.Finding{
		antispamFinding(reconcile.CheckPrecondition, "Antispam precondition not met: rspamd_socket"),
		antispamFinding(reconcile.CheckApplyFailed, "Antispam apply failed at exim_probe"),
	}})
	if got := latestChecks(d); !reflect.DeepEqual(got, want) {
		t.Fatalf("latest after a failed pass: %v", got)
	}
	if got := drainAlertCh(d); len(got) != 2 {
		t.Fatalf("alerts after a failed pass: %+v", got)
	}

	d.reportAntispam(reconcile.Outcome{Checks: []string{reconcile.CheckPrecondition}, Retry: reconcile.BusyRetry})
	delete(want, reconcile.CheckPrecondition)
	if got := latestChecks(d); !reflect.DeepEqual(got, want) {
		t.Fatalf("latest after a busy pass: %v", got)
	}

	d.reportAntispam(reconcile.Outcome{Err: context.Canceled})
	if got := latestChecks(d); !reflect.DeepEqual(got, want) {
		t.Fatalf("latest after a canceled pass: %v", got)
	}

	d.reportAntispam(reconcile.Outcome{Checks: both})
	delete(want, reconcile.CheckApplyFailed)
	if got := latestChecks(d); !reflect.DeepEqual(got, want) {
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
func usePing(t *testing.T, results ...error) *atomic.Int64 {
	t.Helper()
	calls := new(atomic.Int64)
	prev := antispamPing
	t.Cleanup(func() { antispamPing = prev })
	antispamPing = func(_ context.Context, socket string) (int, error) {
		if socket != testScanSocket {
			t.Errorf("probed %q", socket)
		}
		call := calls.Add(1)
		if call > int64(len(results)) {
			t.Errorf("unexpected probe %d", call)
			return -1, errors.New("unexpected probe")
		}
		return 0, results[call-1]
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

func probeTimes(d *Daemon, n int, start time.Time) {
	for i := range n {
		d.probeAntispam(context.Background(), start.Add(time.Duration(i)*20*time.Second))
	}
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

	probeTimes(d, 4, now)
	if len(*delivered) != 1 || (*delivered)[0].Check != reconcile.CheckRspamdDown {
		t.Fatalf("down notices %+v", *delivered)
	}
	if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 1 {
		t.Fatalf("latest during the outage: %v", got)
	}
	probeTimes(d, 2, now.Add(time.Minute))
	if len(*delivered) != 2 || (*delivered)[1].Check != reconcile.CheckRspamdRecovered {
		t.Fatalf("recovery notices %+v", *delivered)
	}
	if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 0 || got[reconcile.CheckRspamdRecovered] != 0 {
		t.Fatalf("latest after recovery: %v", got)
	}
	probeTimes(d, 3, now.Add(2*time.Minute))
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
	probeTimes(d, 3, time.Now())
	if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 1 || got[reconcile.CheckScanError] != 1 {
		t.Fatalf("latest while enabled: %v", got)
	}

	enableAntispam(t, d, false)
	probeTimes(d, 2, time.Now().Add(time.Minute))
	if calls.Load() != 3 {
		t.Fatalf("probes sent while disabled: %d", calls.Load()-3)
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
	refused := errors.New("connection refused")
	usePing(t, refused, refused, refused)
	delivered := captureDispatch(t)
	probeTimes(d, 2, time.Now())
	ping := antispamPing
	entered, done := make(chan struct{}), make(chan struct{})
	antispamPing = func(ctx context.Context, _ string) (int, error) {
		close(entered)
		<-ctx.Done()
		return -1, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		d.probeAntispam(ctx, time.Now())
		close(done)
	}()
	<-entered
	cancel()
	<-done
	antispamPing = ping
	if len(*delivered) != 0 || len(d.antispamHealth.Active()) != 0 {
		t.Fatalf("canceled probes raised %+v", *delivered)
	}
	probeTimes(d, 1, time.Now())
	if len(*delivered) != 1 || (*delivered)[0].Check != reconcile.CheckRspamdDown {
		t.Fatalf("cancellation changed the previous failure count: %+v", *delivered)
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

// A reload before the loop is published must still reach initial health.
func TestStartAntispamKeepsReloadDuringSetup(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	useAntispamHost(t)
	d := newTestDaemon(t)
	useActiveConfig(t, d.cfg)
	factory := antispamReconciler
	antispamReconciler = func() reconcile.Reconciler {
		cfg := &config.Config{}
		cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, DryRun: true, RspamdSocket: testScanSocket, RejectScore: 15, TagScore: 6}
		config.SetActive(cfg)
		d.reconcileAntispam()
		return factory()
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.scanCtx, d.scanCancel = ctx, cancel
	t.Cleanup(func() { cancel(); d.wg.Wait() })
	d.startAntispam()
	if got := d.antispamHealth.Line(scanErrorLine, time.Now()); len(got) != 1 || got[0].Check != reconcile.CheckScanError {
		t.Fatalf("startup lost the reloaded antispam switch: %+v", got)
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

// Every Exim main-log line reaches antispam health; scan errors count only
// while antispam is enabled.
func TestEximLogFeedsAntispamScanHealth(t *testing.T) {
	d := newTestDaemon(t)
	cfg := &config.Config{}
	scanErrors := func() int {
		n := 0
		for _, f := range d.handleEximLine(scanErrorLine, alert.Observation{}, cfg) {
			if f.Check == reconcile.CheckScanError {
				n++
			}
		}
		return n
	}
	if n := scanErrors(); n != 0 {
		t.Fatalf("disabled antispam reported %d scan errors", n)
	}
	d.antispamHealth.SetEnabled(true, testScanSocket)
	if n := scanErrors(); n != 1 {
		t.Fatalf("enabled antispam reported %d scan errors, want 1", n)
	}
}

// A config reload, from SIGHUP or a web UI save, starts a pass that reads
// the new config and points health at the new switch (spec section 4.3).
func TestConfigReloadReconcilesAntispam(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	passes := useAntispamHost(t)
	prevGuard := newForwardGuard
	t.Cleanup(func() { newForwardGuard = prevGuard })
	newForwardGuard = func() adapter.ForwardGuard { return &countingForwardGuard{} }
	d := newTestDaemon(t)
	useActiveConfig(t, d.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	d.scanCtx, d.scanCancel = ctx, cancel
	t.Cleanup(func() {
		cancel()
		d.wg.Wait()
	})
	d.startAntispam()
	waitPass(t, passes)

	cfg := &config.Config{}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, DryRun: true, RspamdSocket: testScanSocket, RejectScore: 15, TagScore: 6}
	config.SetActive(cfg)
	d.reconcileHotReloadables()
	waitPass(t, passes)
	if got := d.antispamHealth.Line(scanErrorLine, time.Now()); len(got) != 1 {
		t.Fatalf("reload left health tracking off: %+v", got)
	}
}

// rspamd that fails some scans and passes others raises and clears the scan
// error with each message. Alert state keeps that to one notice, not one
// per failed message.
func TestScanErrorFlappingAlertsOnce(t *testing.T) {
	const scanOKLine = `2026-10-13 09:00:01 1xF5ol-00000000SdL-2TMA CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`
	d := newTestDaemon(t)
	d.antispamHealth.SetEnabled(true, testScanSocket)
	notices := 0
	prev := alert.CentralHook
	t.Cleanup(func() { alert.SetCentralHook(prev) })
	alert.SetCentralHook(func(f alert.Finding) {
		if f.Check == reconcile.CheckScanError {
			notices++
		}
	})
	cfg := &config.Config{}
	for range 3 {
		d.dispatchBatch(d.handleEximLine(scanErrorLine, alert.Observation{}, cfg))
		d.dispatchBatch(d.handleEximLine(scanOKLine, alert.Observation{}, cfg))
	}
	if notices != 1 {
		t.Fatalf("flapping scans sent %d scan-error notices, want 1", notices)
	}
}

// A reload, from SIGHUP or a web UI save, must not wait for a running pass:
// a worker run can take minutes.
func TestConfigReloadDoesNotWaitForARunningPass(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	prevGuard := newForwardGuard
	t.Cleanup(func() { newForwardGuard = prevGuard })
	newForwardGuard = func() adapter.ForwardGuard { return &countingForwardGuard{} }
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	prev := antispamReconciler
	t.Cleanup(func() { antispamReconciler = prev })
	antispamReconciler = func() reconcile.Reconciler {
		return reconcile.Reconciler{
			Installed: func() antispam.HostFacts {
				started <- struct{}{}
				<-release
				return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}}
			},
			Now: time.Now,
		}
	}
	d := newTestDaemon(t)
	useActiveConfig(t, d.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	d.scanCtx, d.scanCancel = ctx, cancel
	t.Cleanup(func() {
		cancel()
		d.wg.Wait()
	})
	t.Cleanup(func() { close(release) })
	d.startAntispam()
	<-started

	done := make(chan struct{})
	go func() {
		d.reconcileHotReloadables()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reload waited for the running antispam pass")
	}
}

func TestAntispamReloadClearsLatestHealth(t *testing.T) {
	for _, disable := range []bool{true, false} {
		name := "socket change"
		if disable {
			name = "disable"
		}
		t.Run(name, func(t *testing.T) {
			d := newTestDaemon(t)
			enableAntispam(t, d, true)
			d.antispamLoop.Store(reconcile.NewLoop(nil, nil))
			refused := errors.New("connection refused")
			usePing(t, refused, refused, refused)
			delivered := captureDispatch(t)
			d.antispamHealth.Line(scanErrorLine, time.Now())
			probeTimes(d, 3, time.Now())
			if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 1 || got[reconcile.CheckScanError] != 1 {
				t.Fatalf("latest before reload: %v", got)
			}

			cfg := *d.currentCfg()
			if disable {
				cfg.EmailProtection.Antispam.Enabled = false
			} else {
				cfg.EmailProtection.Antispam.RspamdSocket = "/run/rspamd/other.sock"
			}
			config.SetActive(&cfg)
			d.reconcileAntispam()
			wantScans := 1
			if disable {
				wantScans = 0
			}
			if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 0 || got[reconcile.CheckScanError] != wantScans {
				t.Fatalf("latest immediately after reload: %v", got)
			}
			if len(*delivered) != 1 {
				t.Fatalf("reload sent a notice: %+v", *delivered)
			}
		})
	}
}

// Notification sinks must not hold up the current condition or config reload.
func TestAntispamPublishesHealthBeforeNotification(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		name := "down"
		if recovery {
			name = "recovery"
		}
		t.Run(name, func(t *testing.T) {
			d := newTestDaemon(t)
			enableAntispam(t, d, true)
			refused := errors.New("connection refused")
			usePing(t, refused, refused, refused, nil, nil)
			now := time.Now()
			before := 2
			if recovery {
				before = 4
			}
			probeTimes(d, before, now)
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			releaseDispatch := sync.OnceFunc(func() { close(release) })
			prev := alert.CentralHook
			alert.SetCentralHook(func(alert.Finding) {
				close(entered)
				<-release
			})
			t.Cleanup(func() {
				releaseDispatch()
				<-done
				alert.SetCentralHook(prev)
			})
			go func() {
				d.probeAntispam(context.Background(), now.Add(2*time.Minute))
				close(done)
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("notification did not start")
			}
			wantDown := 1
			if recovery {
				wantDown = 0
			}
			if got := latestChecks(d); got[reconcile.CheckRspamdDown] != wantDown {
				t.Errorf("latest while notification is blocked: %v", got)
			}
			cfg := *d.currentCfg()
			cfg.EmailProtection.Antispam.Enabled = false
			config.SetActive(&cfg)
			reloaded := make(chan struct{})
			t.Cleanup(func() { releaseDispatch(); <-reloaded })
			go func() {
				d.syncAntispamHealth()
				close(reloaded)
			}()
			select {
			case <-reloaded:
			case <-time.After(5 * time.Second):
				t.Fatal("notification blocked config reload")
			}
			if got := latestChecks(d); got[reconcile.CheckRspamdDown] != 0 {
				t.Errorf("disable kept latest while notification is blocked: %v", got)
			}
		})
	}
}

func TestAntispamHealthLoopProbeSchedule(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	calls := usePing(t, nil, nil)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			d.antispamHealthLoop(ctx)
			close(done)
		}()
		synctest.Wait()
		time.Sleep(19 * time.Second)
		synctest.Wait()
		if calls.Load() != 0 {
			t.Fatalf("probe ran before its interval: %d calls", calls.Load())
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("first interval: %d calls", calls.Load())
		}
		enableAntispam(t, d, false)
		time.Sleep(40 * time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("disabled loop probed: %d calls", calls.Load())
		}
		enableAntispam(t, d, true)
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatalf("re-enabled loop did not probe: %d calls", calls.Load())
		}
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("probe loop outlived shutdown")
		}
	})
}

// A socket name can be reused after a reset while an old probe is in flight.
func TestAntispamProbeIgnoresPreviousGeneration(t *testing.T) {
	for _, change := range []string{"disable and enable", "socket round trip", "unrelated reload"} {
		t.Run(change, func(t *testing.T) {
			d := newTestDaemon(t)
			enableAntispam(t, d, true)
			refused := errors.New("connection refused")
			usePing(t, refused, refused, refused, refused, refused, refused)
			delivered := captureDispatch(t)
			now := time.Now()
			probeTimes(d, 2, now)
			ping := antispamPing
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			antispamPing = func(context.Context, string) (int, error) {
				close(entered)
				<-release
				return -1, refused
			}
			go func() {
				d.probeAntispam(context.Background(), now.Add(time.Minute))
				close(done)
			}()
			<-entered
			cfg := *d.currentCfg()
			switch change {
			case "disable and enable":
				cfg.EmailProtection.Antispam.Enabled = false
			case "socket round trip":
				cfg.EmailProtection.Antispam.RspamdSocket = "/run/rspamd/other.sock"
			case "unrelated reload":
				cfg.EmailProtection.Antispam.TagScore++
			}
			config.SetActive(&cfg)
			d.syncAntispamHealth()
			enableAntispam(t, d, true)
			close(release)
			<-done
			antispamPing = ping
			if change == "unrelated reload" {
				if len(*delivered) != 1 {
					t.Fatalf("unrelated reload discarded a probe: %+v", *delivered)
				}
				return
			}
			probeTimes(d, 2, now.Add(2*time.Minute))
			if len(*delivered) != 0 || len(d.antispamHealth.Active()) != 0 {
				t.Fatalf("old probe counted toward a new outage: %+v", *delivered)
			}
			probeTimes(d, 1, now.Add(3*time.Minute))
			if len(*delivered) != 1 || (*delivered)[0].Check != reconcile.CheckRspamdDown {
				t.Fatalf("new outage did not notify: %+v", *delivered)
			}
		})
	}
}
