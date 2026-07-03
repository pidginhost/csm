package daemon

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraworker"
)

// yaraMetricsOnce guards registration of the yara-worker restart
// counter hook so a baseline re-run or a second daemon instance in the
// same test binary does not panic with "duplicate registration".
var yaraMetricsOnce sync.Once

// yaraWorkerOn reports whether the daemon should run YARA-X in a
// supervised child process. The field is a *bool tri-state: nil means
// "use system default" (true, per ROADMAP item 2 follow-up), *true is
// explicit opt-in, *false is explicit opt-out.
//
// A nil cfg falls back to false so a pathological caller does not
// accidentally spin up a worker; production never passes nil.
func yaraWorkerOn(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.Signatures.YaraWorkerEnabled == nil {
		return true
	}
	return *cfg.Signatures.YaraWorkerEnabled
}

// initYaraBackend wires up either the out-of-process YARA-X supervisor
// (default, per ROADMAP item 2 follow-up) or the in-process scanner
// (when config.Signatures.YaraWorkerEnabled is explicitly *false).
// Both paths register themselves as the yara package's active backend
// so existing callers work unchanged.
//
// In worker mode, yara.Init is deliberately NOT called: the rule
// compile happens inside the child process, not the daemon. This is
// the point of the feature (ROADMAP item 2) — a cgo crash while
// compiling or scanning stays contained to the child. Matches carry
// string-valued rule metadata (see yara.Match.Meta / yaraipc.Match.Meta)
// so the emailav YARA-X adapter works identically under both backends
// — severity no longer needs the in-process *yara_x.Rules object.
func (d *Daemon) initYaraBackend() error {
	if !yaraWorkerOn(d.cfg) {
		if yaraScanner := yara.Init(d.cfg.Signatures.RulesDir); yaraScanner != nil {
			fmt.Fprintf(os.Stderr, "[%s] YARA-X scanner active: %d rule file(s)\n", ts(), yaraScanner.RuleCount())
		}
		return nil
	}

	sup, err := yaraworker.NewSupervisor(yaraworker.SupervisorConfig{
		BinaryPath:         d.binaryPath,
		SocketPath:         yaraworker.DefaultSocketPath(),
		RulesDir:           d.cfg.Signatures.RulesDir,
		StartTimeout:       10 * time.Second,
		MinRestartInterval: time.Second,
		MaxRestartInterval: 60 * time.Second,
		StableDuration:     30 * time.Second,
		ClientTimeout:      30 * time.Second,
		OnRestart:          d.onYaraWorkerRestart,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[%s] yara-worker: "+format+"\n", append([]any{ts()}, args...)...)
		},
	})
	if err != nil {
		return fmt.Errorf("creating yara-worker supervisor: %w", err)
	}
	// Own the supervisor before the first Start attempt. If startup fails and
	// the retry goroutine is still trying to bring it online when the daemon
	// stops, stopYaraBackend can cancel/kill that in-flight Start instead of
	// leaving an orphaned worker attempt outside shutdown ownership.
	d.yaraSup = sup
	if err := sup.Start(context.Background()); err != nil {
		// A boot-time start failure must not disable YARA for the daemon's
		// whole lifetime. Retry in the background with backoff and raise a
		// finding once the failure looks persistent, mirroring the
		// post-start crash path (onYaraWorkerRestart). The daemon keeps
		// running; scanning comes online once the worker starts.
		obs.Go("yara-init-retry", func() { d.retryYaraStart(sup) })
		return fmt.Errorf("starting yara-worker (retrying in background): %w", err)
	}

	d.activateYaraBackend(sup)
	return nil
}

// activateYaraBackend installs a started supervisor as the active YARA
// backend, wires its restart metric, and surfaces a still-broken rule compile
// as a finding so a worker that is up but scanning nothing is visible instead
// of masquerading as a healthy zero-rule host.
func (d *Daemon) activateYaraBackend(sup *yaraworker.Supervisor) {
	yara.SetActive(sup)

	// Expose the supervisor's cumulative restart count to Prometheus.
	// Registered once per process; subsequent calls re-point nothing
	// (the closure captures `sup`, and a second daemon.Run in the
	// same process would need to arrange for the metric to follow).
	yaraMetricsOnce.Do(func() {
		metrics.RegisterCounterFunc(
			"csm_yara_worker_restarts_total",
			"Number of times the YARA-X worker subprocess has been restarted by its supervisor.",
			func() float64 { return float64(sup.RestartCount()) },
		)
	})

	fmt.Fprintf(os.Stderr,
		"[%s] YARA-X worker active: %d rule(s) compiled in child process (pid=%d)\n",
		ts(), sup.RuleCount(), sup.ChildPID())

	d.reportYaraCompileStatus(sup.CompileError())
}

// retryYaraStart re-attempts a failed worker start with capped exponential
// backoff until it succeeds or the daemon stops, raising one finding once the
// failure is persistent so the outage is visible.
func (d *Daemon) retryYaraStart(sup *yaraworker.Supervisor) {
	ok := retryStartWithStopContext(
		func(ctx context.Context) error { return sup.Start(ctx) },
		d.stopCh,
		time.Second, 60*time.Second, 3,
		func(attempt int, err error) {
			d.emitYaraFinding(alert.Critical, "yara_backend_unavailable",
				fmt.Sprintf("YARA-X worker has failed to start %d times (%v); real-time malware scanning is disabled while the supervisor keeps retrying.", attempt, err))
		},
	)
	if !ok {
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] yara-worker started after retrying a failed boot\n", ts())
	d.activateYaraBackend(sup)
}

func retryStartWithStopContext(start func(context.Context) error, stop <-chan struct{}, minBackoff, maxBackoff time.Duration, alertAfter int, onPersistent func(attempt int, err error)) bool {
	ctx, cancel := context.WithCancel(context.Background())
	retryDone := make(chan struct{})
	obs.Go("yara-init-retry-stop", func() {
		select {
		case <-stop:
			cancel()
		case <-retryDone:
		}
	})
	ok := retryStart(
		func() error { return start(ctx) },
		stop,
		minBackoff, maxBackoff, alertAfter,
		onPersistent,
	)
	close(retryDone)
	if !ok {
		cancel()
	}
	return ok
}

// retryStart calls start with capped exponential backoff until it returns nil,
// stop is signalled, or forever. onPersistent, if set, fires exactly once
// after alertAfter consecutive failures so a persistent outage raises a single
// finding. Returns true if start eventually succeeded.
func retryStart(start func() error, stop <-chan struct{}, minBackoff, maxBackoff time.Duration, alertAfter int, onPersistent func(attempt int, err error)) bool {
	backoff := minBackoff
	for attempt := 1; ; attempt++ {
		select {
		case <-time.After(backoff):
		case <-stop:
			return false
		}
		if err := start(); err == nil {
			return true
		} else if attempt == alertAfter && onPersistent != nil {
			onPersistent(attempt, err)
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// reportYaraCompileStatus raises a finding when the worker is alive but its
// rules failed to compile. A clean compile ("") is silent.
func (d *Daemon) reportYaraCompileStatus(compileErr string) {
	if compileErr == "" {
		return
	}
	d.emitYaraFinding(alert.Critical, "yara_worker_compile_failed",
		fmt.Sprintf("YARA-X worker is up but its rules failed to compile: %s. Real-time malware scanning is disabled until the rules are fixed and reloaded.", compileErr))
}

// emitYaraFinding pushes a finding without blocking; a saturated alert channel
// is accounted for by the daemon's general drop counter.
func (d *Daemon) emitYaraFinding(sev alert.Severity, check, msg string) {
	finding := alert.Finding{Severity: sev, Check: check, Message: msg}
	select {
	case d.alertCh <- finding:
	default:
	}
}

// stopYaraBackend is called during daemon shutdown. Safe to call when
// worker mode is off.
func (d *Daemon) stopYaraBackend() {
	if d.yaraSup == nil {
		return
	}
	if err := d.yaraSup.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] yara-worker stop: %v\n", ts(), err)
	}
	yara.SetActive(nil)
}

// onYaraWorkerRestart is called once per unplanned worker exit. Emits
// a Critical finding the first time, then one every minute after to
// avoid spamming alerts while a broken rule package is in place.
func (d *Daemon) onYaraWorkerRestart(exitCode int, sig syscall.Signal, ranFor time.Duration) {
	now := time.Now()
	d.yaraCrashMu.Lock()
	last := d.yaraLastCrashAlert
	d.yaraLastCrashAlert = now
	d.yaraCrashMu.Unlock()

	fmt.Fprintf(os.Stderr, "[%s] yara-worker exited code=%d signal=%v ran=%s\n",
		ts(), exitCode, sig, ranFor.Round(time.Millisecond))

	if !last.IsZero() && now.Sub(last) < time.Minute {
		return
	}

	finding := alert.Finding{
		Severity: alert.Critical,
		Check:    "yara_worker_crashed",
		Message:  fmt.Sprintf("YARA-X worker crashed (exit=%d signal=%v after %s); supervisor restarted it, real-time scanning recovered.", exitCode, sig, ranFor.Round(time.Millisecond)),
	}
	select {
	case d.alertCh <- finding:
	default:
		// Channel saturated; the daemon's general drop-counter path
		// already tracks this.
	}
}
