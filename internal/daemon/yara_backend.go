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
	if err := sup.Start(context.Background()); err != nil {
		return fmt.Errorf("starting yara-worker: %w", err)
	}

	d.yaraSup = sup
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
	return nil
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
