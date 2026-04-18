package daemon

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraworker"
)

// initYaraBackend wires up either the in-process YARA-X scanner
// (default) or the out-of-process supervisor (when
// config.Signatures.YaraWorkerEnabled is true). Both paths register
// themselves as the yara package's active backend so existing callers
// work unchanged.
//
// In worker mode, yara.Init is deliberately NOT called: the rule
// compile happens inside the child process, not the daemon. This is
// the point of the feature (ROADMAP item 2) — a cgo crash while
// compiling or scanning stays contained to the child. The known
// regression is that the emailav YARA-X adapter cannot reach
// *yara_x.Rules across a process boundary yet, so emailav falls back
// to ClamAV-only when worker mode is on. Extending the wire protocol
// to carry severity metadata for emailav is tracked separately.
func (d *Daemon) initYaraBackend() error {
	if !d.cfg.Signatures.YaraWorkerEnabled {
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

	fmt.Fprintf(os.Stderr,
		"[%s] YARA-X worker active: %d rule(s) compiled in child process (pid=%d)\n",
		ts(), sup.RuleCount(), sup.ChildPID())
	fmt.Fprintf(os.Stderr,
		"[%s] yara-worker: emailav YARA-X disabled under worker mode; ClamAV unchanged\n", ts())
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
