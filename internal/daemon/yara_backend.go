package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraworker"
)

// yaraMetricsOnce guards registration of the yara-worker failure
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

// yaraWorkerWatcher names the YARA-X worker in the watcher status map.
const yaraWorkerWatcher = "yara_worker"

// Limits for the YARA worker units. A scan gets as long as the old socket
// client allowed. A fresh worker loading Forge full takes about 3.4 s, and
// compiling it about 10 s.
const (
	yaraScanTimeout    = 30 * time.Second
	yaraLoadTimeout    = 60 * time.Second
	yaraCompileTimeout = 2 * time.Minute
)

// yaraWorkerLauncher is a seam for tests that must not start units.
var yaraWorkerLauncher = workerproc.UnitLauncher

// yaraEngineAvailable is a seam: plain-build tests force the yara build's
// answer.
var yaraEngineAvailable = yara.Available

// maxYaraFindingErr bounds the worker error text a finding quotes.
const maxYaraFindingErr = 512

// initYaraBackend wires up either the locked-down worker backend (default)
// or the in-process scanner (when config.Signatures.YaraWorkerEnabled is
// explicitly *false). Both register as the yara package's active backend.
//
// In worker mode the daemon never compiles or scans: rules compile in a
// short-lived compile unit and scans run in a scan unit, both without root,
// network or host files. The backend is installed before the first compile,
// so a compile that cannot run leaves scans failing closed rather than YARA
// skipped.
func (d *Daemon) initYaraBackend() error {
	if !yaraWorkerOn(d.cfg) {
		if yaraScanner := yara.Init(d.cfg.Signatures.RulesDir, d.cfg.Signatures.DisabledRules...); yaraScanner != nil {
			fmt.Fprintf(os.Stderr, "[%s] YARA-X scanner active: %d rule file(s)\n", ts(), yaraScanner.RuleCount())
		}
		return nil
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[%s] yara-worker: "+format+"\n", append([]any{ts()}, args...)...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	for _, prefix := range []string{yaraworker.ScanUnitPrefix, yaraworker.CompileUnitPrefix} {
		if err := stopParseWorkerUnits(ctx, prefix+"-"); err != nil {
			logf("stop leftover units: %v", err)
		}
	}
	cancel()
	hidden := parseWorkerHiddenPaths()
	// #nosec G115 -- FullScanMaxFileBytes is positive and at most 4 GiB.
	scanUnit := yaraworker.ScanUnitConfig(d.binaryPath, yaraworker.ScanMemoryBase+uint64(checks.FullScanMaxFileBytes(d.cfg)), logf)
	scanUnit.InaccessiblePaths = hidden
	compileUnit := yaraworker.CompileUnitConfig(d.binaryPath, logf)
	compileUnit.InaccessiblePaths = hidden
	b, err := yaraworker.NewBackend(yaraworker.BackendConfig{
		ScanLaunch:      d.checkedYaraLauncher(yaraWorkerLauncher(scanUnit)),
		CompileLaunch:   d.checkedYaraLauncher(yaraWorkerLauncher(compileUnit)),
		RulesDir:        d.cfg.Signatures.RulesDir,
		DisabledRules:   d.cfg.Signatures.DisabledRules,
		ScanTimeout:     yaraScanTimeout,
		LoadTimeout:     yaraLoadTimeout,
		CompileTimeout:  yaraCompileTimeout,
		OnFailure:       d.onYaraWorkerFailure,
		OnJob:           d.onYaraWorkerJob,
		Log:             logf,
		WarmAfterReload: true,
	})
	if err != nil {
		return fmt.Errorf("creating yara worker backend: %w", err)
	}
	d.yaraSup = b
	yara.SetActive(b)
	d.registerQueueSource("yara", b)
	yaraMetricsOnce.Do(func() {
		metrics.RegisterCounterFunc(
			"csm_yara_worker_restarts_total",
			"Number of counted YARA-X scan worker failures, including failed starts.",
			func() float64 {
				var total uint64
				for _, n := range b.Stats().Kills {
					total += n
				}
				return float64(total)
			},
		)
	})
	if !yaraEngineAvailable() {
		fmt.Fprintf(os.Stderr, "[%s] %s\n", ts(), yaraWorkerStatusLine(0))
		return nil
	}

	err = b.Reload()
	switch {
	case err == nil:
		d.activateYaraBackend(b)
		return nil
	case retryableYaraCompile(err):
		// The compile worker could not run: every YARA scan fails until it
		// does. Report it where doctor and the status API look, and keep
		// trying in the background.
		d.MarkWatcher(yaraWorkerWatcher, false)
		obs.Go("yara-init-retry", func() { d.retryYaraStart(b) })
		return fmt.Errorf("compiling yara rules (retrying in background): %w", err)
	default:
		d.MarkWatcher(yaraWorkerWatcher, false)
		fmt.Fprintf(os.Stderr, "[%s] %s\n", ts(), yaraWorkerStatusLine(0))
		d.reportYaraCompileStatus(b.CompileError())
		d.reportRealtimeRuleCoverage(yamlRuleCount(), 0, false)
		return nil
	}
}

func retryableYaraCompile(err error) bool {
	// Descriptor pressure belongs to the daemon, so workerproc deliberately
	// leaves it out of worker failure accounting. It still needs a retry.
	return workerproc.FailureReason(err) != "" || errors.Is(err, workerproc.ErrSpawn) ||
		errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// checkedYaraLauncher refuses each launch while the dynamic user cannot run
// the binary, so the failure reaches the scan as an error instead of every
// unit failing at exec.
func (d *Daemon) checkedYaraLauncher(launch workerproc.Launcher) workerproc.Launcher {
	return func(ctx context.Context) (workerproc.Process, error) {
		if err := checkParseWorkerCommand(d.binaryPath); err != nil {
			return nil, fmt.Errorf("yara worker: %w", err)
		}
		return launch(ctx)
	}
}

// activateYaraBackend reports a backend whose rules compiled. The watcher is
// left to the scan worker's own requests, so activation cannot erase a
// failure seen in the meantime.
func (d *Daemon) activateYaraBackend(b *yaraworker.Backend) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", ts(), yaraWorkerStatusLine(b.RuleCount()))
	d.reportRealtimeRuleCoverage(yamlRuleCount(), b.RuleCount(), true)
}

// yaraWorkerStatusLine describes the compiled rules at startup. A worker with
// zero rules matches nothing, so it must not be called active: that wording
// let a host report a healthy scanner while every scan checked against an
// empty rule set.
func yaraWorkerStatusLine(ruleCount int) string {
	if ruleCount == 0 {
		return "YARA-X worker has 0 rules compiled - scanning nothing until rules load"
	}
	return fmt.Sprintf("YARA-X worker active: %d rule(s) compiled, scanning in a locked-down unit", ruleCount)
}

// retryYaraStart re-attempts a first compile whose worker could not run, with
// capped exponential backoff, until it runs or the daemon stops, raising one
// finding once the failure is persistent. A compile that runs and finds the
// rules broken ends the retries: recompiling would fail the same way.
func (d *Daemon) retryYaraStart(b *yaraworker.Backend) {
	var rulesErr error
	ok := retryStartWithStopContext(
		func(ctx context.Context) error {
			err := b.ReloadContext(ctx)
			if err != nil && !retryableYaraCompile(err) {
				rulesErr = err
				return nil
			}
			return err
		},
		d.stopCh,
		time.Second, 60*time.Second, 3,
		func(attempt int, err error) {
			d.emitYaraFinding(alert.Critical, "yara_backend_unavailable",
				fmt.Sprintf("YARA-X rules could not be compiled: the compile worker failed %d times (%v). Files and mail parts are reported as not scanned while CSM keeps retrying.", attempt, err))
		},
	)
	if !ok {
		return
	}
	if rulesErr != nil {
		d.reportYaraCompileStatus(b.CompileError())
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] yara rules compiled after retrying\n", ts())
	if b.RuleCount() == 0 {
		// No scan worker is needed, and the compile worker just ran.
		d.MarkWatcher(yaraWorkerWatcher, true)
	}
	d.activateYaraBackend(b)
}

func retryStartWithStopContext(start func(context.Context) error, stop <-chan struct{}, minBackoff, maxBackoff time.Duration, alertAfter int, onPersistent func(attempt int, err error)) bool {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
		if stopRequested(stop) {
			return false
		}
		if err := start(); err == nil {
			return !stopRequested(stop)
		} else if attempt == alertAfter && onPersistent != nil {
			if stopRequested(stop) {
				return false
			}
			onPersistent(attempt, err)
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func stopRequested(stop <-chan struct{}) bool {
	if stop == nil {
		return false
	}
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

// reportYaraCompileStatus raises a finding when the rules failed to compile
// and none are loaded. A clean compile ("") is silent.
func (d *Daemon) reportYaraCompileStatus(compileErr string) {
	if compileErr == "" {
		return
	}
	d.emitYaraFinding(alert.Critical, "yara_worker_compile_failed",
		fmt.Sprintf("YARA-X rules failed to compile: %s. Files and mail parts are reported as not scanned by YARA until the rules are fixed and reloaded.", compileErr))
}

// emitYaraFinding pushes a finding without blocking; a saturated alert channel
// is accounted for by the daemon's general drop counter.
func (d *Daemon) emitYaraFinding(sev alert.Severity, check, msg string) bool {
	if stopRequested(d.stopCh) {
		return false
	}
	finding := alert.Finding{Severity: sev, Check: check, Message: msg, Timestamp: time.Now()}
	if alert.TryEnqueue(d.alertCh, finding) {
		return true
	} else {
		atomic.AddInt64(&d.droppedAlerts, 1)
		return false
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

// onYaraWorkerJob marks the worker attached after a served request. It runs
// under the worker supervisor's lock and only takes the watcher lock.
func (d *Daemon) onYaraWorkerJob(outcome string, _ uint64) {
	if outcome != workerproc.OutcomeOK || stopRequested(d.stopCh) {
		return
	}
	d.MarkWatcher(yaraWorkerWatcher, true)
}

// onYaraWorkerFailure is called once per counted scan worker failure. It
// marks the watcher failed and emits a Critical finding at most once a
// minute: a file that kills the worker on every scan must not become one
// alert per scan. It runs under the worker supervisor's lock and must not
// block.
func (d *Daemon) onYaraWorkerFailure(reason string, err error) {
	// stopCh closes at the top of shutdown; workers stopped from then on are
	// not failures. A nil stopCh (zero-value Daemon, several tests) means
	// running.
	if stopRequested(d.stopCh) {
		return
	}
	now := time.Now()
	d.yaraCrashMu.Lock()
	d.MarkWatcher(yaraWorkerWatcher, false)
	last := d.yaraLastCrashAlert
	d.yaraLastCrashAlert = now
	d.yaraCrashMu.Unlock()
	if !last.IsZero() && now.Sub(last) < time.Minute {
		return
	}
	detail := err.Error()
	if len(detail) > maxYaraFindingErr {
		detail = strings.ToValidUTF8(detail[:maxYaraFindingErr], "") + "..."
	}
	alert.TryEnqueue(d.alertCh, alert.Finding{
		Severity:  alert.Critical,
		Check:     "yara_worker_crashed",
		Timestamp: now,
		Message:   fmt.Sprintf("YARA-X worker failed (%s: %s); files and mail parts are reported as not scanned until a replacement worker loads the rules.", reason, detail),
	})
}
