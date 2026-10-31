package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraworker"
)

// stubYaraUnits replaces the unit seams, records what init asked for, and
// makes every launch fail unless launch is given.
func stubYaraUnits(t *testing.T, engine bool, launch workerproc.Launcher) (stopped *[]string, units *[]workerproc.UnitConfig) {
	t.Helper()
	stopped, units = new([]string), new([]workerproc.UnitConfig)
	realStop, realLauncher, realHidden, realEngine := stopParseWorkerUnits, yaraWorkerLauncher, parseWorkerHiddenPaths, yaraEngineAvailable
	stopParseWorkerUnits = func(_ context.Context, prefix string) error {
		*stopped = append(*stopped, prefix)
		return nil
	}
	yaraWorkerLauncher = func(cfg workerproc.UnitConfig) workerproc.Launcher {
		*units = append(*units, cfg)
		if launch != nil {
			return launch
		}
		return func(context.Context) (workerproc.Process, error) { return nil, errors.New("no units in tests") }
	}
	parseWorkerHiddenPaths = func() []string { return []string{"/home2"} }
	yaraEngineAvailable = func() bool { return engine }
	t.Cleanup(func() {
		stopParseWorkerUnits, yaraWorkerLauncher, parseWorkerHiddenPaths, yaraEngineAvailable = realStop, realLauncher, realHidden, realEngine
	})
	return stopped, units
}

func yaraWorkerDaemon(t *testing.T, cfg *config.Config) *Daemon {
	t.Helper()
	if cfg.Signatures.RulesDir == "" {
		cfg.Signatures.RulesDir = t.TempDir()
	}
	d := &Daemon{cfg: cfg, binaryPath: "/opt/csm/csm", stopCh: make(chan struct{}), alertCh: make(chan alert.Finding, 16)}
	t.Cleanup(func() {
		close(d.stopCh)
		d.stopYaraBackend()
	})
	return d
}

func TestInitYaraBackendStopsLeftoverUnits(t *testing.T) {
	stopped, _ := stubYaraUnits(t, false, nil)
	allowParseWorkerCommand(t)
	d := yaraWorkerDaemon(t, &config.Config{})
	if err := d.initYaraBackend(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"csm-yara-worker-", "csm-yara-compile-worker-"}; !slices.Equal(*stopped, want) {
		t.Fatalf("leftover units stopped with %q, want %q", *stopped, want)
	}
	if yara.Active() != yara.Backend(d.yaraSup) {
		t.Fatal("the worker backend is not the active YARA backend")
	}
	if _, ok := d.QueueStatuses()["yara.requests"]; !ok {
		t.Fatal("the YARA worker queue is not published")
	}
}

func TestInitYaraBackendScanMemoryFollowsFileCap(t *testing.T) {
	_, units := stubYaraUnits(t, false, nil)
	allowParseWorkerCommand(t)
	cfg := &config.Config{}
	cfg.Thresholds.FullScanMaxFileMB = 64
	d := yaraWorkerDaemon(t, cfg)
	if err := d.initYaraBackend(); err != nil {
		t.Fatal(err)
	}
	if len(*units) != 2 {
		t.Fatalf("unit configs = %d, want scan and compile", len(*units))
	}
	scan, compile := (*units)[0], (*units)[1]
	if scan.Prefix != yaraworker.ScanUnitPrefix || scan.MemoryLimit != 512<<20+64<<20 {
		t.Fatalf("scan unit %q memory %d, want 576 MiB", scan.Prefix, scan.MemoryLimit)
	}
	if compile.Prefix != yaraworker.CompileUnitPrefix || compile.MemoryLimit != 1<<30 {
		t.Fatalf("compile unit %q memory %d", compile.Prefix, compile.MemoryLimit)
	}
	for _, u := range []workerproc.UnitConfig{scan, compile} {
		if u.Command != d.binaryPath || !slices.Equal(u.InaccessiblePaths, []string{"/home2"}) || !u.AllowExecutableMemory {
			t.Fatalf("unit %q runs %q, hides %q, executable memory %v", u.Prefix, u.Command, u.InaccessiblePaths, u.AllowExecutableMemory)
		}
	}
}

// A compile unit that cannot start must not leave YARA silently off: the
// backend is active and every scan errors, the watcher reports the outage,
// and a background retry keeps trying.
func TestInitYaraBackendCompileUnavailableFailsClosed(t *testing.T) {
	var launches atomic.Int32
	stubYaraUnits(t, true, func(context.Context) (workerproc.Process, error) {
		launches.Add(1)
		return nil, errors.New("systemd-run unavailable")
	})
	allowParseWorkerCommand(t)
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = filepath.Join(t.TempDir(), "rules")
	if err := os.Mkdir(cfg.Signatures.RulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Signatures.RulesDir, "rules.yar"), []byte("rule r { condition: true }"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := yaraWorkerDaemon(t, cfg)
	if err := d.initYaraBackend(); err == nil {
		t.Fatal("init reported success with no compile worker")
	}
	backend := yara.Active()
	if backend == nil || backend != yara.Backend(d.yaraSup) {
		t.Fatal("YARA is not active while the compile worker is down; scans would skip it silently")
	}
	if m, err := yara.ScanBytesChecked(backend, "x.php", []byte("<?php echo 1;")); err == nil {
		t.Fatalf("byte scan read clean with no compiled rules: %+v", m)
	}
	part := filepath.Join(t.TempDir(), "part")
	if err := os.WriteFile(part, []byte("part"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(part)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := yara.ScanFileDescriptorChecked(backend, f, 4); err == nil {
		t.Fatal("mail part scan read clean with no compiled rules")
	}
	attached, recorded := d.WatcherStatuses()[yaraWorkerWatcher]
	if !recorded || attached {
		t.Fatalf("watcher recorded=%t attached=%t, want a recorded failure", recorded, attached)
	}
	snapshot := health.Snapshot{StartedAt: time.Now(), StoreHealthy: true, Watchers: d.WatcherStatuses()}
	if got := snapshot.OverallStatus(); got != "degraded" {
		t.Fatalf("health = %q, want degraded", got)
	}
	first := launches.Load()
	deadline := time.Now().Add(5 * time.Second)
	for launches.Load() == first && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if launches.Load() == first {
		t.Fatal("no background retry of the compile")
	}
}

// The watcher follows the scan worker: a failure marks it failed, a served
// request marks it attached, alert throttling never throttles the health
// transition, activation does not erase a failure, and shutdown changes
// nothing.
func TestYaraWorkerWatcherFollowsJobs(t *testing.T) {
	d := &Daemon{cfg: &config.Config{}, stopCh: make(chan struct{}), alertCh: make(chan alert.Finding, 16)}
	status := func() bool { return d.WatcherStatuses()[yaraWorkerWatcher] }

	d.onYaraWorkerJob(workerproc.OutcomeOK, 0)
	if !status() {
		t.Fatal("a served request did not mark the worker attached")
	}
	d.onYaraWorkerFailure(workerproc.ReasonCrash, errWorkerDied)
	if status() {
		t.Fatal("a failure left the worker attached")
	}
	d.onYaraWorkerJob(workerproc.OutcomeOK, 0)
	d.onYaraWorkerFailure(workerproc.ReasonCrash, errWorkerDied) // rate-limited alert
	if status() {
		t.Fatal("a rate-limited failure left the worker attached")
	}
	d.onYaraWorkerJob(workerproc.ReasonTimeout, 0)
	if status() {
		t.Fatal("a failed outcome marked the worker attached")
	}

	b, err := yaraworker.NewBackend(yaraworker.BackendConfig{
		ScanLaunch:     func(context.Context) (workerproc.Process, error) { return nil, errors.New("unused") },
		CompileLaunch:  func(context.Context) (workerproc.Process, error) { return nil, errors.New("unused") },
		ScanTimeout:    time.Second,
		LoadTimeout:    time.Second,
		CompileTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Stop() }()
	d.activateYaraBackend(b)
	if status() {
		t.Fatal("activation erased a worker failure")
	}

	d.MarkWatcher(yaraWorkerWatcher, true)
	close(d.stopCh)
	d.onYaraWorkerFailure(workerproc.ReasonCrash, errWorkerDied)
	if !status() {
		t.Fatal("a failure during shutdown marked the worker failed")
	}
	d.MarkWatcher(yaraWorkerWatcher, false)
	d.onYaraWorkerJob(workerproc.OutcomeOK, 0)
	if status() {
		t.Fatal("a request during shutdown marked the worker attached")
	}
}

// The boot compile runs before the daemon tells systemd it is ready, so it
// is bounded: a compile that has not finished hands over to the background
// retry instead of holding startup past systemd's start timeout.
func TestInitYaraBackendBootCompileIsBounded(t *testing.T) {
	var launches atomic.Int32
	stubYaraUnits(t, true, func(ctx context.Context) (workerproc.Process, error) {
		launches.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	allowParseWorkerCommand(t)
	realBoot := yaraBootCompileTimeout
	yaraBootCompileTimeout = 200 * time.Millisecond
	t.Cleanup(func() { yaraBootCompileTimeout = realBoot })
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = filepath.Join(t.TempDir(), "rules")
	if err := os.Mkdir(cfg.Signatures.RulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Signatures.RulesDir, "rules.yar"), []byte("rule r { condition: true }"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := yaraWorkerDaemon(t, cfg)
	began := time.Now()
	if err := d.initYaraBackend(); err == nil {
		t.Fatal("init reported success while the boot compile hung")
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("boot compile held startup for %s", took)
	}
	if d.yaraSup.CompileError() == "" {
		t.Fatal("a boot compile that never finished left scans answering as if rules were empty")
	}
	deadline := time.Now().Add(5 * time.Second)
	for launches.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if launches.Load() < 2 {
		t.Fatal("a timed-out boot compile was not retried in the background")
	}
}
