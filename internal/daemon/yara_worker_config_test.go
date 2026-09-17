package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/yaraworker"
)

// recordYaraWorkerArgs starts the backend against a helper that records its
// arguments and exits, and returns the flags the worker was given.
func recordYaraWorkerArgs(t *testing.T, cfg *config.Config) map[string]string {
	t.Helper()
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	worker := filepath.Join(dir, "worker")
	if err := os.WriteFile(worker, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > '"+argsPath+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: cfg, binaryPath: worker, stopCh: make(chan struct{})}
	// Avoid a retry loop after the deliberately short-lived helper exits.
	close(d.stopCh)
	if err := d.initYaraBackend(); err == nil {
		t.Fatal("argument recorder unexpectedly served YARA requests")
	}
	defer d.stopYaraBackend()
	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	values := make(map[string]string)
	for i := 1; i+1 < len(args); i += 2 {
		values[args[i]] = args[i+1]
	}
	return values
}

func TestYaraWorkerInheritsEffectiveRuleConfiguration(t *testing.T) {
	confDir := t.TempDir()
	cfg := &config.Config{ConfigFile: "/custom/csm.yaml", ConfigDir: confDir}
	cfg.Signatures.RulesDir = "/custom/rules"
	cfg.Signatures.DisabledRules = []string{"php_goto_obfuscation", "Other_Rule"}

	values := recordYaraWorkerArgs(t, cfg)

	for flag, want := range map[string]string{"--config": cfg.ConfigFile, "--inherited-config-dir": cfg.ConfigDir, "--rules-dir": cfg.Signatures.RulesDir} {
		if values[flag] != want {
			t.Errorf("%s = %q, want %q", flag, values[flag], want)
		}
	}
	var disabled []string
	if err := json.Unmarshal([]byte(values["--disabled-rules"]), &disabled); err != nil {
		t.Fatalf("missing effective disabled list: %v", err)
	}
	if !reflect.DeepEqual(disabled, cfg.Signatures.DisabledRules) {
		t.Fatalf("disabled rules = %v, want %v", disabled, cfg.Signatures.DisabledRules)
	}
}

// The daemon treats a missing conf.d as "no fragments", but the worker treats
// an explicit --config-dir that does not exist as a fatal error. The internal
// handoff must preserve the path without turning it into an operator override.
func TestYaraWorkerInheritsMissingConfigDir(t *testing.T) {
	cfg := &config.Config{ConfigFile: "/custom/csm.yaml", ConfigDir: filepath.Join(t.TempDir(), "conf.d")}
	cfg.Signatures.RulesDir = "/custom/rules"

	values := recordYaraWorkerArgs(t, cfg)

	if got, ok := values["--config-dir"]; ok {
		t.Fatalf("worker was given missing conf.d %q", got)
	}
	if got := values["--inherited-config-dir"]; got != cfg.ConfigDir {
		t.Fatalf("inherited directory = %q, want %q", got, cfg.ConfigDir)
	}
	if values["--config"] != cfg.ConfigFile {
		t.Fatalf("--config = %q, want %q", values["--config"], cfg.ConfigFile)
	}
}

// A worker that cannot start leaves every YARA scan disabled. Record it as a
// failed watcher so doctor and the status API report the outage instead of an
// overall OK, and record recovery once the backend activates.
func TestYaraWorkerStartReportsWatcherState(t *testing.T) {
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = t.TempDir()
	dir := t.TempDir()
	worker := filepath.Join(dir, "worker")
	if err := os.WriteFile(worker, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: cfg, binaryPath: worker, stopCh: make(chan struct{})}
	t.Cleanup(func() {
		close(d.stopCh)
		d.stopYaraBackend()
	})
	if err := d.initYaraBackend(); err == nil {
		t.Fatal("failing worker unexpectedly started")
	}

	attached, recorded := d.WatcherStatuses()[yaraWorkerWatcher]
	if !recorded || attached {
		t.Fatalf("failed worker start recorded=%t attached=%t, want recorded failure", recorded, attached)
	}
	snapshot := health.Snapshot{StartedAt: time.Now(), StoreHealthy: true, Watchers: d.WatcherStatuses()}
	if got := snapshot.OverallStatus(); got != "degraded" {
		t.Fatalf("failed worker health = %q, want degraded", got)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSM_DAEMON_TEST_EXECUTABLE", executable)
	t.Setenv("CSM_DAEMON_TEST_YARA_WORKER", "1")
	if err := os.WriteFile(worker+".ready", []byte("#!/bin/sh\nexec \"$CSM_DAEMON_TEST_EXECUTABLE\" -test.run=^TestYaraWorkerReadyProcess$ -- \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(worker+".ready", worker); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !d.WatcherStatuses()[yaraWorkerWatcher] && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !d.WatcherStatuses()[yaraWorkerWatcher] || d.yaraSup.ChildPID() == 0 {
		t.Fatal("worker retry did not recover watcher state")
	}
	snapshot.Watchers = d.WatcherStatuses()
	if got := snapshot.OverallStatus(); got != "ok" {
		t.Fatalf("recovered worker health = %q, want ok", got)
	}
}

func TestYaraWorkerReadyProcess(t *testing.T) {
	if os.Getenv("CSM_DAEMON_TEST_YARA_WORKER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--socket" && i+1 < len(os.Args) {
			if err := yaraworker.Run(context.Background(), yaraworker.Config{SocketPath: os.Args[i+1]}); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("missing worker socket")
}

// A worker that crashes after a healthy start is offline until the supervisor
// brings back one that stays up. The watcher follows that, so a crash loop
// keeps doctor failing instead of reporting the boot-time success.
func TestYaraWorkerCrashLoopReportsWatcherState(t *testing.T) {
	d := &Daemon{cfg: &config.Config{}, binaryPath: "/usr/local/bin/csm", stopCh: make(chan struct{})}
	cfg := d.yaraSupervisorConfig()
	if cfg.OnRestart == nil || cfg.OnStable == nil {
		t.Fatal("supervisor is not wired to report worker crashes and recovery")
	}
	d.MarkWatcher(yaraWorkerWatcher, true)

	cfg.OnRestart(139, 0, 5*time.Second)
	if attached, ok := d.WatcherStatuses()[yaraWorkerWatcher]; !ok || attached {
		t.Fatalf("crashed worker watcher recorded=%t attached=%t, want failure", ok, attached)
	}

	cfg.OnStable()
	if !d.WatcherStatuses()[yaraWorkerWatcher] {
		t.Fatal("worker that stayed up was not recorded as recovered")
	}

	// Alert throttling must never throttle the health transition.
	cfg.OnRestart(139, 0, 5*time.Second)
	if d.WatcherStatuses()[yaraWorkerWatcher] {
		t.Fatal("rate-limited crash left the worker watcher healthy")
	}
}

// During shutdown the worker exits on purpose; that must not flip the watcher.
func TestYaraWorkerWatcherIgnoresShutdownExit(t *testing.T) {
	d := &Daemon{cfg: &config.Config{}, binaryPath: "/usr/local/bin/csm", stopCh: make(chan struct{})}
	cfg := d.yaraSupervisorConfig()
	d.MarkWatcher(yaraWorkerWatcher, true)
	close(d.stopCh)

	cfg.OnRestart(0, 0, time.Minute)
	if !d.WatcherStatuses()[yaraWorkerWatcher] {
		t.Fatal("shutdown exit marked the worker watcher failed")
	}

	d.MarkWatcher(yaraWorkerWatcher, false)
	cfg.OnStable()
	if d.WatcherStatuses()[yaraWorkerWatcher] {
		t.Fatal("shutdown recovery marked the worker watcher healthy")
	}
}

// Start launches supervision before returning to the daemon. A crash in that
// window must not be erased when boot or boot-retry activation catches up.
func TestYaraWorkerActivationPreservesCrashState(t *testing.T) {
	// macOS's default temporary directory exceeds the Unix socket path limit.
	t.Setenv("TMPDIR", "/tmp")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSM_DAEMON_TEST_EXECUTABLE", executable)
	t.Setenv("CSM_DAEMON_TEST_YARA_WORKER", "1")
	dir := t.TempDir()
	worker := filepath.Join(dir, "worker")
	if writeErr := os.WriteFile(worker, []byte("#!/bin/sh\nexec \"$CSM_DAEMON_TEST_EXECUTABLE\" -test.run=^TestYaraWorkerReadyProcess$ -- \"$@\"\n"), 0700); writeErr != nil {
		t.Fatal(writeErr)
	}
	d := &Daemon{cfg: &config.Config{}, binaryPath: worker, stopCh: make(chan struct{})}
	cfg := d.yaraSupervisorConfig()
	cfg.SocketPath = filepath.Join(dir, "worker.sock")
	cfg.MinRestartInterval = time.Hour
	crashed := make(chan struct{})
	cfg.OnRestart = func(code int, sig syscall.Signal, ranFor time.Duration) {
		d.onYaraWorkerRestart(code, sig, ranFor)
		close(crashed)
	}
	sup, err := yaraworker.NewSupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.yaraSup = sup
	t.Cleanup(func() {
		close(d.stopCh)
		d.stopYaraBackend()
	})
	if startErr := sup.Start(context.Background()); startErr != nil {
		t.Fatal(startErr)
	}
	child, err := os.FindProcess(sup.ChildPID())
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-crashed:
	case <-time.After(5 * time.Second):
		t.Fatal("worker crash was not reported")
	}
	if attached, recorded := d.WatcherStatuses()[yaraWorkerWatcher]; !recorded || attached {
		t.Fatal("worker crash did not publish a failed watcher")
	}
	failedAt := d.WatcherChangedAt()[yaraWorkerWatcher]
	if failedAt.IsZero() {
		t.Fatal("worker crash did not record the outage timestamp")
	}
	d.activateYaraBackend(sup)
	if attached, recorded := d.WatcherStatuses()[yaraWorkerWatcher]; !recorded || attached {
		t.Fatal("backend activation overwrote the crashed worker's failed state")
	}
	if got := d.WatcherChangedAt()[yaraWorkerWatcher]; !got.Equal(failedAt) {
		t.Fatal("backend activation reset the worker outage timestamp")
	}
}
