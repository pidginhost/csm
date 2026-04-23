package daemon

import (
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// newDaemonForYaraBackendTest builds a Daemon minimal enough to drive
// the non-worker branch of initYaraBackend, all of stopYaraBackend, and
// every rate-limit arm of onYaraWorkerRestart.
func newDaemonForYaraBackendTest(t *testing.T) *Daemon {
	t.Helper()
	return &Daemon{
		cfg:     &config.Config{},
		alertCh: make(chan alert.Finding, 8),
	}
}

// --- initYaraBackend --------------------------------------------------

// With YaraWorkerEnabled=false (the default) initYaraBackend calls
// yara.Init(rulesDir) and returns. Under the non-yara build tag Init
// returns nil, under the yara build tag it returns an empty-rules
// scanner. Either way the function must succeed without touching the
// worker supervisor.
func TestInitYaraBackendInProcessPath(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	f := false
	d.cfg.Signatures.YaraWorkerEnabled = &f
	d.cfg.Signatures.RulesDir = t.TempDir()

	if err := d.initYaraBackend(); err != nil {
		t.Fatalf("initYaraBackend in-process: %v", err)
	}
	if d.yaraSup != nil {
		t.Errorf("yaraSup must stay nil when worker mode is off, got %v", d.yaraSup)
	}
}

// --- stopYaraBackend --------------------------------------------------

// The nil-yaraSup branch is the common case: in-process mode leaves
// the supervisor unset, and shutdown must not panic.
func TestStopYaraBackendNoSupervisorIsNoop(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	// Just calling this on a bare Daemon is the regression the test
	// locks in; a panic or nil-deref here would break shutdown.
	d.stopYaraBackend()
}

// --- onYaraWorkerRestart ----------------------------------------------

func TestOnYaraWorkerRestartFirstCallEmitsCriticalFinding(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)

	d.onYaraWorkerRestart(1, syscall.SIGSEGV, 5*time.Second)

	select {
	case f := <-d.alertCh:
		if f.Severity != alert.Critical {
			t.Errorf("severity: got %v, want Critical", f.Severity)
		}
		if f.Check != "yara_worker_crashed" {
			t.Errorf("check: got %q", f.Check)
		}
		if f.Message == "" {
			t.Error("message must not be empty")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no finding emitted on first crash")
	}
}

// Two crashes within a minute: the second must be rate-limited
// regardless of how extreme the signal is. The alert channel receives
// exactly one finding.
func TestOnYaraWorkerRestartRateLimitsWithinOneMinute(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)

	d.onYaraWorkerRestart(1, syscall.SIGSEGV, time.Second)
	d.onYaraWorkerRestart(1, syscall.SIGSEGV, time.Second)

	// One finding, then nothing within a reasonable window.
	select {
	case <-d.alertCh:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected one finding on alertCh")
	}
	select {
	case f := <-d.alertCh:
		t.Errorf("second crash within 60s must be suppressed, got %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
}

// If the last-alert timestamp is older than a minute, the next crash
// emits a fresh finding. Simulated by writing yaraLastCrashAlert
// directly into the past.
func TestOnYaraWorkerRestartEmitsAgainAfterOneMinute(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.yaraCrashMu.Lock()
	d.yaraLastCrashAlert = time.Now().Add(-2 * time.Minute)
	d.yaraCrashMu.Unlock()

	d.onYaraWorkerRestart(2, syscall.SIGABRT, 500*time.Millisecond)

	select {
	case f := <-d.alertCh:
		if f.Check != "yara_worker_crashed" {
			t.Errorf("check: got %q", f.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected a finding after the rate-limit window expired")
	}
}

// Channel saturation must be swallowed silently -- the comment in
// onYaraWorkerRestart explains the daemon's general drop-counter
// tracks it elsewhere, so this function's `default` arm is a no-op.
func TestOnYaraWorkerRestartDropsWhenAlertChFull(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.alertCh = make(chan alert.Finding, 1)
	d.alertCh <- alert.Finding{Check: "placeholder"}

	// Must not panic or block.
	d.onYaraWorkerRestart(1, syscall.SIGKILL, time.Millisecond)
}
