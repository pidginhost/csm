package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/workerproc"
)

// newDaemonForYaraBackendTest builds a Daemon minimal enough to drive
// the non-worker branch of initYaraBackend, all of stopYaraBackend, and
// every rate-limit arm of onYaraWorkerFailure.
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

// --- onYaraWorkerFailure ----------------------------------------------

var errWorkerDied = errors.New("yara worker: EOF")

func TestOnYaraWorkerFailureFirstCallEmitsCriticalFinding(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)

	d.onYaraWorkerFailure(workerproc.ReasonCrash, errWorkerDied)

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
		t.Fatal("no finding emitted on first failure")
	}
}

// Two failures within a minute: the second is rate-limited. A file that kills
// the worker on every scan must not turn into one alert per scan.
func TestOnYaraWorkerFailureRateLimitsWithinOneMinute(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)

	d.onYaraWorkerFailure(workerproc.ReasonCrash, errWorkerDied)
	d.onYaraWorkerFailure(workerproc.ReasonTimeout, errWorkerDied)

	select {
	case <-d.alertCh:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected one finding on alertCh")
	}
	select {
	case f := <-d.alertCh:
		t.Errorf("second failure within 60s must be suppressed, got %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
}

// If the last alert is older than a minute, the next failure alerts again.
func TestOnYaraWorkerFailureEmitsAgainAfterOneMinute(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.yaraCrashMu.Lock()
	d.yaraLastCrashAlert = time.Now().Add(-2 * time.Minute)
	d.yaraCrashMu.Unlock()

	d.onYaraWorkerFailure(workerproc.ReasonOOM, errWorkerDied)

	select {
	case f := <-d.alertCh:
		if f.Check != "yara_worker_crashed" {
			t.Errorf("check: got %q", f.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected a finding after the rate-limit window expired")
	}
}

// The callback runs under the worker supervisor's lock, so a saturated alert
// channel must be swallowed, never waited on.
func TestOnYaraWorkerFailureDropsWhenAlertChFull(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.alertCh = make(chan alert.Finding, 1)
	d.alertCh <- alert.Finding{Check: "placeholder"}

	d.onYaraWorkerFailure(workerproc.ReasonCrash, errWorkerDied)
}

// The finding is raised when the worker fails, before any replacement has
// loaded the rules. It must say what operators lose, not claim recovery.
func TestOnYaraWorkerFailureMessageDoesNotClaimRecovery(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)

	d.onYaraWorkerFailure(workerproc.ReasonCrash, errWorkerDied)

	select {
	case f := <-d.alertCh:
		for _, claim := range []string{"restarted it", "recovered"} {
			if strings.Contains(f.Message, claim) {
				t.Errorf("message claims %q before any restart: %s", claim, f.Message)
			}
		}
		for _, want := range []string{"crash", errWorkerDied.Error(), "reported as not scanned"} {
			if !strings.Contains(f.Message, want) {
				t.Errorf("message missing %q: %s", want, f.Message)
			}
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no finding emitted on failure")
	}
}

// Worker error text can be long (a quoted worker diagnostic); the finding
// carries a bounded excerpt.
func TestOnYaraWorkerFailureBoundsErrorText(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)

	d.onYaraWorkerFailure(workerproc.ReasonProtocol, errors.New(strings.Repeat("x", 10000)))

	f := <-d.alertCh
	if len(f.Message) > 1024 {
		t.Fatalf("finding message is %d bytes", len(f.Message))
	}
}
