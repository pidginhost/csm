package daemon

import (
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The unit sets no KillMode, so systemd's default (control-group) sends
// SIGTERM to every process in the cgroup, the yara-worker child included.
// The worker therefore dies at the same moment as the daemon, well before
// shutdown reaches stopYaraBackend and cancels the supervisor context. The
// supervisor's own "ctx cancelled" guard has not fired yet, so the exit
// looked unplanned and every `systemctl restart csm` mailed the operator a
// Critical "YARA-X worker crashed".
//
// Observed on a production host: an orderly restart produced
// "YARA-X worker crashed (exit=-1 signal=terminated after 35m33.386s)"
// twice, at the same second as "Stopping CSM".
func TestOnYaraWorkerRestartSilentDuringShutdown(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.stopCh = make(chan struct{})
	close(d.stopCh)

	d.onYaraWorkerRestart(-1, syscall.SIGTERM, 35*time.Minute)

	select {
	case f := <-d.alertCh:
		t.Fatalf("shutdown emitted a crash finding: %s", f.Message)
	default:
	}
}

// The guard must not cost us the alert it exists to preserve: a worker that
// dies while the daemon is running is a real crash and still has to be
// reported.
func TestOnYaraWorkerRestartReportsCrashWhileRunning(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.stopCh = make(chan struct{}) // open: daemon is running

	d.onYaraWorkerRestart(1, syscall.SIGSEGV, 5*time.Second)

	select {
	case f := <-d.alertCh:
		if f.Check != "yara_worker_crashed" {
			t.Errorf("check = %q, want yara_worker_crashed", f.Check)
		}
		if f.Severity != alert.Critical {
			t.Errorf("severity = %v, want Critical", f.Severity)
		}
	default:
		t.Fatal("a crash during normal operation emitted no finding")
	}
}

// A Daemon built without a stopCh (as several tests and the zero value do)
// must be treated as running, not as shutting down. Reading a nil channel
// blocks forever, so a guard written as a plain receive would swallow every
// crash finding on such a daemon.
func TestOnYaraWorkerRestartNilStopChStillReports(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	if d.stopCh != nil {
		t.Fatal("harness unexpectedly set stopCh; this test covers the nil case")
	}

	d.onYaraWorkerRestart(1, syscall.SIGSEGV, 5*time.Second)

	select {
	case <-d.alertCh:
	default:
		t.Fatal("nil stopCh was treated as shutdown and swallowed the finding")
	}
}
