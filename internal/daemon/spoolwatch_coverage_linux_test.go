//go:build linux

package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// These tests cover helpers in spoolwatch.go that do not require a real
// fanotify fd or kernel resources. SpoolWatcher fields are populated
// manually to exercise the pure-Go paths.

// --- PermissionMode getter ---

func TestSpoolWatcherPermissionModeTrue(t *testing.T) {
	sw := &SpoolWatcher{permissionMode: true}
	if !sw.PermissionMode() {
		t.Error("PermissionMode() should return true")
	}
}

func TestSpoolWatcherPermissionModeFalse(t *testing.T) {
	sw := &SpoolWatcher{permissionMode: false}
	if sw.PermissionMode() {
		t.Error("PermissionMode() should return false")
	}
}

// --- emitFinding ---

func TestSpoolWatcherEmitFindingDelivers(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}
	sw.emitFinding("email_av_test", alert.Warning, "hello")

	select {
	case f := <-ch:
		if f.Check != "email_av_test" {
			t.Errorf("check = %q", f.Check)
		}
		if f.Severity != alert.Warning {
			t.Errorf("severity = %v", f.Severity)
		}
		if f.Message != "hello" {
			t.Errorf("message = %q", f.Message)
		}
	default:
		t.Fatal("finding was not delivered")
	}
}

func TestSpoolWatcherEmitFindingDropsWhenFull(t *testing.T) {
	// Buffered channel of size 1, already full. Must not block.
	ch := make(chan alert.Finding, 1)
	ch <- alert.Finding{Check: "preexisting"}
	sw := &SpoolWatcher{alertCh: ch}

	done := make(chan struct{})
	go func() {
		sw.emitFinding("dropped", alert.Critical, "msg")
		close(done)
	}()

	select {
	case <-done:
		// OK - non-blocking drop
	case <-time.After(time.Second):
		t.Fatal("emitFinding blocked when channel was full")
	}
}

// --- emitDegradedWarning ---

func TestSpoolWatcherEmitDegradedWarningFirstEmits(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}
	sw.emitDegradedWarning("engines down")

	select {
	case f := <-ch:
		if f.Check != "email_av_degraded" {
			t.Errorf("check = %q", f.Check)
		}
	default:
		t.Fatal("first degraded warning should emit")
	}
}

func TestSpoolWatcherEmitDegradedWarningRateLimited(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}

	// First call: emits.
	sw.emitDegradedWarning("first")
	// Drain
	<-ch

	// Second call within <1 minute: should be suppressed.
	sw.emitDegradedWarning("second")
	select {
	case f := <-ch:
		t.Fatalf("rate-limited call should not have emitted: %+v", f)
	default:
		// OK
	}
}

func TestSpoolWatcherEmitDegradedWarningResetAfterMinute(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}

	// Pretend last emission was long ago.
	sw.lastDegradedAt = time.Now().Add(-2 * time.Minute)
	sw.emitDegradedWarning("should emit")

	select {
	case <-ch:
		// OK
	default:
		t.Fatal("expected emission after minute-long quiet period")
	}
}

// --- Stop idempotence / nil-safe path ---

func TestSpoolWatcherStopIdempotent(t *testing.T) {
	// Use an invalid fd (-1) and make pipe appear already closed so Stop()
	// only exercises the sync.Once path + closeFd.
	sw := &SpoolWatcher{
		fd:     -1,
		stopCh: make(chan struct{}),
	}
	sw.pipeClosed = 1 // pretend pipe already closed
	sw.fdClosed = 1   // skip real close

	// Must not panic on repeated invocation.
	sw.Stop()
	sw.Stop()

	select {
	case <-sw.stopCh:
		// expected: stopCh closed
	default:
		t.Error("stopCh should be closed after Stop()")
	}
}

func TestSpoolWatcherCloseFdIdempotent(t *testing.T) {
	sw := &SpoolWatcher{fd: -1}
	sw.fdClosed = 1 // pretend already closed
	// Should not panic.
	sw.closeFd()
	sw.closeFd()
}
