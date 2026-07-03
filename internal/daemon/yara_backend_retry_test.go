package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// retryStart must keep retrying a failed start with backoff, raise the
// persistent-failure callback exactly once, and stop as soon as start
// succeeds. This is the core that keeps a boot-time YARA worker failure from
// disabling scanning for the daemon's whole lifetime.
func TestRetryStartEmitsOnceThenSucceeds(t *testing.T) {
	const failUntil = 3
	calls := 0
	persistent := 0
	ok := retryStart(
		func() error {
			calls++
			if calls <= failUntil {
				return errors.New("boom")
			}
			return nil
		},
		nil,
		time.Millisecond, 4*time.Millisecond, failUntil,
		func(attempt int, err error) { persistent++ },
	)
	if !ok {
		t.Fatal("retryStart should report success once start stops failing")
	}
	if calls != failUntil+1 {
		t.Errorf("start attempts = %d, want %d", calls, failUntil+1)
	}
	if persistent != 1 {
		t.Errorf("persistent-failure callback fired %d times, want exactly 1", persistent)
	}
}

// A stop signal must break the retry loop and report no success.
func TestRetryStartStopsOnSignal(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	ok := retryStart(
		func() error { return errors.New("always fails") },
		stop,
		time.Millisecond, time.Millisecond, 2,
		nil,
	)
	if ok {
		t.Error("retryStart must return false when stopped before success")
	}
}

// A worker that is up but whose rules failed to compile must raise a finding
// so the silent-dead backend is visible to operators.
func TestReportYaraCompileStatusEmitsFinding(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.reportYaraCompileStatus("bad rule at line 7")

	select {
	case f := <-d.alertCh:
		if f.Severity != alert.Critical {
			t.Errorf("severity = %v, want Critical", f.Severity)
		}
		if f.Check != "yara_worker_compile_failed" {
			t.Errorf("check = %q", f.Check)
		}
		if f.Message == "" {
			t.Error("message must not be empty")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no finding emitted for a failed rule compile")
	}
}

// A clean compile raises nothing.
func TestReportYaraCompileStatusSilentWhenClean(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.reportYaraCompileStatus("")

	select {
	case f := <-d.alertCh:
		t.Errorf("a clean compile must not emit a finding, got %+v", f)
	case <-time.After(50 * time.Millisecond):
	}
}

// emitYaraFinding must never block, even when the alert channel is saturated.
func TestEmitYaraFindingDoesNotBlockWhenFull(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.alertCh = make(chan alert.Finding, 1)
	d.alertCh <- alert.Finding{Check: "placeholder"}
	// Must return promptly rather than deadlock.
	done := make(chan struct{})
	go func() {
		d.emitYaraFinding(alert.Critical, "yara_backend_unavailable", "msg")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("emitYaraFinding blocked on a full channel")
	}
}
