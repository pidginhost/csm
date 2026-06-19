package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// healthFixture wires an authBackendHealth to a controllable probe result and a
// restart counter so tests can drive outage/recovery transitions deterministically.
type healthFixture struct {
	clock      *staticClock
	healthy    bool
	restarts   int
	restartErr error
	h          *authBackendHealth
}

func newHealthFixture(t *testing.T, restartEnabled bool, downGrace, cooldown time.Duration, maxPerHour int) *healthFixture {
	t.Helper()
	f := &healthFixture{
		clock:   &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)},
		healthy: true,
	}
	f.h = newAuthBackendHealth(
		f.clock.Now,
		func() bool { return f.healthy },
		func() error { f.restarts++; return f.restartErr },
		restartEnabled, downGrace, cooldown, maxPerHour,
	)
	return f
}

func countCheck(findings []alert.Finding, check string) int {
	n := 0
	for _, f := range findings {
		if f.Check == check {
			n++
		}
	}
	return n
}

func TestAuthBackendHealth_HealthyEmitsNothing(t *testing.T) {
	f := newHealthFixture(t, false, 10*time.Minute, 2*time.Minute, 3)
	if out := f.h.Observe(); out != nil {
		t.Fatalf("healthy probe must emit nothing, got %v", out)
	}
	if f.h.Degraded() {
		t.Fatal("healthy backend must not be Degraded")
	}
}

func TestAuthBackendHealth_DownAlertsOnceAndIsDegraded(t *testing.T) {
	f := newHealthFixture(t, false, 10*time.Minute, 2*time.Minute, 3)
	f.healthy = false
	out := f.h.Observe()
	if countCheck(out, "mail_auth_backend_degraded") != 1 {
		t.Fatalf("first down probe must alert once, got %v", out)
	}
	if !f.h.Degraded() {
		t.Fatal("backend must be Degraded while probe fails")
	}
	f.clock.advance(30 * time.Second)
	if c := countCheck(f.h.Observe(), "mail_auth_backend_degraded"); c != 0 {
		t.Fatalf("must not re-alert while still down, got %d", c)
	}
}

func TestAuthBackendHealth_RecoveryClearsAndReArms(t *testing.T) {
	f := newHealthFixture(t, false, 10*time.Minute, 2*time.Minute, 3)
	f.healthy = false
	f.h.Observe()
	f.healthy = true
	if out := f.h.Observe(); out != nil {
		t.Fatalf("recovery probe should emit nothing, got %v", out)
	}
	if f.h.Degraded() {
		t.Fatal("recovered backend must not be Degraded")
	}
	// A new outage after recovery must alert again.
	f.healthy = false
	if c := countCheck(f.h.Observe(), "mail_auth_backend_degraded"); c != 1 {
		t.Fatalf("new outage after recovery must re-alert, got %d", c)
	}
}

func TestAuthBackendHealth_NoRestartBeforeGrace(t *testing.T) {
	f := newHealthFixture(t, true, 10*time.Minute, 2*time.Minute, 3)
	f.healthy = false
	f.h.Observe()
	f.clock.advance(9 * time.Minute) // still under the 10m grace
	if c := countCheck(f.h.Observe(), "auto_response"); c != 0 {
		t.Fatalf("must not restart before grace elapses, got %d", c)
	}
	if f.restarts != 0 {
		t.Fatalf("restart command must not run before grace, ran %d", f.restarts)
	}
}

func TestAuthBackendHealth_RestartAfterSustainedOutage(t *testing.T) {
	f := newHealthFixture(t, true, 10*time.Minute, 2*time.Minute, 3)
	f.healthy = false
	f.h.Observe()
	f.clock.advance(11 * time.Minute) // past the grace period
	out := f.h.Observe()
	if c := countCheck(out, "auto_response"); c != 1 {
		t.Fatalf("must emit one auto_response restart finding after grace, got %d (%v)", c, out)
	}
	if f.restarts != 1 {
		t.Fatalf("restart command must run exactly once, ran %d", f.restarts)
	}
}

func TestAuthBackendHealth_RestartDisabledNeverRuns(t *testing.T) {
	f := newHealthFixture(t, false, 10*time.Minute, 2*time.Minute, 3)
	f.healthy = false
	f.h.Observe()
	f.clock.advance(30 * time.Minute)
	f.h.Observe()
	if f.restarts != 0 {
		t.Fatalf("restart must never run when disabled, ran %d", f.restarts)
	}
}

func TestAuthBackendHealth_RestartCooldownBetweenAttempts(t *testing.T) {
	f := newHealthFixture(t, true, 10*time.Minute, 2*time.Minute, 5)
	f.healthy = false
	f.h.Observe()
	f.clock.advance(11 * time.Minute)
	f.h.Observe()                    // first restart
	f.clock.advance(1 * time.Minute) // within 2m cooldown
	f.h.Observe()
	if f.restarts != 1 {
		t.Fatalf("must respect cooldown between restarts, ran %d", f.restarts)
	}
	f.clock.advance(2 * time.Minute) // cooldown elapsed
	f.h.Observe()
	if f.restarts != 2 {
		t.Fatalf("must retry after cooldown elapses, ran %d", f.restarts)
	}
}

func TestAuthBackendHealth_RestartRateLimitedPerHour(t *testing.T) {
	f := newHealthFixture(t, true, 1*time.Minute, 1*time.Minute, 2)
	f.healthy = false
	f.h.Observe()
	// Keep it down and step past cooldown repeatedly; cap is 2/hour.
	for i := 0; i < 6; i++ {
		f.clock.advance(2 * time.Minute)
		f.h.Observe()
	}
	if f.restarts != 2 {
		t.Fatalf("restart must be capped at 2/hour, ran %d", f.restarts)
	}
}

func TestAuthBackendHealth_RestartFailureEmitsHigh(t *testing.T) {
	f := newHealthFixture(t, true, 10*time.Minute, 2*time.Minute, 3)
	f.restartErr = errors.New("restartsrv exited 1")
	f.healthy = false
	f.h.Observe()
	f.clock.advance(11 * time.Minute)
	out := f.h.Observe()
	var found bool
	for _, fd := range out {
		if fd.Check == "auto_response" && fd.Severity == alert.High {
			found = true
		}
	}
	if !found {
		t.Fatalf("failed restart must emit a High auto_response finding, got %v", out)
	}
}

func TestAuthBackendHealth_DegradedDoesNotWaitForBlockedProbe(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})
	h := newAuthBackendHealth(
		clock.Now,
		func() bool {
			close(probeEntered)
			<-releaseProbe
			return false
		},
		nil,
		false,
		10*time.Minute,
		2*time.Minute,
		3,
	)
	h.downSince = clock.Now()

	done := make(chan struct{})
	go func() {
		_ = h.Observe()
		close(done)
	}()
	<-probeEntered

	degraded := make(chan bool, 1)
	go func() { degraded <- h.Degraded() }()
	select {
	case got := <-degraded:
		if !got {
			t.Fatal("Degraded returned false while outage state was already known")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Degraded blocked behind a slow probe")
	}

	close(releaseProbe)
	<-done
}

func TestAuthBackendHealth_DegradedDoesNotWaitForRestart(t *testing.T) {
	f := newHealthFixture(t, true, 1*time.Minute, 1*time.Minute, 3)
	f.healthy = false
	f.h.Observe()
	f.clock.advance(2 * time.Minute)

	restartEntered := make(chan struct{})
	releaseRestart := make(chan struct{})
	f.h.restart = func() error {
		close(restartEntered)
		<-releaseRestart
		return nil
	}

	done := make(chan []alert.Finding, 1)
	go func() { done <- f.h.Observe() }()
	<-restartEntered

	degraded := make(chan bool, 1)
	go func() { degraded <- f.h.Degraded() }()
	select {
	case got := <-degraded:
		if !got {
			t.Fatal("Degraded returned false while restart was running")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Degraded blocked behind a slow restart")
	}

	close(releaseRestart)
	<-done
}

func TestRestartMailAuthBackendAcceptsCommandLine(t *testing.T) {
	if err := restartMailAuthBackend("printf authbackend"); err != nil {
		t.Fatalf("restartMailAuthBackend command line: %v", err)
	}
}

func TestRestartMailAuthBackendRejectsEmptyCommand(t *testing.T) {
	if err := restartMailAuthBackend("   "); err == nil {
		t.Fatal("restartMailAuthBackend accepted an empty command")
	}
}
