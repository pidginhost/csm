package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A brute-force alert send must not happen while the listener holds p.mu.
// Previously recordFailure sent to alertCh under the lock, so a stalled alert
// consumer wedged every recordFailure, clearFailures, and the cleanup loop --
// failure trackers then grew without bound. With the send moved out of the
// critical section, a blocked emit no longer holds the lock.
func TestPAMListenerEmitDoesNotHoldLock(t *testing.T) {
	alertCh := make(chan alert.Finding, 1)
	alertCh <- alert.Finding{Check: "blocker"}
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3          // trigger brute-force quickly
	cfg.Thresholds.CredStuffingDistinctAccounts = 100 // keep stuffing path quiet

	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
		stuffing: newCredentialStuffingDetector(100, 10*time.Minute, nil),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			p.processEvent("FAIL ip=203.0.113.30 user=root service=sshd")
		}
	}()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-done:
			t.Fatal("producer finished before the alert send blocked")
		default:
		}

		if p.mu.TryLock() {
			tracker := p.failures["203.0.113.30"]
			blocked := tracker != nil && tracker.blocked && tracker.count >= 3
			p.mu.Unlock()
			if blocked {
				break
			}
		}

		select {
		case <-deadline:
			t.Fatal("producer did not reach a blocked alert send with p.mu free")
		case <-time.After(time.Millisecond):
		}
	}

	// While the emit is blocked, a method that needs p.mu must still run.
	lockFreed := make(chan struct{})
	go func() {
		p.clearFailures("203.0.113.99")
		close(lockFreed)
	}()

	select {
	case <-lockFreed:
		// Lock was free during the blocked emit.
	case <-time.After(3 * time.Second):
		t.Fatal("clearFailures blocked: alert emit is holding p.mu")
	}

	<-alertCh
	select {
	case f := <-alertCh:
		if f.Check != "pam_bruteforce" {
			t.Fatalf("unexpected finding after unblocking producer: %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("producer did not emit pam_bruteforce after channel was drained")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("producer did not finish after channel was drained")
	}
}

// emitRecordFailure mirrors processEvent's FAIL path (recordFailure then emit)
// so tests that drive recordFailure directly still observe findings on alertCh.
func emitRecordFailure(p *PAMListener, ip, user, service string) {
	p.emit(p.recordFailure(ip, user, service))
}
