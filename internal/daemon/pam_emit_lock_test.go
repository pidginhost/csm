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
	alertCh := make(chan alert.Finding) // unbuffered, no reader -> send blocks
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3          // trigger brute-force quickly
	cfg.Thresholds.CredStuffingDistinctAccounts = 100 // keep stuffing path quiet

	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
		stuffing: newCredentialStuffingDetector(100, 10*time.Minute, nil),
	}

	// Brute-force from one IP; the resulting emit blocks (no reader).
	emitting := make(chan struct{})
	go func() {
		close(emitting)
		for i := 0; i < 4; i++ {
			p.processEvent("FAIL ip=203.0.113.30 user=root service=sshd")
		}
	}()
	<-emitting

	// While the emit is blocked, a method that needs p.mu must still run.
	lockFreed := make(chan struct{})
	go func() {
		// Spin a few times so we race against the blocked emit, not just the
		// pre-emit window.
		for i := 0; i < 3; i++ {
			p.clearFailures("203.0.113.99")
			time.Sleep(time.Millisecond)
		}
		close(lockFreed)
	}()

	select {
	case <-lockFreed:
		// Lock was free during the blocked emit.
	case <-time.After(3 * time.Second):
		t.Fatal("clearFailures blocked: alert emit is holding p.mu")
	}

	// Drain so the producer goroutine can finish.
	go func() {
		for range alertCh {
		}
	}()
}
