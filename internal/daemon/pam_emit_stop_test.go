package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// emit must abort a blocked send once the listener is stopping. Otherwise a
// per-connection goroutine blocked on an undrained alertCh (the alert
// dispatcher stops draining at shutdown) leaks for the life of the process.
func TestPAMEmitUnblocksOnStop(t *testing.T) {
	stopCh := make(chan struct{})
	p := &PAMListener{
		alertCh: make(chan alert.Finding), // unbuffered, never drained
		stopCh:  stopCh,
	}

	done := make(chan struct{})
	go func() {
		p.emit([]alert.Finding{{Check: "pam_login"}})
		close(done)
	}()

	// Let emit reach the blocked send, then signal stop.
	time.Sleep(20 * time.Millisecond)
	close(stopCh)

	select {
	case <-done:
		// emit returned after stop -- correct.
	case <-time.After(2 * time.Second):
		t.Fatal("emit did not unblock after stopCh closed; goroutine would leak")
	}
}

// With no stop channel wired (tests that construct a listener by hand), emit
// keeps its original blocking-send semantics so the lock-free emit contract is
// unaffected.
func TestPAMEmitBlocksWithoutStopChannel(t *testing.T) {
	alertCh := make(chan alert.Finding)
	p := &PAMListener{
		alertCh: alertCh, // unbuffered until the test drains it below
	}

	done := make(chan struct{})
	go func() {
		p.emit([]alert.Finding{{Check: "pam_login"}})
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("emit returned despite no reader and no stop signal")
	case <-time.After(100 * time.Millisecond):
		// Still blocked, as expected.
	}

	<-alertCh
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emit did not finish after the test drained alertCh")
	}
}
