package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A scan burst that fills the shared alert channel while the dispatcher is
// mid-batch must apply backpressure, not silently drop findings. An earlier
// non-blocking send dropped a real db_rogue_admin finding under a
// false-positive flood.
func TestEnqueueScanAlertsBackpressureDoesNotDrop(t *testing.T) {
	d := &Daemon{
		alertCh: make(chan alert.Finding, 1),
		stopCh:  make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		// Two findings, a one-slot channel, and no drainer yet: the first fills
		// the buffer and the second must block until room appears.
		d.enqueueScanAlerts([]alert.Finding{
			{Check: "a", Severity: alert.Critical},
			{Check: "db_rogue_admin", Severity: alert.Critical},
		}, "deep")
		close(done)
	}()

	// If enqueue returns before anything is drained, the second finding was
	// dropped on the full channel instead of applying backpressure.
	select {
	case <-done:
		t.Fatal("enqueueScanAlerts returned without delivering both findings; a finding was dropped on a full channel")
	case <-time.After(250 * time.Millisecond):
		// Still blocked on the second send -- correct backpressure.
	}

	if got := <-d.alertCh; got.Check != "a" {
		t.Fatalf("first finding = %q, want a", got.Check)
	}
	select {
	case got := <-d.alertCh:
		if got.Check != "db_rogue_admin" {
			t.Fatalf("second finding = %q, want db_rogue_admin", got.Check)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("db_rogue_admin finding was never delivered")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("enqueueScanAlerts did not return after delivering both findings")
	}
	if n := atomic.LoadInt64(&d.droppedAlerts); n != 0 {
		t.Fatalf("droppedAlerts = %d, want 0", n)
	}
}

// A scan finding blocked on a full channel must be released on daemon shutdown
// instead of hanging the scan goroutine forever.
func TestEnqueueScanAlertsHonorsStopCh(t *testing.T) {
	d := &Daemon{
		alertCh: make(chan alert.Finding, 1),
		stopCh:  make(chan struct{}),
	}
	d.alertCh <- alert.Finding{Check: "filler"} // full; a further send blocks

	done := make(chan struct{})
	go func() {
		d.enqueueScanAlerts([]alert.Finding{{Check: "late", Severity: alert.Critical}}, "deep")
		close(done)
	}()

	// Let the enqueue reach its blocking send, then signal shutdown.
	time.Sleep(50 * time.Millisecond)
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("enqueueScanAlerts ignored stopCh and hung on a full channel")
	}
}

// A wedged dispatcher must bound the whole no-progress stall. Waiting for the
// full timeout again for every remaining finding would turn a large scan burst
// into an hours-long blocked scanner or control-socket request.
func TestEnqueueScanAlertsTimeoutDropsRemainingBatch(t *testing.T) {
	d := &Daemon{
		alertCh: make(chan alert.Finding, 1),
		stopCh:  make(chan struct{}),
	}
	d.alertCh <- alert.Finding{Check: "filler"}

	findings := []alert.Finding{
		{Check: "first", Severity: alert.Critical},
		{Check: "perf_wp_cron", Severity: alert.Warning},
		{Check: "second", Severity: alert.High},
		{Check: "third", Severity: alert.Critical},
		{Check: "fourth", Severity: alert.High},
		{Check: "fifth", Severity: alert.Critical},
	}
	const timeout = 50 * time.Millisecond
	start := time.Now()
	d.enqueueScanAlertsWithin(findings, "deep", timeout)
	elapsed := time.Since(start)

	if elapsed < timeout {
		t.Fatalf("enqueue returned after %s, before timeout %s", elapsed, timeout)
	}
	if elapsed >= 3*timeout {
		t.Fatalf("enqueue took %s; timeout was applied repeatedly to the undelivered tail", elapsed)
	}
	if n := atomic.LoadInt64(&d.droppedAlerts); n != 5 {
		t.Fatalf("droppedAlerts = %d, want 5 undelivered alertable findings", n)
	}
	if got := <-d.alertCh; got.Check != "filler" {
		t.Fatalf("queued finding = %q, want filler", got.Check)
	}
}
