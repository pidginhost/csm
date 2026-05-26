package wpcheck

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduleRetryFiresWhenNotStopped(t *testing.T) {
	c := NewCache(t.TempDir())
	var calls atomic.Int32
	done := make(chan struct{})
	c.scheduleRetry(5*time.Millisecond, func() {
		calls.Add(1)
		close(done)
	})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("retry callback never fired")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

func TestScheduleRetryCancelsOnStop(t *testing.T) {
	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	c.SetStopCh(stop)

	var calls atomic.Int32
	c.scheduleRetry(50*time.Millisecond, func() {
		calls.Add(1)
	})
	close(stop)
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("calls = %d after stop, want 0 (retry must be cancelled)", got)
	}
}

func TestScheduleRetryStopMidFlightDoesNotFire(t *testing.T) {
	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	c.SetStopCh(stop)

	var calls atomic.Int32
	c.scheduleRetry(200*time.Millisecond, func() {
		calls.Add(1)
	})
	time.Sleep(50 * time.Millisecond)
	close(stop)
	time.Sleep(300 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("calls = %d after mid-flight stop, want 0", got)
	}
}
