package daemon

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestUIDRefresherTicksAndCallsLoader(t *testing.T) {
	var calls atomic.Int64
	r := NewUIDRefresher(UIDRefresherConfig{
		Interval: 30 * time.Millisecond,
		Refresh: func() error {
			calls.Add(1)
			return nil
		},
	})
	r.Start()
	defer r.Stop()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Errorf("Refresh calls: want >=2, got %d", calls.Load())
	}
}

func TestUIDRefresherStopIdempotent(t *testing.T) {
	r := NewUIDRefresher(UIDRefresherConfig{
		Interval: time.Hour,
		Refresh:  func() error { return nil },
	})
	r.Start()
	r.Start() // double start no-op
	r.Stop()
	r.Stop() // double stop no-op
}

func TestUIDRefresherStatsBumpOnFailure(t *testing.T) {
	r := NewUIDRefresher(UIDRefresherConfig{
		Interval: 30 * time.Millisecond,
		Refresh: func() error {
			return errAlwaysFails{}
		},
	})
	r.Start()
	defer r.Stop()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if r.Stats().Failures >= 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("expected failures counter to advance; got %+v", r.Stats())
}

type errAlwaysFails struct{}

func (errAlwaysFails) Error() string { return "always fails" }
