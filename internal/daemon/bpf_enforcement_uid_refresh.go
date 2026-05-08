package daemon

import (
	"sync"
	"sync/atomic"
	"time"
)

// UIDRefresherConfig drives a UIDRefresher. Refresh is the function
// called every tick; production wiring re-reads /etc/passwd and
// repopulates the BPF safe_uids map. Interval bounds the period;
// production uses 5 minutes.
type UIDRefresherConfig struct {
	Interval time.Duration
	Refresh  func() error
}

// UIDRefresherStats is a counter snapshot.
type UIDRefresherStats struct {
	Refreshes uint64
	Failures  uint64
}

// UIDRefresher runs the configured Refresh on a fixed interval. Stop
// is idempotent.
type UIDRefresher struct {
	cfg     UIDRefresherConfig
	stop    chan struct{}
	wg      sync.WaitGroup
	started atomic.Bool
	stopped atomic.Bool

	refreshes atomic.Uint64
	failures  atomic.Uint64
}

// NewUIDRefresher returns a stopped refresher. Call Start to launch.
func NewUIDRefresher(cfg UIDRefresherConfig) *UIDRefresher {
	return &UIDRefresher{cfg: cfg, stop: make(chan struct{})}
}

// Start launches the refresh goroutine. Idempotent.
func (r *UIDRefresher) Start() {
	if r.started.Swap(true) {
		return
	}
	r.wg.Add(1)
	go r.loop()
}

// Stop signals the goroutine and waits. Safe to call multiple times.
func (r *UIDRefresher) Stop() {
	if r.stopped.Swap(true) {
		return
	}
	close(r.stop)
	r.wg.Wait()
}

// Stats returns a counter snapshot.
func (r *UIDRefresher) Stats() UIDRefresherStats {
	return UIDRefresherStats{
		Refreshes: r.refreshes.Load(),
		Failures:  r.failures.Load(),
	}
}

func (r *UIDRefresher) loop() {
	defer r.wg.Done()
	t := time.NewTicker(r.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			if err := r.cfg.Refresh(); err != nil {
				r.failures.Add(1)
				continue
			}
			r.refreshes.Add(1)
		}
	}
}
