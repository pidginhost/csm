//go:build linux

package firewall

import "time"

// leaseReading is the lease clock's last reading: the time it gave and the
// elapsed-clock sample it was taken from.
type leaseReading struct {
	now, at time.Time
}

// leaseNowLocked is the time absolute expiries are turned into kernel
// timeouts against (spec 5.4 and 5.5: a clock step must not lengthen a
// lease). It never runs backward: it is the later of the wall clock and
// the last reading advanced by the elapsed time since. A forward step is
// kept, which only shortens leases.
func (e *Engine) leaseNowLocked() time.Time {
	return e.leaseAtLocked(e.expiryNow())
}

// leaseAtLocked reads the lease clock from sample, a reading of the
// engine's clock: the wall time without its monotonic component, and the
// sample itself, whose differences are monotonic in production. A caller
// that already read the clock passes that reading, so one instant serves
// both. leaseClock replaces the sample in tests.
func (e *Engine) leaseAtLocked(sample time.Time) time.Time {
	wall, elapsed := sample.Round(0), sample
	if e.leaseClock != nil {
		wall, elapsed = e.leaseClock()
	}
	now := wall
	if !e.lease.at.IsZero() {
		if since := e.lease.now.Add(elapsed.Sub(e.lease.at)); since.After(now) {
			now = since
		}
	}
	e.lease = leaseReading{now: now, at: elapsed}
	return now
}

// SetLeaseFloor moves the lease clock forward to floor when it is behind
// it. The daemon passes the admission clock's saved time before the first
// Apply: a lower bound for a new boot, where the lease checkpoint proves no
// downtime (lease_checkpoint_linux.go).
func (e *Engine) SetLeaseFloor(floor time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.raiseLeaseLocked(floor)
}

func (e *Engine) raiseLeaseLocked(floor time.Time) {
	if now := e.leaseNowLocked(); floor.After(now) {
		e.lease.now = floor.Round(0)
	}
}
