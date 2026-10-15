//go:build linux

package firewall

import (
	"testing"
	"time"
)

// RetirementTestEngine exposes only the real cleanup and seeding paths to
// the external ledger integration test; no production dependency is added.
func RetirementTestEngine(t *testing.T, dir string, wall time.Time, boot string, since time.Duration) (*Engine, func() map[string]time.Duration, func()) {
	t.Helper()
	f := newBatchFixture(t, FirewallState{})
	f.e.statePath = dir
	clock := &leaseSteps{wall: wall, elapsed: wall}
	f.e.leaseClock, f.e.expiryClock = clock.read, func() time.Time { return clock.wall }
	f.e.SetBootClock((&bootReading{id: boot, since: since}).read)
	return f.e, func() map[string]time.Duration { return seededTimeouts(t, f.e) }, func() { saveLease(t, f.e) }
}
