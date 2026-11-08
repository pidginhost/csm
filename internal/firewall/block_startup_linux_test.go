//go:build linux

package firewall

import (
	"slices"
	"testing"
	"time"
)

// Skipping an expired row is safe only when Apply cannot restore it after
// a backward wall-clock step between the ledger check and installation.
func TestStartupBlockActionsPinExpiryAcrossClockRollback(t *testing.T) {
	for _, ip := range []string{"192.0.2.60", "2001:db8::60"} {
		t.Run(ip, func(t *testing.T) {
			at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
			dir := t.TempDir()
			writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{
				{IP: ip, ActionID: "act_expired", ExpiresAt: at.Add(-time.Minute)},
				{IP: "198.51.100.50", Reason: "operator"},
			}})
			clock := &leaseSteps{wall: at, elapsed: at}
			e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}, leaseClock: clock.read, expiryClock: func() time.Time { return clock.wall }}
			ids, err := e.BlockActionIDsForStartup()
			if err != nil {
				t.Fatal(err)
			}
			// The ledger cannot prove any of the saved actions applied.
			if _, err = e.MarkBlockActionsUnverified(ids); err != nil {
				t.Fatal(err)
			}
			clock.step(-time.Hour)
			got := seededTimeouts(t, e)
			if timeout, restored := got[ip]; restored {
				t.Errorf("unchecked expired action restored for %v after clock rollback", timeout)
			}
			if timeout, restored := got["198.51.100.50"]; !restored || timeout != 0 || len(got) != 1 {
				t.Fatalf("restored blocks = %v, want only the permanent operator block", got)
			}
		})
	}
}

func TestStartupBlockActionsKeepHeldAndLiveIdentities(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	dir := t.TempDir()
	writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.60", ActionID: "act_expired", ExpiresAt: at.Add(-time.Second)},
		{IP: "192.0.2.61", ActionID: "act_boundary", ExpiresAt: at},
		{IP: "192.0.2.62", ActionID: "act_held", Unverified: true, ExpiresAt: at.Add(-time.Second)},
		{IP: "192.0.2.63", ActionID: "act_live", ExpiresAt: at.Add(-time.Second)},
		{IP: "192.0.2.63", ActionID: "act_live", ExpiresAt: at.Add(time.Hour)},
		{IP: "::ffff:192.0.2.63", ActionID: "act_live", ExpiresAt: at.Add(time.Hour)},
		{IP: "192.0.2.64", ActionID: "act_permanent"},
		{IP: "192.0.2.65", Reason: "operator"},
	}})
	clock := &leaseSteps{wall: at.Add(-time.Hour), elapsed: at}
	e := &Engine{statePath: dir, leaseClock: clock.read, expiryClock: func() time.Time { return clock.wall }}
	e.SetLeaseFloor(at)
	ids, err := e.BlockActionIDsForStartup()
	if want := []string{"act_held", "act_live", "act_permanent"}; err != nil || !slices.Equal(ids, want) {
		t.Fatalf("startup actions = %v, %v; want %v", ids, err, want)
	}
}
