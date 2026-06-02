//go:build linux

package firewall

import (
	"testing"
	"time"
)

// When the temporary-deny cap is reached, the eviction policy must pick the
// block closest to expiry so a fresh block (a real attacker) always fits. This
// is what stops an attacker from saturating the cap with throwaway IPs to
// shield the IPs doing real damage.
func TestSoonestExpiringTempIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	st := FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.1"}, // permanent: never evicted here
		{IP: "192.0.2.2", ExpiresAt: now.Add(time.Hour)},
		{IP: "192.0.2.3", ExpiresAt: now.Add(10 * time.Minute)}, // soonest
		{IP: "192.0.2.4", ExpiresAt: now.Add(30 * time.Minute)},
	}}

	got, ok := soonestExpiringTempIP(st, "")
	if !ok || got != "192.0.2.3" {
		t.Fatalf("soonest-expiring temp = %q (ok=%v), want 192.0.2.3", got, ok)
	}

	// The IP being blocked now must not be chosen as its own victim.
	got, ok = soonestExpiringTempIP(st, "192.0.2.3")
	if !ok || got != "192.0.2.4" {
		t.Fatalf("with exclude, soonest = %q (ok=%v), want 192.0.2.4", got, ok)
	}
}

// With only permanent blocks there is nothing to evict, so the caller keeps
// refusing rather than removing an operator's permanent block.
func TestSoonestExpiringTempIP_NoTempEntries(t *testing.T) {
	st := FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.1"}}}
	if _, ok := soonestExpiringTempIP(st, ""); ok {
		t.Fatal("permanent-only state must report no temp entry to evict")
	}
}
