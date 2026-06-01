package daemon

import (
	"fmt"
	"testing"
	"time"
)

// fixedClock returns a controllable time source for the detector tests.
func fixedClock(t *time.Time) func() time.Time {
	return func() time.Time { return *t }
}

func TestCredentialStuffingFiresOnceAtDistinctAccountThreshold(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	d := newCredentialStuffingDetector(3, 10*time.Minute, fixedClock(&now))

	if accts, fire := d.Record("203.0.113.7", "alice"); fire {
		t.Fatalf("fired at 1 distinct account: %v", accts)
	}
	if _, fire := d.Record("203.0.113.7", "bob"); fire {
		t.Fatalf("fired at 2 distinct accounts")
	}
	accts, fire := d.Record("203.0.113.7", "carol")
	if !fire {
		t.Fatalf("expected fire at 3 distinct accounts, got none")
	}
	want := []string{"alice", "bob", "carol"}
	if len(accts) != len(want) {
		t.Fatalf("account list = %v, want %v", accts, want)
	}
	for i := range want {
		if accts[i] != want[i] {
			t.Fatalf("account list = %v, want sorted %v", accts, want)
		}
	}
}

func TestCredentialStuffingDepthDoesNotFire(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	d := newCredentialStuffingDetector(3, 10*time.Minute, fixedClock(&now))

	// Same account hammered many times is brute-force (depth), not the
	// distinct-account breadth signal credential stuffing keys on.
	for i := 0; i < 20; i++ {
		if _, fire := d.Record("203.0.113.7", "alice"); fire {
			t.Fatalf("fired on repeated single-account failures (depth, not breadth)")
		}
	}
}

func TestCredentialStuffingFiresOnlyOncePerCampaign(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	d := newCredentialStuffingDetector(3, 10*time.Minute, fixedClock(&now))

	d.Record("203.0.113.7", "a")
	d.Record("203.0.113.7", "b")
	if _, fire := d.Record("203.0.113.7", "c"); !fire {
		t.Fatalf("expected fire at threshold")
	}
	// Further distinct accounts in the same window must not re-fire.
	if _, fire := d.Record("203.0.113.7", "d"); fire {
		t.Fatalf("re-fired within same campaign window")
	}
}

func TestCredentialStuffingWindowExpiryResets(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	d := newCredentialStuffingDetector(3, 10*time.Minute, fixedClock(&now))

	d.Record("203.0.113.7", "a")
	d.Record("203.0.113.7", "b")
	// Jump past the window: the prior distinct set is stale and must not
	// carry over, so a single new account stays below threshold.
	now = now.Add(11 * time.Minute)
	if _, fire := d.Record("203.0.113.7", "c"); fire {
		t.Fatalf("stale out-of-window accounts counted toward threshold")
	}
}

func TestCredentialStuffingBoundsTrackedIPs(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	d := newCredentialStuffingDetector(3, 10*time.Minute, fixedClock(&now))
	d.maxTrackedIPs = 100

	// Far more distinct source IPs than the cap, each advancing the clock so
	// lastSeen differs. The live map must stay bounded by the cap.
	for i := 0; i < 500; i++ {
		now = now.Add(time.Second)
		d.Record(fmt.Sprintf("198.51.100.%d:%d", i%256, i), "victim")
	}
	if got := len(d.perIP); got > 100 {
		t.Fatalf("tracked IPs = %d, want <= 100 (unbounded growth)", got)
	}
}

func TestCredentialStuffingPruneStaleDropsExpired(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	d := newCredentialStuffingDetector(3, 10*time.Minute, fixedClock(&now))

	d.Record("203.0.113.7", "a")
	now = now.Add(11 * time.Minute)
	if pruned := d.PruneStale(now); pruned != 1 {
		t.Fatalf("PruneStale dropped %d, want 1", pruned)
	}
	if len(d.perIP) != 0 {
		t.Fatalf("stale entry survived prune: %d", len(d.perIP))
	}
}

func TestCredentialStuffingIgnoresEmptyFields(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	d := newCredentialStuffingDetector(2, 10*time.Minute, fixedClock(&now))

	if _, fire := d.Record("", "alice"); fire {
		t.Fatalf("fired on empty IP")
	}
	if _, fire := d.Record("203.0.113.7", ""); fire {
		t.Fatalf("counted empty account")
	}
	if _, fire := d.Record("203.0.113.7", "alice"); fire {
		t.Fatalf("fired below threshold after empties ignored")
	}
}
