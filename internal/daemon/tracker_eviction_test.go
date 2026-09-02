package daemon

import (
	"fmt"
	"testing"
	"time"
)

// Both auth trackers bounded IPs, subnets and accounts with one LRU across
// all three maps. Account keys are attacker-chosen, so a flood of unique
// mailbox names evicted the oldest entries of every kind, including an IP
// entry carrying good-source standing or in-window slow-brute evidence, and
// the source that had earned an exemption became blockable again. Victims
// are now ranked: attacker-chosen account and subnet keys go first, idle
// sources next, sources with in-window failure or slow-brute evidence last.
func TestMailTrackerFloodOfAccountNamesKeepsGoodSourceStanding(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := now
	tr := newMailAuthTracker(50, 80, 120, 10*time.Minute, 60*time.Minute, 40, 6*time.Hour, 20, func() time.Time { return clock })

	// A source that authenticates to two mailboxes: established good standing.
	tr.RecordSuccess("198.51.100.10", "alice@example.com")
	tr.RecordSuccess("198.51.100.10", "bob@example.com")
	clock = clock.Add(time.Minute)

	for i := 0; i < 200; i++ {
		clock = clock.Add(time.Second)
		tr.Record("203.0.113.5", fmt.Sprintf("victim%d@example.com", i))
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if _, ok := tr.ips["198.51.100.10"]; !ok {
		t.Fatal("good-source IP entry evicted by a flood of attacker-chosen account names")
	}
	if len(tr.ips)+len(tr.subnets)+len(tr.accounts) > tr.maxTracked {
		t.Fatalf("tracker over its cap after the flood: %d entries, cap %d", len(tr.ips)+len(tr.subnets)+len(tr.accounts), tr.maxTracked)
	}
}

func TestSMTPTrackerFloodOfAccountNamesKeepsSlowEvidence(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := now
	tr := newSMTPAuthTracker(50, 80, 120, 10*time.Minute, 60*time.Minute, 40, 6*time.Hour, 20, func() time.Time { return clock })

	// A source with in-window slow-brute evidence and a recorded success.
	tr.Record("198.51.100.20", "walk1@example.com")
	tr.RecordSuccess("198.51.100.20")
	clock = clock.Add(time.Minute)

	for i := 0; i < 200; i++ {
		clock = clock.Add(time.Second)
		tr.Record("203.0.113.6", fmt.Sprintf("victim%d@example.com", i))
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if _, ok := tr.ips["198.51.100.20"]; !ok {
		t.Fatal("IP entry with slow-brute evidence evicted by a flood of attacker-chosen account names")
	}
	if len(tr.ips)+len(tr.subnets)+len(tr.accounts) > tr.maxTracked {
		t.Fatalf("tracker over its cap after the flood: %d entries, cap %d", len(tr.ips)+len(tr.subnets)+len(tr.accounts), tr.maxTracked)
	}
}

// A source can authenticate successfully and then sit idle for longer than
// the fast failure window while its good-source record is still needed. A
// one-failure-per-fresh-IP flood must not rank those attacker entries above
// the legitimate source and evict its standing.
func TestMailTrackerFreshIPFloodKeepsIdleGoodSource(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := now
	tr := newMailAuthTracker(50, 80, 120, 10*time.Minute, 60*time.Minute, 40, 6*time.Hour, 20, func() time.Time { return clock })

	tr.RecordSuccess("198.51.100.30", "alice@example.com")
	clock = clock.Add(11 * time.Minute)
	for i := 0; i < 200; i++ {
		clock = clock.Add(time.Second)
		ip := fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)
		tr.Record(ip, fmt.Sprintf("victim%d@example.com", i))
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if _, ok := tr.ips["198.51.100.30"]; !ok {
		t.Fatal("idle good-source IP entry evicted by fresh one-failure sources")
	}
}

func TestSMTPTrackerFreshIPFloodKeepsRecentSuccess(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := now
	tr := newSMTPAuthTracker(50, 80, 120, 10*time.Minute, 60*time.Minute, 40, 6*time.Hour, 20, func() time.Time { return clock })

	tr.RecordSuccess("198.51.100.40")
	clock = clock.Add(11 * time.Minute)
	for i := 0; i < 200; i++ {
		clock = clock.Add(time.Second)
		ip := fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)
		tr.Record(ip, fmt.Sprintf("victim%d@example.com", i))
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if _, ok := tr.ips["198.51.100.40"]; !ok {
		t.Fatal("IP entry with a recent successful auth evicted by fresh one-failure sources")
	}
}

func TestMailEvictionRankIncludesWindowBoundary(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	window := 10 * time.Minute
	slowWindow := 6 * time.Hour

	if got := (&mailIPEntry{times: []time.Time{now.Add(-window)}}).evictionRank(now, window, slowWindow); got != evictionRankActiveIP {
		t.Fatalf("fast failure at window boundary rank = %d, want active", got)
	}
	if got := (&mailIPEntry{slowTimes: []time.Time{now.Add(-slowWindow), now.Add(-slowWindow)}}).evictionRank(now, window, slowWindow); got != evictionRankProtectedIP {
		t.Fatalf("slow evidence at window boundary rank = %d, want protected", got)
	}
	if got := (&mailIPEntry{slowTimes: []time.Time{now, now}, slowLastSuccess: now}).evictionRank(now, window, 0); got != evictionRankIdleIP {
		t.Fatalf("disabled slow window rank = %d, want idle", got)
	}
}

func TestSMTPEvictionRankIncludesWindowBoundary(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	window := 10 * time.Minute
	slowWindow := 6 * time.Hour

	if got := (&smtpIPEntry{times: []time.Time{now.Add(-window)}}).evictionRank(now, window, slowWindow); got != evictionRankActiveIP {
		t.Fatalf("fast failure at window boundary rank = %d, want active", got)
	}
	if got := (&smtpIPEntry{slowLastSuccess: now.Add(-slowWindow)}).evictionRank(now, window, slowWindow); got != evictionRankProtectedIP {
		t.Fatalf("success at slow-window boundary rank = %d, want protected", got)
	}
	if got := (&smtpIPEntry{slowTimes: []time.Time{now, now}, slowLastSuccess: now}).evictionRank(now, window, 0); got != evictionRankIdleIP {
		t.Fatalf("disabled slow window rank = %d, want idle", got)
	}
}
