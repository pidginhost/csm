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
