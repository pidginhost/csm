package webui

import (
	"testing"
)

func TestIPDedup(t *testing.T) {
	items := []enrichedFinding{
		{
			Severity:  "HIGH",
			SevClass:  "high",
			Check:     "ip_reputation",
			Message:   "Known malicious IP accessing server: 1.2.3.4 (AbuseIPDB)",
			FirstSeen: "2026-04-01T10:00:00Z",
			LastSeen:  "2026-04-01T10:00:00Z",
		},
		{
			Severity:  "CRITICAL",
			SevClass:  "critical",
			Check:     "ip_reputation",
			Message:   "Known malicious IP accessing server: 1.2.3.4 (Spamhaus)",
			FirstSeen: "2026-04-01T09:00:00Z",
			LastSeen:  "2026-04-01T11:00:00Z",
		},
		{
			Severity:  "HIGH",
			SevClass:  "high",
			Check:     "ip_reputation",
			Message:   "Known malicious IP accessing server: 5.6.7.8 (AbuseIPDB)",
			FirstSeen: "2026-04-01T10:00:00Z",
			LastSeen:  "2026-04-01T10:00:00Z",
		},
		{
			Severity:  "CRITICAL",
			SevClass:  "critical",
			Check:     "brute_force",
			Message:   "Brute force detected",
			FirstSeen: "2026-04-01T10:00:00Z",
			LastSeen:  "2026-04-01T10:00:00Z",
		},
	}

	result := dedupIPReputation(items)

	// Should have 3 entries: brute_force + deduped 1.2.3.4 + 5.6.7.8
	if len(result) != 3 {
		t.Fatalf("expected 3 entries after dedup, got %d", len(result))
	}

	// The deduped 1.2.3.4 entry should have CRITICAL severity (promoted from HIGH)
	found := false
	for _, r := range result {
		if r.Check == "ip_reputation" && r.Message == "Known malicious IP accessing server: 1.2.3.4 (AbuseIPDB, Spamhaus)" {
			found = true
			if r.Severity != "CRITICAL" {
				t.Errorf("expected CRITICAL severity after merge, got %s", r.Severity)
			}
			if r.FirstSeen != "2026-04-01T09:00:00Z" {
				t.Errorf("expected earliest FirstSeen, got %s", r.FirstSeen)
			}
			if r.LastSeen != "2026-04-01T11:00:00Z" {
				t.Errorf("expected latest LastSeen, got %s", r.LastSeen)
			}
		}
	}
	if !found {
		t.Error("expected deduped ip_reputation entry for 1.2.3.4")
	}

	// Non-ip_reputation entry should pass through unchanged
	foundBrute := false
	for _, r := range result {
		if r.Check == "brute_force" {
			foundBrute = true
		}
	}
	if !foundBrute {
		t.Error("expected brute_force entry to pass through unchanged")
	}
}

func TestIPDedupNoIPReputation(t *testing.T) {
	items := []enrichedFinding{
		{Check: "brute_force", Message: "test"},
		{Check: "webshell", Message: "test2"},
	}
	result := dedupIPReputation(items)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries (no dedup needed), got %d", len(result))
	}
}
