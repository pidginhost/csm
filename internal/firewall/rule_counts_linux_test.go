//go:build linux

package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRuleCountsExcludesExpired pins that RuleCounts reads every rule
// category from the engine state file and prunes expired temp bans, the
// same way the live block-state index does. A regression here feeds the
// Prometheus firewall gauges a stale or category-incomplete count.
func TestRuleCountsExcludesExpired(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	now := time.Now()
	st := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.1", ExpiresAt: now.Add(time.Hour)},  // active
			{IP: "203.0.113.2", ExpiresAt: now.Add(-time.Hour)}, // expired -> pruned
			{IP: "203.0.113.3"}, // permanent (zero expiry)
		},
		Allowed: []AllowedEntry{
			{IP: "203.0.113.10"},
			{IP: "203.0.113.11", ExpiresAt: now.Add(-time.Minute)}, // expired -> pruned
		},
		BlockedNet: []SubnetEntry{
			{CIDR: "198.51.100.0/24"},
		},
		PortAllowed: []PortAllowEntry{
			{IP: "203.0.113.20", Port: 25, Proto: "tcp"},
			{IP: "203.0.113.21", Port: 587, Proto: "tcp"},
		},
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	c := e.RuleCounts()
	if c.Blocked != 2 {
		t.Errorf("Blocked = %d, want 2 (1 expired pruned)", c.Blocked)
	}
	if c.Allowed != 1 {
		t.Errorf("Allowed = %d, want 1 (1 expired pruned)", c.Allowed)
	}
	if c.Subnets != 1 {
		t.Errorf("Subnets = %d, want 1", c.Subnets)
	}
	if c.PortAllowed != 2 {
		t.Errorf("PortAllowed = %d, want 2", c.PortAllowed)
	}
	if got, want := c.Total(), 6; got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}
