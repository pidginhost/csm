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
	e := &Engine{statePath: dir, cfg: &FirewallConfig{}}

	now := time.Now()
	st := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.1", ExpiresAt: now.Add(time.Hour)},  // active
			{IP: "203.0.113.2", ExpiresAt: now.Add(-time.Hour)}, // expired -> pruned
			{IP: "203.0.113.3"},        // permanent (zero expiry)
			{IP: "::ffff:203.0.113.3"}, // same nft element as 203.0.113.3
			{IP: "2001:db8::1"},        // IPv6 disabled -> not enforced
			{IP: "not-an-ip"},          // invalid -> not enforced
		},
		Allowed: []AllowedEntry{
			{IP: "203.0.113.10", Source: SourceCLI},
			{IP: "203.0.113.10", Source: SourceDynDNS},             // same nft element
			{IP: "203.0.113.11", ExpiresAt: now.Add(-time.Minute)}, // expired -> pruned
			{IP: "2001:db8::10"},                                   // IPv6 disabled
			{IP: "not-an-ip"},
		},
		BlockedNet: []SubnetEntry{
			{CIDR: "198.51.100.0/24"},
			{CIDR: "198.51.100.0/24"}, // same nft interval
			{CIDR: "2001:db8:1::/64"}, // IPv6 disabled
			{CIDR: "not-a-cidr"},
		},
		PortAllowed: []PortAllowEntry{
			{IP: "203.0.113.20", Port: 25, Proto: "tcp"},
			{IP: "203.0.113.21", Port: 587, Proto: "tcp"},
			{IP: "2001:db8::20", Port: 993, Proto: "tcp"}, // IPv6 disabled
			{IP: "not-an-ip", Port: 465, Proto: "tcp"},
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
		t.Errorf("Blocked = %d, want 2 (expired, duplicate, invalid, IPv6-disabled entries ignored)", c.Blocked)
	}
	if c.Allowed != 1 {
		t.Errorf("Allowed = %d, want 1 (same IP across sources is one set element)", c.Allowed)
	}
	if c.Subnets != 1 {
		t.Errorf("Subnets = %d, want 1 (duplicates, invalid, IPv6-disabled entries ignored)", c.Subnets)
	}
	if c.PortAllowed != 2 {
		t.Errorf("PortAllowed = %d, want 2 (invalid and IPv6-disabled entries ignored)", c.PortAllowed)
	}
	if got, want := c.Total(), 6; got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}

func TestRuleCountsIncludesIPv6WhenEnabled(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}}

	st := FirewallState{
		Blocked:     []BlockedEntry{{IP: "2001:db8::1"}},
		Allowed:     []AllowedEntry{{IP: "2001:db8::10"}},
		BlockedNet:  []SubnetEntry{{CIDR: "2001:db8:1::/64"}},
		PortAllowed: []PortAllowEntry{{IP: "2001:db8::20", Port: 993, Proto: "tcp"}},
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	c := e.RuleCounts()
	if got, want := c.Total(), 4; got != want {
		t.Fatalf("Total = %d, want %d: %+v", got, want, c)
	}
}
