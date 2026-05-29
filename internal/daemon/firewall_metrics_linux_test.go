//go:build linux

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// TestFirewallMetricsReadEngineState pins that the firewall gauges read
// the engine state file, not the bbolt fw:* buckets. Production never
// writes those buckets (only migration does), so a gauge reading the
// store reports a value frozen at migration time. The test seeds the
// store with deliberately-wrong counts and proves the scrape ignores
// them in favour of the engine.
func TestFirewallMetricsReadEngineState(t *testing.T) {
	// Seed the dead bbolt bucket with values the gauge must NOT report.
	db := openStoreForTest(t)
	for _, ip := range []string{"10.0.0.250", "10.0.0.251", "10.0.0.252"} {
		if err := db.BlockIP(ip, "stale-bucket", time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("BlockIP: %v", err)
		}
	}

	dir := t.TempDir()
	eng, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true}, dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// NewEngine roots state under <dir>/firewall.
	stateFile := filepath.Join(dir, "firewall", "state.json")
	writeState := func(path string, st firewall.FirewallState) {
		data, marshalErr := json.MarshalIndent(st, "", "  ")
		if marshalErr != nil {
			t.Fatalf("marshal state: %v", marshalErr)
		}
		if writeErr := os.WriteFile(path, data, 0600); writeErr != nil {
			t.Fatalf("write state: %v", writeErr)
		}
	}

	now := time.Now()
	writeState(stateFile, firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.1", ExpiresAt: now.Add(time.Hour)},
			{IP: "203.0.113.2", ExpiresAt: now.Add(-time.Hour)}, // expired -> pruned
			{IP: "203.0.113.3"}, // permanent
		},
		Allowed:     []firewall.AllowedEntry{{IP: "203.0.113.10"}},
		BlockedNet:  []firewall.SubnetEntry{{CIDR: "198.51.100.0/24"}},
		PortAllowed: []firewall.PortAllowEntry{{IP: "203.0.113.20", Port: 25, Proto: "tcp"}},
	})

	d := &Daemon{cfg: &config.Config{}}

	// Nil-engine path registers the gauges and must report 0, never
	// panic.
	d.registerFirewallMetrics()
	body := scrapeBody(t)
	if got := readGauge(body, "csm_blocked_ips_total"); got != 0 {
		t.Errorf("nil engine csm_blocked_ips_total = %g, want 0", got)
	}
	if got := readGauge(body, "csm_firewall_rules_total"); got != 0 {
		t.Errorf("nil engine csm_firewall_rules_total = %g, want 0", got)
	}

	// Populated engine: 2 active blocked + 1 allowed + 1 subnet + 1 port.
	d.setFirewallEngine(eng)
	body = scrapeBody(t)
	if got := readGauge(body, "csm_blocked_ips_total"); got != 2 {
		t.Errorf("csm_blocked_ips_total = %g, want 2 (engine state, expired pruned; store seeded 3)", got)
	}
	if got := readGauge(body, "csm_firewall_rules_total"); got != 5 {
		t.Errorf("csm_firewall_rules_total = %g, want 5 (2 blocked + 1 allow + 1 subnet + 1 port)", got)
	}

	// Mutate the engine state file and re-scrape to prove the gauge is
	// live, not captured at register time.
	writeState(stateFile, firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.1", ExpiresAt: now.Add(time.Hour)},
		},
	})
	if got := readGauge(scrapeBody(t), "csm_blocked_ips_total"); got != 1 {
		t.Errorf("csm_blocked_ips_total after rewrite = %g, want 1", got)
	}

	otherDir := t.TempDir()
	otherEng, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true}, otherDir)
	if err != nil {
		t.Fatalf("second NewEngine: %v", err)
	}
	otherStateFile := filepath.Join(otherDir, "firewall", "state.json")
	writeState(otherStateFile, firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.10"},
			{IP: "203.0.113.11"},
			{IP: "203.0.113.12"},
		},
	})

	other := &Daemon{cfg: &config.Config{}}
	other.registerFirewallMetrics()
	if got := readGauge(scrapeBody(t), "csm_blocked_ips_total"); got != 0 {
		t.Errorf("second daemon nil engine csm_blocked_ips_total = %g, want 0", got)
	}
	other.setFirewallEngine(otherEng)
	if got := readGauge(scrapeBody(t), "csm_blocked_ips_total"); got != 3 {
		t.Errorf("second daemon csm_blocked_ips_total = %g, want 3", got)
	}
}
