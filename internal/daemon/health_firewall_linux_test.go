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

// TestAutomationStatusFirewallManaged verifies that when a live nftables engine
// is wired, the snapshot reports FirewallManaged plus the live block counts.
func TestAutomationStatusFirewallManaged(t *testing.T) {
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}}
	prev := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prev) })

	stateRoot := t.TempDir()
	eng, err := firewall.NewEngine(cfg.Firewall, stateRoot)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	writeAutomationFirewallState(t, stateRoot, firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.10", Reason: "test", BlockedAt: time.Now()},
			{IP: "203.0.113.11", Reason: "test", BlockedAt: time.Now()},
		},
		BlockedNet: []firewall.SubnetEntry{
			{CIDR: "198.51.100.0/24", Reason: "test", BlockedAt: time.Now()},
		},
	})

	got := (&Daemon{cfg: cfg, fwEngine: eng}).AutomationStatus()
	if !got.FirewallEnabled {
		t.Error("FirewallEnabled should be true")
	}
	if !got.FirewallManaged {
		t.Error("FirewallManaged should be true when an engine is wired")
	}
	if got.FirewallBlockedIPs != 2 || got.FirewallBlockedSubnets != 1 {
		t.Errorf("block counts = ips:%d subnets:%d, want ips:2 subnets:1",
			got.FirewallBlockedIPs, got.FirewallBlockedSubnets)
	}
}

func writeAutomationFirewallState(t *testing.T, stateRoot string, state firewall.FirewallState) {
	t.Helper()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, "firewall", "state.json"), data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// TestAutomationStatusLocalPortLocks verifies the snapshot reports the ports
// the live engine locks, and none when no engine is wired.
func TestAutomationStatusLocalPortLocks(t *testing.T) {
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true, LocalPortLocks: []string{"8080:www-data,stalwart"}}}
	prev := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prev) })

	eng, err := firewall.NewEngine(cfg.Firewall, t.TempDir())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if got := (&Daemon{cfg: cfg, fwEngine: eng}).AutomationStatus().FirewallLocalPortLocks; len(got) != 1 || got[0] != 8080 {
		t.Fatalf("FirewallLocalPortLocks = %v, want [8080]", got)
	}
	if got := (&Daemon{cfg: cfg}).AutomationStatus().FirewallLocalPortLocks; got != nil {
		t.Fatalf("without an engine FirewallLocalPortLocks = %v, want none", got)
	}
}
