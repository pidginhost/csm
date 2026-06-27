//go:build linux

package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// TestAutomationStatusFirewallManaged verifies that when a live nftables engine
// is wired, the snapshot reports FirewallManaged plus the live block counts.
func TestAutomationStatusFirewallManaged(t *testing.T) {
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}}
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(nil) })

	eng, err := firewall.NewEngine(cfg.Firewall, t.TempDir())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	got := (&Daemon{cfg: cfg, fwEngine: eng}).AutomationStatus()
	if !got.FirewallEnabled {
		t.Error("FirewallEnabled should be true")
	}
	if !got.FirewallManaged {
		t.Error("FirewallManaged should be true when an engine is wired")
	}
	// A fresh engine over an empty state dir has no persisted blocks.
	if got.FirewallBlockedIPs != 0 || got.FirewallBlockedSubnets != 0 {
		t.Errorf("fresh engine should report 0 blocks, got ips=%d subnets=%d", got.FirewallBlockedIPs, got.FirewallBlockedSubnets)
	}
}
