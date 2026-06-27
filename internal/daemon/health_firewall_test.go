package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// TestAutomationStatusFirewallEnabledNotManaged verifies the health snapshot
// reports the "configured on but not managed" condition: firewall.enabled is
// true but no engine is wired (the engine failed to apply at startup). This is
// the signal that previously left the firewall silently unmanaged with no
// machine-readable indication.
func TestAutomationStatusFirewallEnabledNotManaged(t *testing.T) {
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}}
	prev := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prev) })

	d := &Daemon{cfg: cfg}
	got := d.AutomationStatus()
	if !got.FirewallEnabled {
		t.Error("FirewallEnabled should be true when firewall.enabled is set")
	}
	if got.FirewallManaged {
		t.Error("FirewallManaged must be false when no engine is wired (enabled-but-not-managed alert condition)")
	}
}

// TestAutomationStatusFirewallDisabled verifies a disabled firewall reports
// neither enabled nor managed (no false alert).
func TestAutomationStatusFirewallDisabled(t *testing.T) {
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: false}}
	prev := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prev) })

	got := (&Daemon{cfg: cfg}).AutomationStatus()
	if got.FirewallEnabled {
		t.Error("FirewallEnabled should be false when firewall is disabled")
	}
	if got.FirewallManaged {
		t.Error("FirewallManaged should be false when no engine is wired")
	}
}

func TestAutomationStatusFirewallNilConfigSafe(t *testing.T) {
	prev := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prev) })

	tests := []struct {
		name string
		d    *Daemon
	}{
		{name: "nil config", d: &Daemon{}},
		{name: "nil firewall config", d: &Daemon{cfg: &config.Config{}}},
	}

	for _, tt := range tests {
		got := tt.d.AutomationStatus()
		if got.FirewallEnabled {
			t.Errorf("%s: FirewallEnabled should be false", tt.name)
		}
		if got.FirewallManaged {
			t.Errorf("%s: FirewallManaged should be false", tt.name)
		}
		if got.FirewallBlockedIPs != 0 || got.FirewallBlockedSubnets != 0 {
			t.Errorf("%s: block counts should be zero, got ips=%d subnets=%d",
				tt.name, got.FirewallBlockedIPs, got.FirewallBlockedSubnets)
		}
	}
}
