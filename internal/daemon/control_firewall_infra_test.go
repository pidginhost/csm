package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
)

// The engine is handed mergeInfraIPs(top-level, firewall-section), so a host
// that declares infra_ips only at the top level still gets those addresses
// into the live ruleset. Reporting the firewall-section length alone showed
// "Infra IPs: 0 entries" on a host whose ruleset held six, which reads as an
// imminent lockout and sends an operator hunting a fault that does not exist.
func TestHandleFirewallStatusCountsMergedInfraIPs(t *testing.T) {
	c := newListenerForTest(t)
	c.d.cfg = &config.Config{
		InfraIPs: []string{"192.0.2.10", "192.0.2.11", "198.51.100.7"},
		Firewall: &firewall.FirewallConfig{Enabled: true},
	}
	config.SetActive(c.d.cfg)

	raw, err := c.handleFirewallStatus(nil)
	if err != nil {
		t.Fatalf("handleFirewallStatus: %v", err)
	}
	r := raw.(control.FirewallStatusResult)

	if r.InfraIPCount != 3 {
		t.Fatalf("InfraIPCount = %d, want 3 (top-level entries reach the engine)", r.InfraIPCount)
	}
}

// Entries listed in both sections are one address, not two.
func TestHandleFirewallStatusDeduplicatesInfraIPs(t *testing.T) {
	c := newListenerForTest(t)
	c.d.cfg = &config.Config{
		InfraIPs: []string{"192.0.2.10", "192.0.2.11"},
		Firewall: &firewall.FirewallConfig{
			Enabled:  true,
			InfraIPs: []string{"192.0.2.11", "203.0.113.5"},
		},
	}
	config.SetActive(c.d.cfg)

	raw, err := c.handleFirewallStatus(nil)
	if err != nil {
		t.Fatalf("handleFirewallStatus: %v", err)
	}
	r := raw.(control.FirewallStatusResult)

	if r.InfraIPCount != 3 {
		t.Fatalf("InfraIPCount = %d, want 3 unique addresses across both sections", r.InfraIPCount)
	}
}
