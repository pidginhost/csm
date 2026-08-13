package daemon

import (
	"strings"
	"sync"
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

func TestHandleFirewallStatusCountsTopLevelInfraIPsWithoutFirewallSection(t *testing.T) {
	c := newListenerForTest(t)
	c.d.cfg = &config.Config{
		InfraIPs: []string{"192.0.2.10", "192.0.2.11"},
	}
	config.SetActive(c.d.cfg)

	raw, err := c.handleFirewallStatus(nil)
	if err != nil {
		t.Fatalf("handleFirewallStatus: %v", err)
	}
	r := raw.(control.FirewallStatusResult)

	if r.InfraIPCount != 2 {
		t.Fatalf("InfraIPCount = %d, want 2 top-level entries", r.InfraIPCount)
	}

	grepRaw, err := c.handleFirewallGrep([]byte(`{"pattern":"192.0.2.10"}`))
	if err != nil {
		t.Fatalf("handleFirewallGrep: %v", err)
	}
	grepLines := grepRaw.(control.FirewallListResult).Lines
	if len(grepLines) != 1 || grepLines[0] != "INFRA    192.0.2.10" {
		t.Errorf("grep lines = %v, want top-level infra match", grepLines)
	}
}

func TestHandleFirewallStatusUsesOneConfigSnapshotDuringReload(t *testing.T) {
	c := newListenerForTest(t)
	statePath := t.TempDir()
	first := &config.Config{
		StatePath: statePath,
		InfraIPs:  []string{"192.0.2.10"},
		Firewall:  &firewall.FirewallConfig{InfraIPs: []string{"192.0.2.10/32"}},
	}
	second := &config.Config{
		StatePath: statePath,
		InfraIPs:  []string{"198.51.100.10", "198.51.100.11"},
		Firewall:  &firewall.FirewallConfig{InfraIPs: []string{"203.0.113.10"}},
	}
	config.SetActive(first)

	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			default:
				config.SetActive(first)
				config.SetActive(second)
			}
		}
	}()
	defer func() {
		close(stop)
		writer.Wait()
	}()

	for i := 0; i < 100; i++ {
		raw, err := c.handleFirewallStatus(nil)
		if err != nil {
			t.Fatalf("handleFirewallStatus: %v", err)
		}
		got := raw.(control.FirewallStatusResult).InfraIPCount
		if got != 1 && got != 3 {
			t.Fatalf("InfraIPCount = %d, want one complete config snapshot (1 or 3)", got)
		}
	}
}

func TestHandleFirewallStatusReportsEffectiveChallengePort(t *testing.T) {
	c := newListenerForTest(t)
	c.d.cfg = &config.Config{
		Firewall: &firewall.FirewallConfig{
			TCPIn:         []int{80},
			RestrictedTCP: []int{8439, 9443},
		},
	}
	c.d.cfg.Challenge.Enabled = true
	c.d.cfg.Challenge.PortGate.Enabled = true
	c.d.cfg.Challenge.ListenAddr = "0.0.0.0"
	c.d.cfg.Challenge.ListenPort = 8439
	config.SetActive(c.d.cfg)

	raw, err := c.handleFirewallStatus(nil)
	if err != nil {
		t.Fatalf("handleFirewallStatus: %v", err)
	}
	r := raw.(control.FirewallStatusResult)
	if len(r.TCPIn) != 2 || r.TCPIn[0] != "80" || r.TCPIn[1] != "8439" {
		t.Errorf("TCPIn = %v, want [80 8439]", r.TCPIn)
	}
	if len(r.Restricted) != 1 || r.Restricted[0] != "9443" {
		t.Errorf("Restricted = %v, want [9443]", r.Restricted)
	}

	portsRaw, err := c.handleFirewallPorts(nil)
	if err != nil {
		t.Fatalf("handleFirewallPorts: %v", err)
	}
	lines := strings.Join(portsRaw.(control.FirewallListResult).Lines, "\n")
	if !strings.Contains(lines, "80, 8439") || !strings.Contains(lines, "TCP Restricted (infra only):\n  9443") {
		t.Errorf("ports output does not match effective firewall policy:\n%s", lines)
	}
}
