package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// The firewall refuses to block an address in either infra list, so a
// challenge, which can end in a block, must not be aimed at one either.
func TestChallengeRouteSkipsFirewallInfraIPs(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.InfraIPs = []string{"198.51.100.20"}
	cfg.Firewall = &firewall.FirewallConfig{InfraIPs: []string{"203.0.113.0/28", "2001:db8::/64"}}

	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "brute force from 198.51.100.20"},
		{Check: "wp_login_bruteforce", Message: "brute force from 203.0.113.5"},
		{Check: "wp_login_bruteforce", Message: "brute force from 2001:db8::5"},
		{Check: "wp_login_bruteforce", Message: "brute force from 192.0.2.44"},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 1 || !mock.ips["192.0.2.44"] || len(mock.ips) != 1 {
		t.Fatalf("routed %v (%d actions), want only 192.0.2.44", mock.ips, len(actions))
	}
}
