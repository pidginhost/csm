package checks

import (
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// The firewall refuses to block an address in either infra list, so a
// challenge, which can end in a block, must not be aimed at one either.
func TestChallengeRouteSkipsFirewallInfraIPs(t *testing.T) {
	a := withAdmission(t)
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
	if calls := a.responses(); len(calls) != 1 || calls[0].target != "192.0.2.44" {
		t.Fatalf("admission responses = %+v, want only 192.0.2.44", calls)
	}
}

func TestChallengeRouteInfraAddressForms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ip       string
		topLevel []string
		firewall *firewall.FirewallConfig
	}{
		{"top-level without firewall", "198.51.100.20", []string{"198.51.100.20"}, nil},
		{"firewall IPv4", "203.0.113.5", nil, &firewall.FirewallConfig{InfraIPs: []string{"203.0.113.5"}}},
		{"firewall IPv4 CIDR", "203.0.113.5", nil, &firewall.FirewallConfig{InfraIPs: []string{"203.0.113.0/28"}}},
		{"firewall IPv6", "2001:db8::5", nil, &firewall.FirewallConfig{InfraIPs: []string{"2001:0db8:0:0:0:0:0:5"}}},
		{"firewall IPv6 CIDR", "2001:db8::5", nil, &firewall.FirewallConfig{InfraIPs: []string{"2001:db8::/64"}}},
		{"firewall mapped IPv4 CIDR", "203.0.113.5", nil, &firewall.FirewallConfig{InfraIPs: []string{"::ffff:203.0.113.0/124"}}},
		{"firewall whitespace", "203.0.113.5", nil, &firewall.FirewallConfig{InfraIPs: []string{"", " 203.0.113.5 "}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := withAdmission(t)
			list := &mockIPList{ips: make(map[string]bool)}
			withChallengeList(t, list)
			cfg := &config.Config{}
			cfg.Challenge.Enabled = true
			findings := []alert.Finding{{Check: "wp_login_bruteforce", SourceIP: tc.ip}}
			before := append([]alert.Finding(nil), findings...)

			// Each address must be routable without the exemption, including IPv6.
			if actions := ChallengeRouteIPs(cfg, findings); len(actions) != 1 || !list.Contains(tc.ip) {
				t.Fatalf("unprotected address: actions = %v, list = %v", actions, list.ips)
			}
			list.Remove(tc.ip)
			if calls := a.responses(); len(calls) != 1 || calls[0].target != tc.ip {
				t.Fatalf("unprotected admission responses = %+v, want only %s", calls, tc.ip)
			}

			cfg.InfraIPs, cfg.Firewall = tc.topLevel, tc.firewall
			detectionInfra := append([]string(nil), cfg.InfraIPs...)
			if actions := ChallengeRouteIPs(cfg, findings); len(actions) != 0 || len(list.ips) != 0 {
				t.Fatalf("protected address: actions = %v, list = %v", actions, list.ips)
			}
			if calls := a.responses(); len(calls) != 1 {
				t.Fatalf("protected address reached admission: %+v", calls)
			}
			if !reflect.DeepEqual(findings, before) || !reflect.DeepEqual(cfg.InfraIPs, detectionInfra) {
				t.Fatal("routing changed the findings or the detection exemption list")
			}
		})
	}
}

type protectingBlocker struct {
	fakeBlocker
	protected map[string]bool
}

func (p *protectingBlocker) BlockProtected(ip string) bool { return p.protected[ip] }

// The engine also protects what config cannot show: the current addresses
// of infra hostnames and the host's own interfaces. Routing asks it.
func TestChallengeRouteSkipsEngineProtectedIPs(t *testing.T) {
	a := withAdmission(t)
	list := &mockIPList{ips: make(map[string]bool)}
	withChallengeList(t, list)
	oldBlocker := getIPBlocker()
	SetIPBlocker(&protectingBlocker{fakeBlocker: fakeBlocker{blocked: map[string]bool{}}, protected: map[string]bool{"198.51.100.5": true}})
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", SourceIP: "198.51.100.5"},
		{Check: "wp_login_bruteforce", SourceIP: "192.0.2.44"},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 1 || !list.Contains("192.0.2.44") || len(list.ips) != 1 {
		t.Fatalf("routed %v (%d actions), want only 192.0.2.44", list.ips, len(actions))
	}
	if calls := a.responses(); len(calls) != 1 || calls[0].target != "192.0.2.44" {
		t.Fatalf("admission responses = %+v, want only 192.0.2.44", calls)
	}
}
