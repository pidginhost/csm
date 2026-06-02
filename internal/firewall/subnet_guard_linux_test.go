//go:build linux

package firewall

import (
	"net"
	"strings"
	"testing"
)

// Documentation ranges (RFC 5737 / RFC 3849) keep real customer addresses out
// of committed tests.

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	return network
}

// A subnet block must be refused when it would firewall infrastructure the
// daemon must never drop. Before the guard, BlockSubnet went straight to nft,
// so a /24 containing the panel/management IP locked the operator out and a
// shared-hosting /24 could be weaponised against unrelated customers.
func TestSubnetSafetyGuard_RefusesUnsafeRanges(t *testing.T) {
	e := &Engine{
		cfg: &FirewallConfig{
			InfraIPs: []string{"192.0.2.1", "192.0.2.128/25"},
		},
		infraResolved:    map[string]map[string]struct{}{"panel.example": {"198.51.100.7": {}}},
		allowedIPIndex:   map[string]struct{}{"192.0.2.10": {}},
		localAddrsLookup: func() ([]string, error) { return []string{"203.0.113.5"}, nil },
	}

	cases := []struct {
		name string
		cidr string
		want string
	}{
		{"default route", "0.0.0.0/0", "default route"},
		{"contains infra IP", "192.0.2.0/26", "infra IP 192.0.2.1"},
		{"overlaps infra CIDR", "192.0.2.0/24", "infra"},
		{"contains resolved infra host", "198.51.100.0/24", "resolved from panel.example"},
		{"contains local addr", "203.0.113.0/24", "local host IP 203.0.113.5"},
		{"contains allowed IP", "192.0.2.8/30", "allowed IP 192.0.2.10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := e.subnetSafetyGuardLocked(mustCIDR(t, tc.cidr))
			if err == nil {
				t.Fatalf("expected refusal for %s, got nil", tc.cidr)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

// A subnet with no overlap against infra, local, resolved, or allowed sets
// must pass the guard so real malicious ranges can still be blocked.
func TestSubnetSafetyGuard_AllowsSafeRange(t *testing.T) {
	e := &Engine{
		cfg:              &FirewallConfig{InfraIPs: []string{"192.0.2.1"}},
		localAddrsLookup: func() ([]string, error) { return []string{"203.0.113.5"}, nil },
	}
	if err := e.subnetSafetyGuardLocked(mustCIDR(t, "198.51.100.0/24")); err != nil {
		t.Fatalf("safe subnet must pass guard, got %v", err)
	}
}

// IPv6 default route and infra containment are guarded the same way.
func TestSubnetSafetyGuard_IPv6(t *testing.T) {
	e := &Engine{
		cfg:              &FirewallConfig{InfraIPs: []string{"2001:db8:1::1"}},
		localAddrsLookup: func() ([]string, error) { return nil, nil },
	}
	if err := e.subnetSafetyGuardLocked(mustCIDR(t, "::/0")); err == nil {
		t.Fatal("IPv6 default route must be refused")
	}
	if err := e.subnetSafetyGuardLocked(mustCIDR(t, "2001:db8:1::/64")); err == nil {
		t.Fatal("IPv6 subnet containing infra IP must be refused")
	}
	if err := e.subnetSafetyGuardLocked(mustCIDR(t, "2001:db8:2::/64")); err != nil {
		t.Fatalf("safe IPv6 subnet must pass, got %v", err)
	}
}
