package firewall

import (
	"net"
	"testing"
)

func TestEffectiveDOSExemptNets(t *testing.T) {
	tr := true
	cfg := &FirewallConfig{DOSExemptRanges: []string{"203.0.113.0/24", "2001:db8::/32"}, DOSExemptKnownMailProviders: &tr}
	_, prov, _ := net.ParseCIDR("198.51.100.0/24")
	v4, v6 := EffectiveDOSExemptNets(cfg, []*net.IPNet{prov})
	if len(v4) != 2 || len(v6) != 1 {
		t.Fatalf("got v4=%d v6=%d", len(v4), len(v6))
	}
	f := false
	cfg.DOSExemptKnownMailProviders = &f
	v4b, _ := EffectiveDOSExemptNets(cfg, []*net.IPNet{prov})
	if len(v4b) != 1 {
		t.Fatalf("toggle false must drop provider nets, got %d", len(v4b))
	}
	v4nil, v6nil := EffectiveDOSExemptNets(nil, []*net.IPNet{prov})
	if len(v4nil) != 1 || len(v6nil) != 0 {
		t.Fatalf("nil cfg should still allow provider nets, got v4=%d v6=%d", len(v4nil), len(v6nil))
	}

	// Deep-copy regression: a mutation to a returned net must not leak into a
	// later call. Covers both the operator-range copy path and the provider-net
	// copy path. If either aliases caller/package state, this fails.
	mutCfg := &FirewallConfig{DOSExemptRanges: []string{"203.0.113.0/24"}, DOSExemptKnownMailProviders: &tr}
	_, mutProv, _ := net.ParseCIDR("198.51.100.0/24")
	first, _ := EffectiveDOSExemptNets(mutCfg, []*net.IPNet{mutProv})
	if len(first) != 2 {
		t.Fatalf("deep-copy setup: want 2 v4 nets, got %d", len(first))
	}
	// first[0] = operator 203.0.113.0/24, first[1] = provider 198.51.100.0/24.
	first[0].IP[0] = 0 // mutate operator-range copy
	first[1].IP[0] = 0 // mutate provider-net copy
	second, _ := EffectiveDOSExemptNets(mutCfg, []*net.IPNet{mutProv})
	if second[0].IP[0] != 203 {
		t.Fatalf("operator-range path aliased: second call IP[0]=%d, want 203", second[0].IP[0])
	}
	if second[1].IP[0] != 198 {
		t.Fatalf("provider-net path aliased: second call IP[0]=%d, want 198", second[1].IP[0])
	}
}

func TestParseExemptNet(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // CIDR form of the expected net; "" means nil
	}{
		{"cidr", "203.0.113.0/24", "203.0.113.0/24"},
		{"bare-ipv4", "192.0.2.1", "192.0.2.1/32"},
		{"bare-ipv6", "2001:db8::1", "2001:db8::1/128"},
		{"invalid", "not-an-ip", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseExemptNet(c.in)
			if c.want == "" {
				if got != nil {
					t.Fatalf("parseExemptNet(%q) = %v, want nil", c.in, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseExemptNet(%q) = nil, want %s", c.in, c.want)
			}
			if got.String() != c.want {
				t.Fatalf("parseExemptNet(%q) = %s, want %s", c.in, got.String(), c.want)
			}
		})
	}
}
