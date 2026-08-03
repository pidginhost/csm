package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

func withHostIPv6Addrs(t *testing.T, addrs []string) {
	t.Helper()
	prev := firewallHostIPv6Addrs
	firewallHostIPv6Addrs = func() []string { return addrs }
	t.Cleanup(func() { firewallHostIPv6Addrs = prev })
}

func ipv6TestFirewallCheck(t *testing.T, fc *firewall.FirewallConfig) []alert.Finding {
	t.Helper()
	withMockCmd(t, &mockCmd{
		run: func(name string, _ ...string) ([]byte, error) {
			if name == "nft" {
				return []byte("table inet csm {\n  chain input {\n  }\n  chain output {\n  }\n  set blocked_ips {\n  }\n  set allowed_ips {\n  }\n  set infra_ips {\n  }\n}\n"), nil
			}
			return nil, nil
		},
	})
	cfg := &config.Config{}
	cfg.Firewall = fc
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return CheckFirewall(context.Background(), cfg, st)
}

func findIPv6UnmanagedFinding(findings []alert.Finding) *alert.Finding {
	for i := range findings {
		if findings[i].Check == "firewall_ipv6_unmanaged" {
			return &findings[i]
		}
	}
	return nil
}

// A DROP-policy firewall that blanket-accepts an entire address family is a
// silent posture gap: the engine inserts an NFPROTO ipv6 accept ahead of the
// blocked sets when firewall.ipv6 is false. Operators on dual-stack hosts
// must hear about it.
func TestCheckFirewallWarnsWhenIPv6UnmanagedOnDualStackHost(t *testing.T) {
	withHostIPv6Addrs(t, []string{"2001:db8::10"})
	findings := ipv6TestFirewallCheck(t, &firewall.FirewallConfig{Enabled: true})

	f := findIPv6UnmanagedFinding(findings)
	if f == nil {
		t.Fatalf("findings = %+v, want firewall_ipv6_unmanaged", findings)
	}
	if f.Severity != alert.High {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	if !strings.Contains(f.Message, "2001:db8::10") {
		t.Errorf("message %q should name a global IPv6 address", f.Message)
	}
}

func TestCheckFirewallNoIPv6WarningWhenManaged(t *testing.T) {
	withHostIPv6Addrs(t, []string{"2001:db8::10"})
	findings := ipv6TestFirewallCheck(t, &firewall.FirewallConfig{Enabled: true, IPv6: true})
	if f := findIPv6UnmanagedFinding(findings); f != nil {
		t.Errorf("unexpected finding with ipv6 enabled: %+v", f)
	}
}

func TestCheckFirewallNoIPv6WarningWithoutGlobalAddress(t *testing.T) {
	withHostIPv6Addrs(t, nil)
	findings := ipv6TestFirewallCheck(t, &firewall.FirewallConfig{Enabled: true})
	if f := findIPv6UnmanagedFinding(findings); f != nil {
		t.Errorf("unexpected finding without global IPv6 addresses: %+v", f)
	}
}

func TestHostGlobalIPv6AddrsFiltering(t *testing.T) {
	// The production address source must skip loopback, link-local, ULA,
	// and IPv4; only global unicast IPv6 counts as attack surface.
	cases := []struct {
		addr string
		want bool
	}{
		{"2001:db8::1/64", true},
		{"::1/128", false},
		{"fe80::1/64", false},
		{"fd00::1/64", false},
		{"192.0.2.1/24", false},
	}
	for _, tc := range cases {
		got := globalUnicastIPv6FromCIDR(tc.addr)
		if (got != "") != tc.want {
			t.Errorf("globalUnicastIPv6FromCIDR(%q) = %q, want included=%v", tc.addr, got, tc.want)
		}
	}
}
