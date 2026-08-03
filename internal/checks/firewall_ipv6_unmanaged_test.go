package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

func withHostIPv6Addrs(t *testing.T, addrs []string) {
	t.Helper()
	withHostIPv6AddrSource(t, func() ([]string, error) { return addrs, nil })
}

func withHostIPv6AddrSource(t *testing.T, source func() ([]string, error)) {
	t.Helper()
	prev := firewallHostIPv6Addrs
	firewallHostIPv6Addrs = source
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
	if !strings.Contains(f.Message, "firewall.ipv6: true") {
		t.Errorf("message %q should explain how to enable IPv6 filtering", f.Message)
	}
}

func TestCheckFirewallNoIPv6WarningWhenManaged(t *testing.T) {
	withHostIPv6AddrSource(t, func() ([]string, error) {
		t.Fatal("managed IPv6 must not probe host interface addresses")
		return nil, nil
	})
	findings := ipv6TestFirewallCheck(t, &firewall.FirewallConfig{Enabled: true, IPv6: true})
	if f := findIPv6UnmanagedFinding(findings); f != nil {
		t.Errorf("unexpected finding with ipv6 enabled: %+v", f)
	}
}

func TestCheckFirewallNoIPv6WarningWhenFirewallDisabled(t *testing.T) {
	withHostIPv6AddrSource(t, func() ([]string, error) {
		t.Fatal("disabled firewall must not probe host interface addresses")
		return nil, nil
	})
	findings := ipv6TestFirewallCheck(t, &firewall.FirewallConfig{})
	if f := findIPv6UnmanagedFinding(findings); f != nil {
		t.Errorf("unexpected finding with firewall disabled: %+v", f)
	}
}

func TestCheckFirewallNoIPv6WarningWithoutGlobalAddress(t *testing.T) {
	withHostIPv6Addrs(t, nil)
	findings := ipv6TestFirewallCheck(t, &firewall.FirewallConfig{Enabled: true})
	if f := findIPv6UnmanagedFinding(findings); f != nil {
		t.Errorf("unexpected finding without global IPv6 addresses: %+v", f)
	}
}

func TestCheckFirewallReportsIPv6AddressInspectionFailure(t *testing.T) {
	withHostIPv6AddrSource(t, func() ([]string, error) {
		return nil, errors.New("interface enumeration failed")
	})
	findings := ipv6TestFirewallCheck(t, &firewall.FirewallConfig{Enabled: true})
	f := findIPv6UnmanagedFinding(findings)
	if f == nil {
		t.Fatalf("findings = %+v, want firewall_ipv6_unmanaged inspection warning", findings)
	}
	if f.Severity != alert.Warning {
		t.Errorf("severity = %v, want Warning", f.Severity)
	}
	if !strings.Contains(f.Message, "Unable to inspect host IPv6 addresses") {
		t.Errorf("message %q should explain the failed inspection", f.Message)
	}
}

func TestHostGlobalIPv6AddrsFiltering(t *testing.T) {
	// The production address source must skip loopback, link-local, ULA,
	// and IPv4; only global unicast IPv6 counts as attack surface.
	cases := []struct {
		addr string
		want string
	}{
		{"2001:db8::1/64", "2001:db8::1"},
		{"2001:db8::2%eth0/64", "2001:db8::2"},
		{"2001:db8::3%eth0", "2001:db8::3"},
		{"::1/128", ""},
		{"fe80::1%eth0/64", ""},
		{"fd00::1/64", ""},
		{"192.0.2.1/24", ""},
		{"::ffff:192.0.2.1/128", ""},
		{"::ffff:c000:201/128", ""},
		{"not-an-address", ""},
	}
	for _, tc := range cases {
		got := globalUnicastIPv6FromCIDR(tc.addr)
		if got != tc.want {
			t.Errorf("globalUnicastIPv6FromCIDR(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestCheckFirewallIPv6FindingIdentityIgnoresAddressOrder(t *testing.T) {
	withHostIPv6Addrs(t, []string{"2001:db8::20", "2001:db8::10"})
	first := findIPv6UnmanagedFinding(ipv6TestFirewallCheck(t, &firewall.FirewallConfig{Enabled: true}))
	if first == nil {
		t.Fatal("first scan did not emit firewall_ipv6_unmanaged")
	}

	withHostIPv6Addrs(t, []string{"2001:db8::10", "2001:db8::20"})
	second := findIPv6UnmanagedFinding(ipv6TestFirewallCheck(t, &firewall.FirewallConfig{Enabled: true}))
	if second == nil {
		t.Fatal("second scan did not emit firewall_ipv6_unmanaged")
	}
	if first.Key() != second.Key() || first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("address enumeration order changed finding identity: first=%q second=%q", first.Key(), second.Key())
	}
}
