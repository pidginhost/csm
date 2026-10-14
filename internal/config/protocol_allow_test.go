package config

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestProtocolAllowValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  firewall.ProtocolAllowRule
		error string // empty: no protocol_allow error
	}{
		{"ipv4 and ipv6 peers", firewall.ProtocolAllowRule{Protocol: "vrrp", Peers: []string{"192.0.2.11", "198.51.100.0/24", "2001:db8::11", "2001:db8:1::/64"}}, ""},
		{"empty peers", firewall.ProtocolAllowRule{Protocol: "vrrp"}, "peers"},
		{"unknown protocol", firewall.ProtocolAllowRule{Protocol: "gre", Peers: []string{"192.0.2.11"}}, "gre"},
		{"uppercase name", firewall.ProtocolAllowRule{Protocol: "VRRP", Peers: []string{"192.0.2.11"}}, "VRRP"},
		{"tcp has its own keys", firewall.ProtocolAllowRule{Protocol: "tcp", Peers: []string{"192.0.2.11"}}, "tcp"},
		{"udp has its own keys", firewall.ProtocolAllowRule{Protocol: "udp", Peers: []string{"192.0.2.11"}}, "udp"},
		{"icmp has its own keys", firewall.ProtocolAllowRule{Protocol: "icmp", Peers: []string{"192.0.2.11"}}, "icmp"},
		{"icmpv6 has its own keys", firewall.ProtocolAllowRule{Protocol: "icmpv6", Peers: []string{"192.0.2.11"}}, "icmpv6"},
		{"numeric protocol", firewall.ProtocolAllowRule{Protocol: "112", Peers: []string{"192.0.2.11"}}, "112"},
		{"bad address", firewall.ProtocolAllowRule{Protocol: "vrrp", Peers: []string{"192.0.2.11", "db1.example.com"}}, "db1.example.com"},
		{"empty address", firewall.ProtocolAllowRule{Protocol: "vrrp", Peers: []string{""}}, "peer"},
		{"world-wide ipv4", firewall.ProtocolAllowRule{Protocol: "vrrp", Peers: []string{"0.0.0.0/0"}}, "0.0.0.0/0"},
		{"world-wide ipv6", firewall.ProtocolAllowRule{Protocol: "vrrp", Peers: []string{"::/0"}}, "::/0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := firewall.DefaultConfig()
			fw.Enabled = true
			fw.IPv6 = true
			fw.ProtocolAllow = []firewall.ProtocolAllowRule{tc.rule}
			res, found := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.protocol_allow")
			if tc.error == "" {
				if found {
					t.Fatalf("unexpected error: %s", res.Message)
				}
				return
			}
			if !found {
				t.Fatal("want a firewall.protocol_allow error")
			}
			if !strings.Contains(res.Message, tc.error) {
				t.Errorf("message %q should mention %q", res.Message, tc.error)
			}
		})
	}
}
