package config

import (
	"os"
	"path/filepath"
	"reflect"
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
		{"mapped world-wide ipv4", firewall.ProtocolAllowRule{Protocol: "vrrp", Peers: []string{"::ffff:192.0.2.11/96"}}, "matches every address"},
		{"world-wide with host bits", firewall.ProtocolAllowRule{Protocol: "vrrp", Peers: []string{"192.0.2.11/0"}}, "matches every address"},
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

func TestProtocolAllowStrictYAMLAndDropIns(t *testing.T) {
	const rule = "  protocol_allow:\n    - protocol: vrrp\n      peers: [192.0.2.11, 2001:db8::11]\n"
	want := []firewall.ProtocolAllowRule{{Protocol: "vrrp", Peers: []string{"192.0.2.11", "2001:db8::11"}}}
	for _, dropIn := range []bool{false, true} {
		t.Run(map[bool]string{false: "main", true: "drop-in"}[dropIn], func(t *testing.T) {
			for _, tc := range []struct{ name, body, decodeError, validationError string }{
				{"valid", rule, "", ""},
				{"unknown key", strings.ReplaceAll(rule, "peers:", "peer:"), "peer", ""},
				{"wrong type", strings.ReplaceAll(rule, "[192.0.2.11, 2001:db8::11]", "192.0.2.11"), "cannot unmarshal", ""},
				{"missing peers", "  protocol_allow:\n    - protocol: vrrp\n", "", "peers is required"},
				{"world", strings.ReplaceAll(rule, "192.0.2.11", "0.0.0.0/0"), "", "matches every address"},
				{"unknown protocol", strings.ReplaceAll(rule, "vrrp", "gre"), "", "unknown protocol"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					main := "firewall:\n  enabled: true\n  ipv6: true\n"
					dir := t.TempDir()
					if dropIn {
						if err := os.WriteFile(filepath.Join(dir, "peers.yaml"), []byte("firewall:\n"+tc.body), 0600); err != nil {
							t.Fatal(err)
						}
					} else {
						main += tc.body
					}
					cfg, err := LoadBytesWithDir([]byte(main), dir)
					if tc.decodeError != "" {
						if err == nil || !strings.Contains(err.Error(), tc.decodeError) {
							t.Fatalf("decode error = %v, want %q", err, tc.decodeError)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					result, found := findResult(Validate(cfg), "error", "firewall.protocol_allow")
					if tc.validationError != "" {
						if !found || !strings.Contains(result.Message, tc.validationError) {
							t.Fatalf("validation = %+v, want %q", result, tc.validationError)
						}
					} else if found || !reflect.DeepEqual(cfg.Firewall.ProtocolAllow, want) {
						t.Fatalf("decoded peers = %+v, validation = %+v", cfg.Firewall.ProtocolAllow, result)
					}
				})
			}
		})
	}
}
