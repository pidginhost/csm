package config

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func inAllowConfig(ipv6 bool, rules ...firewall.InAllowRule) *Config {
	fw := firewall.DefaultConfig()
	fw.Enabled = true
	fw.IPv6 = ipv6
	fw.TCPInAllow = rules
	return lockoutTestConfig(fw)
}

// The engine renders nothing for an entry it cannot scope, so each of these
// would otherwise read as "the port just does not answer".
func TestInAllowValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  firewall.InAllowRule
		error string // empty: no tcp_in_allow error
	}{
		{"ipv4 and ipv6 sources", firewall.InAllowRule{Port: 3306, Sources: []string{"203.0.113.10", "198.51.100.0/28", "2001:db8::11", "2001:db8:1::/64"}}, ""},
		{"single address as /32", firewall.InAllowRule{Port: 3306, Sources: []string{"203.0.113.10/32"}}, ""},
		{"port zero", firewall.InAllowRule{Port: 0, Sources: []string{"203.0.113.10"}}, "port 0"},
		{"port above range", firewall.InAllowRule{Port: 65536, Sources: []string{"203.0.113.10"}}, "port 65536"},
		{"empty sources", firewall.InAllowRule{Port: 3306}, "sources"},
		{"hostname", firewall.InAllowRule{Port: 3306, Sources: []string{"203.0.113.10", "db1.example.com"}}, "db1.example.com"},
		{"empty address", firewall.InAllowRule{Port: 3306, Sources: []string{""}}, "source"},
		{"world-wide ipv4", firewall.InAllowRule{Port: 3306, Sources: []string{"0.0.0.0/0"}}, "0.0.0.0/0"},
		{"world-wide ipv6", firewall.InAllowRule{Port: 3306, Sources: []string{"::/0"}}, "::/0"},
		{"mapped world-wide ipv4", firewall.InAllowRule{Port: 3306, Sources: []string{"::ffff:192.0.2.11/96"}}, "::ffff:192.0.2.11/96"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, found := findResult(Validate(inAllowConfig(true, tc.rule)), "error", "firewall.tcp_in_allow")
			if tc.error == "" {
				if found {
					t.Fatalf("unexpected error: %s", res.Message)
				}
				return
			}
			if !found {
				t.Fatal("want a firewall.tcp_in_allow error")
			}
			if !strings.Contains(res.Message, tc.error) {
				t.Errorf("message %q should mention %q", res.Message, tc.error)
			}
		})
	}
}

// A bad port does not hide a bad source in the same entry: the operator
// fixes both in one pass.
func TestInAllowReportsPortAndSourceTogether(t *testing.T) {
	results := Validate(inAllowConfig(true, firewall.InAllowRule{Port: 0, Sources: []string{"db1.example.com"}}))
	var port, source bool
	for _, r := range results {
		if r.Level != "error" || r.Field != "firewall.tcp_in_allow" {
			continue
		}
		port = port || strings.Contains(r.Message, "port 0")
		source = source || strings.Contains(r.Message, "db1.example.com")
	}
	if !port || !source {
		t.Fatalf("port error reported=%t, source error reported=%t, want both", port, source)
	}
}

func TestInAllowWarnsOnV6SourceWhileIPv6Off(t *testing.T) {
	results := Validate(inAllowConfig(false, firewall.InAllowRule{Port: 3306, Sources: []string{"2001:db8::11"}}))
	if res, found := findResult(results, "error", "firewall.tcp_in_allow"); found {
		t.Fatalf("unexpected error: %s", res.Message)
	}
	res, found := findResult(results, "warn", "firewall.tcp_in_allow")
	if !found {
		t.Fatal("want a warning: the IPv6 source renders no rule while firewall.ipv6 is off")
	}
	if !strings.Contains(res.Message, "2001:db8::11") {
		t.Errorf("message %q should name the source", res.Message)
	}
}

// An entry on a port tcp_in already opens still does something: it keeps the
// listed sources reaching the port when they are blocked. No finding.
func TestInAllowAcceptsPortAlreadyPublic(t *testing.T) {
	cfg := inAllowConfig(true, firewall.InAllowRule{Port: 443, Sources: []string{"203.0.113.10"}})
	cfg.Firewall.TCPIn = append(cfg.Firewall.TCPIn, 443)
	for _, r := range Validate(cfg) {
		if r.Field == "firewall.tcp_in_allow" {
			t.Fatalf("unexpected %s: %s", r.Level, r.Message)
		}
	}
}

// Naming a port in tcp_in_allow is how an operator asks for a listener only
// chosen sources reach. The lockout checks must not call that a lockout, and
// must keep warning when no source in the entry renders a rule.
func TestInAllowScopedPortIsNotALockout(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []firewall.InAllowRule
		warn  bool
	}{
		{"no entry", nil, true},
		{"usable source", []firewall.InAllowRule{
			{Port: 22, Sources: []string{"db1.example.com", "203.0.113.10"}},
			{Port: 9443, Sources: []string{"198.51.100.0/28"}},
		}, false},
		{"no usable source", []firewall.InAllowRule{
			{Port: 22, Sources: []string{"db1.example.com", "0.0.0.0/0"}},
			{Port: 9443},
		}, true},
		{"entry for another port", []firewall.InAllowRule{{Port: 3306, Sources: []string{"203.0.113.10"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useSSHDConfig(t, "Port 22\n")
			cfg := lockoutTestConfig(&firewall.FirewallConfig{
				Enabled: true, ConnRateLimit: 200,
				TCPIn: []int{80, 443}, IPv6: true, TCP6In: []int{80},
				TCPInAllow: tc.rules,
			})
			got := map[string]bool{}
			for _, r := range append(Validate(cfg), ValidateDeepSection(cfg, "firewall")...) {
				if r.Level != "warn" || (r.Field != "firewall.tcp_in" && r.Field != "firewall.tcp6_in") {
					continue
				}
				for _, service := range []string{"sshd", "web UI"} {
					if strings.Contains(r.Message, service) {
						got[r.Field+" "+service] = true
					}
				}
			}
			for _, key := range []string{"firewall.tcp_in sshd", "firewall.tcp6_in sshd", "firewall.tcp_in web UI", "firewall.tcp6_in web UI"} {
				if got[key] != tc.warn {
					t.Errorf("%s lockout warning = %t, want %t", key, got[key], tc.warn)
				}
			}
		})
	}
}
