package config

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// Every value below is consumed by a switch whose default branch silently
// picks a behaviour. A typo therefore does not fail, it quietly changes what
// CSM does -- central.action falls open to "challenge", block_at_severity
// falls open to "never block", and a port_flood proto typo falls open to TCP.

func TestValidateCentralAction(t *testing.T) {
	valid := []string{"", "off", "challenge", "block_if_local_corroborated"}
	for _, action := range valid {
		cfg := lockoutTestConfig(nil)
		cfg.Reputation.Central.Enabled = true
		cfg.Reputation.Central.Action = action
		if _, ok := findResult(Validate(cfg), "error", "reputation.central.action"); ok {
			t.Errorf("action %q must be accepted", action)
		}
	}

	cfg := lockoutTestConfig(nil)
	cfg.Reputation.Central.Enabled = true
	cfg.Reputation.Central.Action = "blok_if_local_corroborated"
	res, ok := findResult(Validate(cfg), "error", "reputation.central.action")
	if !ok {
		t.Fatal("a misspelled central action must be rejected, not silently downgraded to challenge")
	}
	if !strings.Contains(res.Message, "block_if_local_corroborated") {
		t.Errorf("error should list the valid values, got %q", res.Message)
	}

	// A typo is worth reporting before the operator flips enabled on.
	disabled := lockoutTestConfig(nil)
	disabled.Reputation.Central.Action = "nonsense"
	if _, ok := findResult(Validate(disabled), "error", "reputation.central.action"); !ok {
		t.Error("a typo in a not-yet-enabled central block should still be reported")
	}
}

func TestValidateBlockAtSeverity(t *testing.T) {
	for _, sev := range []string{"", "high", "critical", "HIGH", "Critical"} {
		cfg := lockoutTestConfig(nil)
		cfg.Incidents.SpraySuppression.BlockAtSeverity = sev
		if _, ok := findResult(Validate(cfg), "error", "incidents.spray_suppression.block_at_severity"); ok {
			t.Errorf("severity %q must be accepted (matching is case-insensitive)", sev)
		}
	}

	cfg := lockoutTestConfig(nil)
	cfg.Incidents.SpraySuppression.BlockAtSeverity = "warning"
	if _, ok := findResult(Validate(cfg), "error", "incidents.spray_suppression.block_at_severity"); !ok {
		t.Error("an unsupported severity silently disables blocking and must be rejected")
	}

	auto := lockoutTestConfig(nil)
	auto.Incidents.AutoBlock.Enabled = true
	auto.Incidents.AutoBlock.BlockAtSeverity = "medium"
	if _, ok := findResult(Validate(auto), "error", "incidents.auto_block.block_at_severity"); !ok {
		t.Error("incidents.auto_block.block_at_severity needs the same check")
	}
}

func TestValidateFirewallPortLists(t *testing.T) {
	for _, tc := range []struct {
		field string
		apply func(fw *firewall.FirewallConfig)
	}{
		{"firewall.tcp_in", func(fw *firewall.FirewallConfig) { fw.TCPIn = []int{22, 70000} }},
		{"firewall.tcp_out", func(fw *firewall.FirewallConfig) { fw.TCPOut = []int{0} }},
		{"firewall.udp_in", func(fw *firewall.FirewallConfig) { fw.UDPIn = []int{-1} }},
		{"firewall.tcp6_in", func(fw *firewall.FirewallConfig) { fw.TCP6In = []int{70000} }},
		{"firewall.tcp6_out", func(fw *firewall.FirewallConfig) { fw.TCP6Out = []int{70000} }},
		{"firewall.udp6_in", func(fw *firewall.FirewallConfig) { fw.UDP6In = []int{0} }},
		{"firewall.udp6_out", func(fw *firewall.FirewallConfig) { fw.UDP6Out = []int{-1} }},
		{"firewall.restricted_tcp", func(fw *firewall.FirewallConfig) { fw.RestrictedTCP = []int{99999} }},
		{"firewall.drop_nolog", func(fw *firewall.FirewallConfig) { fw.DropNoLog = []int{65536} }},
		{"firewall.smtp_ports", func(fw *firewall.FirewallConfig) { fw.SMTPPorts = []int{65536} }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			fw := &firewall.FirewallConfig{Enabled: true, TCPIn: []int{9443}, ConnRateLimit: 200}
			tc.apply(fw)
			if _, ok := findResult(Validate(lockoutTestConfig(fw)), "error", tc.field); !ok {
				t.Errorf("out-of-range port in %s must be rejected", tc.field)
			}
		})
	}

	fw := &firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{22, 443, 9443},
		UDPIn:         []int{53},
		RestrictedTCP: []int{2087},
		DropNoLog:     []int{23},
		ConnRateLimit: 200,
	}
	for _, r := range Validate(lockoutTestConfig(fw)) {
		if r.Level == "error" && strings.HasPrefix(r.Field, "firewall.") {
			t.Errorf("valid port lists produced %s: %s", r.Field, r.Message)
		}
	}
}

func TestValidatePassiveFTPRange(t *testing.T) {
	t.Run("inverted range", func(t *testing.T) {
		fw := &firewall.FirewallConfig{
			Enabled: true, TCPIn: []int{9443}, ConnRateLimit: 200,
			PassiveFTPStart: 65534, PassiveFTPEnd: 49152,
		}
		if _, ok := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.passive_ftp_start"); !ok {
			t.Error("a passive FTP range that ends before it starts must be rejected")
		}
	})

	t.Run("out of range", func(t *testing.T) {
		fw := &firewall.FirewallConfig{
			Enabled: true, TCPIn: []int{9443}, ConnRateLimit: 200,
			PassiveFTPStart: 49152, PassiveFTPEnd: 70000,
		}
		if _, ok := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.passive_ftp_end"); !ok {
			t.Error("a passive FTP port above 65535 must be rejected")
		}
	})

	t.Run("valid range", func(t *testing.T) {
		fw := &firewall.FirewallConfig{
			Enabled: true, TCPIn: []int{9443}, ConnRateLimit: 200,
			PassiveFTPStart: 49152, PassiveFTPEnd: 65534,
		}
		if _, ok := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.passive_ftp_start"); ok {
			t.Error("the shipped default range must validate")
		}
	})
}

func TestValidateCountryCodes(t *testing.T) {
	fw := &firewall.FirewallConfig{
		Enabled: true, TCPIn: []int{9443}, ConnRateLimit: 200,
		CountryBlock: []string{"RO", "cn", "ZZZ"},
	}
	res, ok := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.country_block")
	if !ok {
		t.Fatal("a malformed country code must be rejected")
	}
	if !strings.Contains(res.Message, "ZZZ") {
		t.Errorf("error should name the offending code, got %q", res.Message)
	}

	good := &firewall.FirewallConfig{
		Enabled: true, TCPIn: []int{9443}, ConnRateLimit: 200,
		CountryBlock: []string{"RO", "cn"},
	}
	if _, ok := findResult(Validate(lockoutTestConfig(good)), "error", "firewall.country_block"); ok {
		t.Error("two-letter codes are valid in either case")
	}
}

func TestValidatePortFloodEntries(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule firewall.PortFloodRule
	}{
		{"bad port", firewall.PortFloodRule{Port: 0, Proto: "tcp", Hits: 10, Seconds: 60}},
		{"bad proto", firewall.PortFloodRule{Port: 25, Proto: "ucp", Hits: 10, Seconds: 60}},
		{"uppercase UDP is interpreted as TCP", firewall.PortFloodRule{Port: 53, Proto: "UDP", Hits: 10, Seconds: 60}},
		{"no hits", firewall.PortFloodRule{Port: 25, Proto: "tcp", Hits: 0, Seconds: 60}},
		{"no window", firewall.PortFloodRule{Port: 25, Proto: "tcp", Hits: 10, Seconds: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := &firewall.FirewallConfig{
				Enabled: true, TCPIn: []int{9443}, ConnRateLimit: 200,
				PortFlood: []firewall.PortFloodRule{tc.rule},
			}
			if _, ok := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.port_flood"); !ok {
				t.Errorf("invalid port_flood rule %+v must be rejected", tc.rule)
			}
		})
	}

	fw := &firewall.FirewallConfig{
		Enabled: true, TCPIn: []int{9443}, ConnRateLimit: 200,
		PortFlood: firewall.DefaultConfig().PortFlood,
	}
	if _, ok := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.port_flood"); ok {
		t.Error("the shipped default port_flood rules must validate")
	}

	// The engine treats every spelling of TCP as TCP, including the mixed-case
	// values supported by its mail-port exemption logic.
	fw.PortFlood = []firewall.PortFloodRule{{Port: 25, Proto: "TCP", Hits: 10, Seconds: 60}}
	if _, ok := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.port_flood"); ok {
		t.Error("a case-insensitive TCP protocol that the engine handles must validate")
	}
}
