package config

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func outAllowConfig(rules ...firewall.OutAllowRule) *Config {
	fw := firewall.DefaultConfig()
	fw.Enabled = true
	fw.TCPOutAllow = rules
	return lockoutTestConfig(fw)
}

func TestOutAllowRejectsUnparseableDst(t *testing.T) {
	cfg := outAllowConfig(firewall.OutAllowRule{Dst: "not-an-ip", PortStart: 49152, PortEnd: 65534})
	if _, ok := findResult(Validate(cfg), "error", "firewall.tcp_out_allow"); !ok {
		t.Fatal("a dst that is neither an IP nor a CIDR must be rejected; the engine would silently emit no rule")
	}
}

func TestOutAllowRejectsInvertedRange(t *testing.T) {
	cfg := outAllowConfig(firewall.OutAllowRule{Dst: "203.0.113.155/32", PortStart: 65534, PortEnd: 49152})
	if _, ok := findResult(Validate(cfg), "error", "firewall.tcp_out_allow"); !ok {
		t.Fatal("port_start above port_end matches nothing and must be rejected")
	}
}

func TestOutAllowRejectsOutOfRangePort(t *testing.T) {
	cfg := outAllowConfig(firewall.OutAllowRule{Dst: "203.0.113.155/32", PortStart: 0, PortEnd: 70000})
	if _, ok := findResult(Validate(cfg), "error", "firewall.tcp_out_allow"); !ok {
		t.Fatal("ports outside 1-65535 must be rejected")
	}
}

// Rule order already makes this unreachable -- the smtp_block drop is emitted
// first -- but order must not be the only thing standing between a config key
// and outbound mail.
func TestOutAllowRejectsRangeCoveringSMTPPort(t *testing.T) {
	fw := firewall.DefaultConfig()
	fw.Enabled = true
	fw.SMTPBlock = true
	fw.SMTPPorts = []int{25, 465, 587}
	fw.TCPOutAllow = []firewall.OutAllowRule{{Dst: "203.0.113.155/32", PortStart: 20, PortEnd: 600}}
	res, ok := findResult(Validate(lockoutTestConfig(fw)), "error", "firewall.tcp_out_allow")
	if !ok {
		t.Fatal("a range covering an smtp_ports entry must be rejected while smtp_block is on")
	}
	if !strings.Contains(res.Message, "smtp") {
		t.Errorf("error should name smtp_block as the reason, got %q", res.Message)
	}
}

func TestOutAllowWarnsOnAnyDestination(t *testing.T) {
	cfg := outAllowConfig(firewall.OutAllowRule{Dst: "0.0.0.0/0", PortStart: 49152, PortEnd: 65534})
	if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp_out_allow"); !ok {
		t.Fatal("0.0.0.0/0 opens the range to the whole internet and must warn")
	}
	if _, ok := findResult(Validate(cfg), "error", "firewall.tcp_out_allow"); ok {
		t.Error("any-destination is a supported choice; it warns, it does not error")
	}
}

func TestOutAllowWarnsOnV6DstWhileIPv6Off(t *testing.T) {
	fw := firewall.DefaultConfig()
	fw.Enabled = true
	fw.IPv6 = false
	fw.TCPOutAllow = []firewall.OutAllowRule{{Dst: "2001:db8::1/128", PortStart: 49152, PortEnd: 65534}}
	if _, ok := findResult(Validate(lockoutTestConfig(fw)), "warn", "firewall.tcp_out_allow"); !ok {
		t.Fatal("a v6 dst emits no rule while ipv6 is off; silently doing nothing must warn")
	}
}

func TestOutAllowAcceptsValidRule(t *testing.T) {
	cfg := outAllowConfig(firewall.OutAllowRule{Dst: "203.0.113.155/32", PortStart: 49152, PortEnd: 65534})
	if res, ok := findResult(Validate(cfg), "error", "firewall.tcp_out_allow"); ok {
		t.Fatalf("a well-formed rule must be accepted, got error %q", res.Message)
	}
	if res, ok := findResult(Validate(cfg), "warn", "firewall.tcp_out_allow"); ok {
		t.Fatalf("a scoped rule must not warn, got %q", res.Message)
	}
}

// firewallEgressResults mirrors the output chain. Once tcp_out_allow can open
// a port the chain would otherwise drop, a mirror that does not know about it
// reports a lockout that will not happen.
func TestEgressIgnoresPortCoveredByAnyDestinationOutAllow(t *testing.T) {
	cfg := egressTestConfig([]int{443})
	cfg.Firewall.TCPOutAllow = []firewall.OutAllowRule{{Dst: "0.0.0.0/0", PortStart: 8443, PortEnd: 8443}}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api/csm/findings"

	for _, r := range egressWarnings(cfg) {
		if strings.Contains(r.Message, "8443") {
			t.Fatalf("an any-destination rule reaches the endpoint, so no lockout warning is due: %q", r.Message)
		}
	}
}

// A scoped rule may or may not cover the endpoint -- validation cannot resolve
// the host to prove it. Staying silent would reintroduce the silent-lockout
// failure the egress warnings exist to catch, so it still warns and says why.
func TestEgressStillWarnsWhenOutAllowIsScoped(t *testing.T) {
	cfg := egressTestConfig([]int{443})
	cfg.Firewall.TCPOutAllow = []firewall.OutAllowRule{{Dst: "203.0.113.10/32", PortStart: 8443, PortEnd: 8443}}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api/csm/findings"

	assertWarnMentions(t, egressWarnings(cfg), "firewall.tcp_out", "8443", "tcp_out_allow")
}
