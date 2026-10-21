package config

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func webUIExposureConfig(listen string) *Config {
	cfg := baseValidationConfig()
	cfg.WebUI.Enabled = true
	cfg.WebUI.Listen = listen
	cfg.WebUI.Tokens = []WebUIToken{{Name: "ops", Token: strings.Repeat("a", minWebUITokenLength), Scope: "admin"}}
	return cfg
}

// The web UI is root-equivalent. Listening on every interface is fine behind
// the CSM firewall or with address-limited admin tokens; with neither, only a
// host firewall CSM cannot see stands between it and the internet.
func TestValidateWarnsWhenWebUIIsOpenToEveryNetwork(t *testing.T) {
	for _, listen := range []string{"", "0.0.0.0:9443", "[::]:9443", ":9443", "198.51.100.7:9443", "csm.example.com:9443"} {
		t.Run(listen, func(t *testing.T) {
			if results := Validate(webUIExposureConfig(listen)); !hasResult(results, "warn", "webui.listen") {
				t.Fatalf("no exposure warning for listen %q: %v", listen, results)
			}
		})
	}
}

func TestValidateWarnsForLegacyWebUIToken(t *testing.T) {
	cfg := webUIExposureConfig("0.0.0.0:9443")
	cfg.WebUI.Tokens = nil
	cfg.WebUI.AuthToken = strings.Repeat("a", minWebUITokenLength)
	if results := Validate(cfg); !hasResult(results, "warn", "webui.listen") {
		t.Fatalf("no exposure warning for an unrestricted legacy token: %v", results)
	}
}

func TestValidateWebUIExposureWithUnrestrictedTokenNetworks(t *testing.T) {
	for _, tt := range []struct {
		listen string
		source string
		warn   bool
	}{
		{"0.0.0.0:9443", "0.0.0.0/0", true},
		{"0.0.0.0:9443", "::/0", true},
		{"198.51.100.7:9443", "::ffff:0.0.0.0/96", true},
		{"[2001:db8::7]:9443", "::/0", true},
		{"198.51.100.7:9443", "::/0", false},
		{"[2001:db8::7]:9443", "0.0.0.0/0", false},
		{"0.0.0.0:9443", "203.0.113.0/24", false},
	} {
		t.Run(tt.listen+"/"+tt.source, func(t *testing.T) {
			cfg := webUIExposureConfig(tt.listen)
			cfg.WebUI.Tokens[0].AllowedIPs = []string{tt.source}
			if results := Validate(cfg); hasResult(results, "warn", "webui.listen") != tt.warn {
				t.Fatalf("want exposure warning %v: %v", tt.warn, results)
			}
		})
	}
}

func TestValidateWebUIExposureMatchesTokenAndFirewallFamilies(t *testing.T) {
	cfg := webUIExposureConfig("[::]:9443")
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true, IPv6: true, TCP6In: []int{9443}}
	cfg.WebUI.Tokens[0].AllowedIPs = []string{"0.0.0.0/0"}
	if results := Validate(cfg); hasResult(results, "warn", "webui.listen") {
		t.Fatalf("IPv4 is blocked by the firewall and IPv6 by the token: %v", results)
	}
	cfg.WebUI.Tokens[0].AllowedIPs = []string{"::/0"}
	if results := Validate(cfg); !hasResult(results, "warn", "webui.listen") {
		t.Fatalf("IPv6 is public through both the firewall and token: %v", results)
	}
}

func TestValidateDoesNotWarnWhenWebUIExposureIsLimited(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"ipv4 loopback": func(c *Config) { c.WebUI.Listen = "127.0.0.1:9443" },
		"ipv6 loopback": func(c *Config) { c.WebUI.Listen = "[::1]:9443" },
		"localhost":     func(c *Config) { c.WebUI.Listen = "localhost:9443" },
		"csm firewall":  func(c *Config) { c.Firewall = &firewall.FirewallConfig{Enabled: true, IPv6: true} },
		"web ui off":    func(c *Config) { c.WebUI.Enabled = false },
		"limited admin tokens": func(c *Config) {
			c.WebUI.Tokens[0].AllowedIPs = []string{"203.0.113.0/24"}
			c.WebUI.Tokens = append(c.WebUI.Tokens, WebUIToken{Name: "panel", Token: strings.Repeat("b", minWebUITokenLength), Scope: "read"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := webUIExposureConfig("0.0.0.0:9443")
			mutate(cfg)
			if results := Validate(cfg); hasResult(results, "warn", "webui.listen") {
				t.Fatalf("unexpected exposure warning: %v", results)
			}
		})
	}
}

func TestValidateWebUIExposureUsesFirewallPolicy(t *testing.T) {
	for _, tt := range []struct {
		name   string
		listen string
		fw     firewall.FirewallConfig
		warn   bool
	}{
		{"public IPv4 port", "198.51.100.7:9443", firewall.FirewallConfig{TCPIn: []int{9443}}, true},
		{"restricted IPv4 port", "198.51.100.7:9443", firewall.FirewallConfig{TCPIn: []int{9443}, RestrictedTCP: []int{9443}}, false},
		{"closed IPv4 port", "198.51.100.7:9443", firewall.FirewallConfig{}, false},
		{"unmanaged IPv6", "[2001:db8::7]:9443", firewall.FirewallConfig{RestrictedTCP: []int{9443}}, true},
		{"public IPv6 port", "[2001:db8::7]:9443", firewall.FirewallConfig{IPv6: true, TCP6In: []int{9443}}, true},
		{"inherited IPv6 port", "[2001:db8::7]:9443", firewall.FirewallConfig{IPv6: true, TCPIn: []int{9443}}, true},
		{"closed IPv6 override", "[2001:db8::7]:9443", firewall.FirewallConfig{IPv6: true, TCPIn: []int{9443}, TCP6In: []int{443}}, false},
		{"restricted IPv6 port", "[2001:db8::7]:9443", firewall.FirewallConfig{IPv6: true, TCP6In: []int{9443}, RestrictedTCP: []int{9443}}, false},
		{"default wildcard", "", firewall.FirewallConfig{RestrictedTCP: []int{9443}}, true},
		{"IPv4 wildcard can bind dual stack", "0.0.0.0:9443", firewall.FirewallConfig{RestrictedTCP: []int{9443}}, true},
		{"IPv6 wildcard", "[::]:9443", firewall.FirewallConfig{RestrictedTCP: []int{9443}}, true},
		{"empty host", ":9443", firewall.FirewallConfig{RestrictedTCP: []int{9443}}, true},
		{"hostname may resolve to IPv6", "csm.example.com:9443", firewall.FirewallConfig{RestrictedTCP: []int{9443}}, true},
		{"protected hostname", "csm.example.com:9443", firewall.FirewallConfig{IPv6: true, RestrictedTCP: []int{9443}}, false},
		{"wildcard with public IPv4", "[::]:9443", firewall.FirewallConfig{IPv6: true, TCPIn: []int{9443}, TCP6In: []int{443}}, true},
		{"custom port in passive range", "198.51.100.7:50000", firewall.FirewallConfig{PassiveFTPStart: 49152, PassiveFTPEnd: 65534, RestrictedTCP: []int{50000}}, true},
		{"unknown service port", "198.51.100.7:https", firewall.FirewallConfig{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := webUIExposureConfig(tt.listen)
			tt.fw.Enabled = true
			cfg.Firewall = &tt.fw
			results := Validate(cfg)
			if got := hasResult(results, "warn", "webui.listen"); got != tt.warn {
				t.Fatalf("exposure warning = %v, want %v: %v", got, tt.warn, results)
			}
		})
	}
}
