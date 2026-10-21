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

func TestValidateDoesNotWarnWhenWebUIExposureIsLimited(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"ipv4 loopback": func(c *Config) { c.WebUI.Listen = "127.0.0.1:9443" },
		"ipv6 loopback": func(c *Config) { c.WebUI.Listen = "[::1]:9443" },
		"localhost":     func(c *Config) { c.WebUI.Listen = "localhost:9443" },
		"csm firewall":  func(c *Config) { c.Firewall = &firewall.FirewallConfig{Enabled: true} },
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
