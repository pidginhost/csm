package config

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// lockoutTestConfig returns a config that passes the unrelated validation
// gates, so a test only sees the firewall results it is about.
func lockoutTestConfig(fw *firewall.FirewallConfig) *Config {
	cfg := &Config{Hostname: "host.example.com", Firewall: fw}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"admin@example.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.MaxPerHour = 10
	cfg.WebUI.Listen = "0.0.0.0:9443"
	cfg.InfraIPs = []string{"198.51.100.10"}
	return cfg
}

func findResult(results []ValidationResult, level, field string) (ValidationResult, bool) {
	for _, r := range results {
		if r.Level == level && r.Field == field {
			return r, true
		}
	}
	return ValidationResult{}, false
}

// E1: the web UI already warns about this before a save, but an operator
// editing csm.yaml by hand or running `csm doctor` got nothing.
func TestValidateFirewallLockoutWebUIPort(t *testing.T) {
	t.Run("port missing from tcp_in warns", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{22, 80, 443},
			ConnRateLimit: 200,
		})
		res, ok := findResult(Validate(cfg), "warn", "firewall.tcp_in")
		if !ok {
			t.Fatalf("expected a lockout warning for the web UI port; results=%v", Validate(cfg))
		}
		if !strings.Contains(res.Message, "9443") {
			t.Errorf("warning should name the unreachable port, got %q", res.Message)
		}
	})

	t.Run("port present is silent", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{22, 443, 9443},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp_in"); ok {
			t.Error("no warning expected when the web UI port is allowed inbound")
		}
	})

	t.Run("disabled firewall is silent", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled: false,
			TCPIn:   []int{80},
		})
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp_in"); ok {
			t.Error("a disabled firewall cannot lock anyone out")
		}
	})
}

// tcp6_in is only enforced when the operator actually manages v6 inbound;
// an empty list means "not managed", not "everything denied".
func TestValidateFirewallLockoutIPv6Port(t *testing.T) {
	t.Run("managed v6 missing the port warns", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{9443},
			TCP6In:        []int{22, 443},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp6_in"); !ok {
			t.Error("expected a v6 lockout warning")
		}
	})

	t.Run("unmanaged v6 is silent", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{9443},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp6_in"); ok {
			t.Error("empty tcp6_in means v6 inbound is unmanaged, not denied")
		}
	})
}

// restricted_tcp ports are reachable only from infra_ips. With no infra_ips
// they are reachable from nowhere, which silently bricks the panel ports.
func TestValidateFirewallRestrictedWithoutInfra(t *testing.T) {
	t.Run("restricted ports without infra_ips warn", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{9443},
			RestrictedTCP: []int{2087, 9443},
			ConnRateLimit: 200,
		})
		cfg.InfraIPs = nil
		res, ok := findResult(Validate(cfg), "warn", "firewall.restricted_tcp")
		if !ok {
			t.Fatal("expected a warning that restricted ports are reachable from nowhere")
		}
		if !strings.Contains(res.Message, "infra_ips") {
			t.Errorf("warning should point at infra_ips, got %q", res.Message)
		}
	})

	t.Run("restricted ports with infra_ips are fine", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{9443},
			RestrictedTCP: []int{2087},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(Validate(cfg), "warn", "firewall.restricted_tcp"); ok {
			t.Error("infra_ips is set, so restricted ports are reachable")
		}
	})

	t.Run("firewall-section infra_ips also counts", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{9443},
			RestrictedTCP: []int{2087},
			InfraIPs:      []string{"198.51.100.11"},
			ConnRateLimit: 200,
		})
		cfg.InfraIPs = nil
		if _, ok := findResult(Validate(cfg), "warn", "firewall.restricted_tcp"); ok {
			t.Error("infra_ips under the firewall section is equally valid")
		}
	})
}

// A restricted web UI port with no infra_ips is the sharpest version of the
// trap: the port is in tcp_in, so the plain port check stays quiet, yet the
// restriction refuses everyone. Restricting it *with* infra_ips set is a
// deliberate hardening posture and must stay silent.
func TestValidateFirewallWebUIPortRestricted(t *testing.T) {
	fw := func() *firewall.FirewallConfig {
		return &firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{22, 9443},
			RestrictedTCP: []int{9443},
			ConnRateLimit: 200,
		}
	}

	cfg := lockoutTestConfig(fw())
	cfg.InfraIPs = nil
	res, ok := findResult(Validate(cfg), "warn", "firewall.restricted_tcp")
	if !ok {
		t.Fatal("expected a warning that the web UI port is reachable from nowhere")
	}
	if !strings.Contains(res.Message, "9443") {
		t.Errorf("warning should name the web UI port, got %q", res.Message)
	}

	if _, ok := findResult(Validate(lockoutTestConfig(fw())), "warn", "firewall.restricted_tcp"); ok {
		t.Error("restricting the web UI port to infra_ips is deliberate hardening, not a lockout")
	}
}
