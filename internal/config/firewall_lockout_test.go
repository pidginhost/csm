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
	cfg.WebUI.Enabled = true
	cfg.WebUI.Listen = "0.0.0.0:9443"
	cfg.WebUI.Tokens = []WebUIToken{{Name: "operator", Token: "test-secret", Scope: "admin"}}
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

// Hand-edited config and csm doctor must get the same warning as a Web UI save.
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

	t.Run("disabled web UI is silent", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{22, 443},
			ConnRateLimit: 200,
		})
		cfg.WebUI.Enabled = false
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp_in"); ok {
			t.Error("a disabled web UI cannot be locked out")
		}
	})

	// The shipped defaults keep the web UI port out of tcp_in and name it in
	// restricted_tcp, which is the deliberate infra-only deployment. Infra IPs
	// are accepted on every port, so the operator is not locked out.
	t.Run("infra-only port with infra_ips is silent", func(t *testing.T) {
		fw := firewall.DefaultConfig()
		fw.Enabled = true
		if containsPort(fw.TCPIn, 9443) || !containsPort(fw.RestrictedTCP, 9443) {
			t.Fatal("shipped firewall policy no longer exercises infra-only web UI validation")
		}
		cfg := lockoutTestConfig(fw)
		if res, ok := findResult(Validate(cfg), "warn", "firewall.tcp_in"); ok {
			t.Errorf("infra-only web UI port is reachable from infra_ips, got warning %q", res.Message)
		}
	})

	t.Run("infra-only port without infra_ips warns", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{22, 80, 443},
			RestrictedTCP: []int{9443},
			ConnRateLimit: 200,
		})
		cfg.InfraIPs = nil
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp_in"); !ok {
			t.Error("restricted_tcp without infra_ips leaves the web UI reachable from nowhere")
		}
	})

	t.Run("blank infra_ips still warn", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{22, 80, 443},
			RestrictedTCP: []int{9443},
			InfraIPs:      []string{"\t"},
			ConnRateLimit: 200,
		})
		cfg.InfraIPs = []string{"", " "}
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp_in"); !ok {
			t.Error("blank infra_ips do not create an infra accept rule")
		}
	})

	t.Run("port absent from both lists still warns", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{22, 80, 443},
			RestrictedTCP: []int{2087},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp_in"); !ok {
			t.Error("a port in neither list is an oversight worth warning about")
		}
	})
}

// A non-empty tcp6_in overrides tcp_in for IPv6. An empty list inherits the
// IPv4 list, so the IPv4 check already covers the effective policy.
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

	t.Run("inherited v6 policy is silent", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{9443},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(Validate(cfg), "warn", "firewall.tcp6_in"); ok {
			t.Error("empty tcp6_in inherits tcp_in, which already allows the port")
		}
	})
}

// restricted_tcp removes matching public accepts. With no infra_ips, an
// overlapping allowed port becomes unreachable and can silently brick a panel.
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
			TCPIn:         []int{2087, 9443},
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
			TCPIn:         []int{2087, 9443},
			RestrictedTCP: []int{2087},
			InfraIPs:      []string{"198.51.100.11"},
			ConnRateLimit: 200,
		})
		cfg.InfraIPs = nil
		if _, ok := findResult(Validate(cfg), "warn", "firewall.restricted_tcp"); ok {
			t.Error("infra_ips under the firewall section is equally valid")
		}
	})

	t.Run("restricted port absent from allow lists is silent", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{9443},
			RestrictedTCP: []int{2087},
			ConnRateLimit: 200,
		})
		cfg.InfraIPs = nil
		if _, ok := findResult(Validate(cfg), "warn", "firewall.restricted_tcp"); ok {
			t.Error("restricted_tcp only filters tcp_in; it does not make an absent port reachable")
		}
	})

	t.Run("IPv6-only allowed port still warns", func(t *testing.T) {
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{9443},
			TCP6In:        []int{2087, 9443},
			RestrictedTCP: []int{2087},
			ConnRateLimit: 200,
		})
		cfg.InfraIPs = nil
		if _, ok := findResult(Validate(cfg), "warn", "firewall.restricted_tcp"); !ok {
			t.Error("restricted_tcp filters the effective IPv6 allow list too")
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
