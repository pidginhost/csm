package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// useSSHDConfig points the lockout guard at a temp sshd_config for the test.
func useSSHDConfig(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	original := sshdConfigPath
	sshdConfigPath = path
	t.Cleanup(func() { sshdConfigPath = original })
}

// useMissingSSHDConfig points the guard at a path with no sshd config at all.
func useMissingSSHDConfig(t *testing.T) {
	t.Helper()
	original := sshdConfigPath
	sshdConfigPath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { sshdConfigPath = original })
}

// The shipped defaults leave 22 out of tcp_in, so a host whose sshd still
// listens there loses SSH on the next firewall apply.
func TestValidateDeepSSHLockout(t *testing.T) {
	t.Run("sshd port missing from tcp_in warns", func(t *testing.T) {
		useSSHDConfig(t, "Port 22\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{80, 443, 9443},
			ConnRateLimit: 200,
		})
		res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in")
		if !ok {
			t.Fatal("expected an SSH lockout warning")
		}
		if !strings.Contains(res.Message, "22") || !strings.Contains(res.Message, "sshd") {
			t.Errorf("warning should name sshd and the port, got %q", res.Message)
		}
	})

	t.Run("sshd port present is silent", func(t *testing.T) {
		useSSHDConfig(t, "Port 2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{2222, 80, 443, 9443},
			ConnRateLimit: 200,
		})
		if res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); ok {
			t.Errorf("no warning expected when the sshd port is allowed, got %q", res.Message)
		}
	})

	// The whole reason the parser had to grow multi-value Port support: a
	// second Port line is a live listener the firewall must still allow.
	t.Run("second port directive is checked too", func(t *testing.T) {
		useSSHDConfig(t, "Port 2222\nPort 22\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{2222, 80, 443, 9443},
			ConnRateLimit: 200,
		})
		res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in")
		if !ok {
			t.Fatal("expected a warning for the second sshd port")
		}
		if !strings.Contains(res.Message, "22") {
			t.Errorf("warning should name the unreachable port, got %q", res.Message)
		}
	})

	t.Run("port from an included drop-in is checked", func(t *testing.T) {
		dir := t.TempDir()
		dropin := filepath.Join(dir, "50-port.conf")
		if err := os.WriteFile(dropin, []byte("Port 2244\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "sshd_config")
		if err := os.WriteFile(path, []byte("Include "+dropin+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		original := sshdConfigPath
		sshdConfigPath = path
		t.Cleanup(func() { sshdConfigPath = original })

		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{22, 80, 443, 9443},
			ConnRateLimit: 200,
		})
		res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in")
		if !ok {
			t.Fatal("expected a warning for the drop-in port")
		}
		if !strings.Contains(res.Message, "2244") {
			t.Errorf("warning should name the drop-in port, got %q", res.Message)
		}
	})

	t.Run("disabled firewall is silent", func(t *testing.T) {
		useSSHDConfig(t, "Port 22\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled: false,
			TCPIn:   []int{80},
		})
		if _, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); ok {
			t.Error("a disabled firewall cannot lock anyone out")
		}
	})

	// No sshd config means no evidence about a listener. Warning off the
	// compiled default would fire on every host that does not run sshd.
	t.Run("missing sshd config is silent", func(t *testing.T) {
		useMissingSSHDConfig(t)
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{80, 443, 9443},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); ok {
			t.Error("without an sshd config there is nothing to warn about")
		}
	})

	// An sshd config with no Port line does listen on 22.
	t.Run("implicit default port is checked", func(t *testing.T) {
		useSSHDConfig(t, "PermitRootLogin no\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{80, 443, 9443},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); !ok {
			t.Error("sshd with no Port line listens on 22")
		}
	})

	t.Run("infra-only sshd port with infra_ips is silent", func(t *testing.T) {
		useSSHDConfig(t, "Port 2087\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{80, 443, 9443},
			RestrictedTCP: []int{2087},
			ConnRateLimit: 200,
		})
		if res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); ok {
			t.Errorf("an infra-only sshd port stays reachable from infra_ips, got %q", res.Message)
		}
	})

	t.Run("infra-only sshd port without infra_ips warns", func(t *testing.T) {
		useSSHDConfig(t, "Port 2087\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{80, 443, 9443},
			RestrictedTCP: []int{2087},
			ConnRateLimit: 200,
		})
		cfg.InfraIPs = nil
		if _, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); !ok {
			t.Error("restricted_tcp without infra_ips leaves sshd reachable from nowhere")
		}
	})

	t.Run("managed IPv6 missing the sshd port warns", func(t *testing.T) {
		useSSHDConfig(t, "Port 2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{2222, 443, 9443},
			TCP6In:        []int{443, 9443},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp6_in"); !ok {
			t.Error("a non-empty tcp6_in overrides tcp_in and must allow the sshd port too")
		}
	})

	t.Run("inherited IPv6 policy is silent", func(t *testing.T) {
		useSSHDConfig(t, "Port 2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{2222, 443, 9443},
			ConnRateLimit: 200,
		})
		if _, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp6_in"); ok {
			t.Error("empty tcp6_in inherits tcp_in, which already allows the port")
		}
	})

	t.Run("quoted port with inline comment is parsed", func(t *testing.T) {
		useSSHDConfig(t, "Port \"2222\" # alternate listener\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{2222, 443, 9443},
			ConnRateLimit: 200,
		})
		if res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); ok {
			t.Errorf("valid quoted port should not fall back to 22, got %q", res.Message)
		}
	})

	t.Run("IPv4-only sshd does not require tcp6_in", func(t *testing.T) {
		useSSHDConfig(t, "AddressFamily inet\nPort 2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{2222, 443, 9443},
			TCP6In:        []int{443, 9443},
			ConnRateLimit: 200,
		})
		if res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp6_in"); ok {
			t.Errorf("IPv4-only sshd has no IPv6 port to allow, got %q", res.Message)
		}
	})

	t.Run("IPv6-only sshd does not require tcp_in", func(t *testing.T) {
		useSSHDConfig(t, "AddressFamily inet6\nPort 2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{443, 9443},
			TCP6In:        []int{2222, 443, 9443},
			ConnRateLimit: 200,
		})
		if res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); ok {
			t.Errorf("IPv6-only sshd has no IPv4 port to allow, got %q", res.Message)
		}
	})

	t.Run("explicit IPv4 listener does not require tcp6_in", func(t *testing.T) {
		useSSHDConfig(t, "ListenAddress 192.0.2.10:2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{2222, 443, 9443},
			TCP6In:        []int{443, 9443},
			ConnRateLimit: 200,
		})
		if res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp6_in"); ok {
			t.Errorf("an IPv4 ListenAddress does not open an IPv6 listener, got %q", res.Message)
		}
	})

	t.Run("explicit IPv6 listener does not require tcp_in", func(t *testing.T) {
		useSSHDConfig(t, "ListenAddress [2001:db8::10]:2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{443, 9443},
			TCP6In:        []int{2222, 443, 9443},
			ConnRateLimit: 200,
		})
		if res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in"); ok {
			t.Errorf("an IPv6 ListenAddress does not open an IPv4 listener, got %q", res.Message)
		}
	})

	t.Run("loopback-only sshd is outside the inbound firewall", func(t *testing.T) {
		useSSHDConfig(t, "ListenAddress 127.0.0.1:2222\nListenAddress [::1]:2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{443, 9443},
			TCP6In:        []int{443, 9443},
			ConnRateLimit: 200,
		})
		for _, result := range ValidateDeepSection(cfg, "firewall") {
			if strings.Contains(result.Message, "sshd") {
				t.Errorf("loopback listeners cannot be blocked by inbound policy, got %q", result.Message)
			}
		}
	})

	t.Run("IPv6 listener checks inherited tcp_in", func(t *testing.T) {
		useSSHDConfig(t, "ListenAddress [2001:db8::10]:2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			IPv6:          true,
			TCPIn:         []int{443, 9443},
			ConnRateLimit: 200,
		})
		res, ok := findResult(ValidateDeepSection(cfg, "firewall"), "warn", "firewall.tcp_in")
		if !ok || !strings.Contains(res.Message, "2222") {
			t.Errorf("inherited IPv6 policy should warn about port 2222, got %+v", res)
		}
	})

	t.Run("one warning names every unreachable port", func(t *testing.T) {
		useSSHDConfig(t, "Port 22\nPort 2222\n")
		cfg := lockoutTestConfig(&firewall.FirewallConfig{
			Enabled:       true,
			TCPIn:         []int{80, 443, 9443},
			ConnRateLimit: 200,
		})
		results := ValidateDeepSection(cfg, "firewall")
		count := 0
		for _, r := range results {
			if r.Level == "warn" && r.Field == "firewall.tcp_in" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("got %d tcp_in warnings, want one covering both ports", count)
		}
		res, _ := findResult(results, "warn", "firewall.tcp_in")
		if !strings.Contains(res.Message, "22") || !strings.Contains(res.Message, "2222") {
			t.Errorf("warning should name both ports, got %q", res.Message)
		}
	})
}

// Validate stays free of host state: reading sshd_config belongs to the deep
// pass, so the same config validates identically on any machine.
func TestValidateDoesNotReadSSHDConfig(t *testing.T) {
	useSSHDConfig(t, "Port 22\n")
	cfg := lockoutTestConfig(&firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{80, 443, 9443},
		ConnRateLimit: 200,
	})
	for _, r := range Validate(cfg) {
		if strings.Contains(r.Message, "sshd") {
			t.Errorf("Validate must not probe the host, got %q", r.Message)
		}
	}
}

func TestValidateDeepIncludesSSHLockout(t *testing.T) {
	useSSHDConfig(t, "Port 22\n")
	cfg := lockoutTestConfig(&firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{80, 443, 9443},
		ConnRateLimit: 200,
	})
	cfg.StatePath = t.TempDir()
	if _, ok := findResult(ValidateDeep(cfg), "warn", "firewall.tcp_in"); !ok {
		t.Error("ValidateDeep should carry the SSH lockout warning")
	}
}
