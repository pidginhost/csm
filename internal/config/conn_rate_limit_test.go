package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// conn_rate_limit had three different meanings for 0. The engine skips
// the connection meter, the web UI documents "0 disables", and validation
// rejected it outright. An operator following the web UI's own help text got
// a config the validator called invalid.
func TestConnRateLimitZeroIsDisabledNotInvalid(t *testing.T) {
	cfg := lockoutTestConfig(&firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{9443},
		ConnRateLimit: 0,
		ConnLimit:     400,
	})

	results := Validate(cfg)
	if _, ok := findResult(results, "error", "firewall.conn_rate_limit"); ok {
		t.Errorf("explicit 0 must be accepted as disabled; results=%v", results)
	}

	// The operator still needs to see that a protection is off, so the
	// firewall summary has to say so rather than omit the field.
	summary, ok := findResult(results, "ok", "firewall")
	if !ok {
		t.Fatalf("expected a firewall summary result; results=%v", results)
	}
	if !strings.Contains(summary.Message, "conn_rate_limit=disabled") {
		t.Errorf("summary should report the meter as disabled, got %q", summary.Message)
	}
}

func TestConnRateLimitNegativeIsRejected(t *testing.T) {
	cfg := lockoutTestConfig(&firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{9443},
		ConnRateLimit: -5,
	})

	res, ok := findResult(Validate(cfg), "error", "firewall.conn_rate_limit")
	if !ok {
		t.Fatal("a negative rate limit is not a disable switch, it is a typo")
	}
	if !strings.Contains(res.Message, "0") {
		t.Errorf("error should tell the operator how to disable it, got %q", res.Message)
	}
}

// An omitted key must keep getting the shipped default rather than silently
// disabling the meter, which is what makes explicit 0 unambiguous later.
func TestConnRateLimitOmittedKeepsDefault(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
hostname: host.example.com
alerts:
  email:
    enabled: true
    to: ["admin@example.com"]
    smtp: "localhost:25"
    from: "csm@example.com"
firewall:
  enabled: true
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if got, want := cfg.Firewall.ConnRateLimit, firewall.DefaultConfig().ConnRateLimit; got != want {
		t.Errorf("omitted conn_rate_limit = %d, want shipped default %d", got, want)
	}
}

func TestConnRateLimitExplicitZeroSurvivesLoad(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
hostname: host.example.com
alerts:
  email:
    enabled: true
    to: ["admin@example.com"]
    smtp: "localhost:25"
    from: "csm@example.com"
firewall:
  enabled: true
  conn_rate_limit: 0
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Firewall.ConnRateLimit != 0 {
		t.Fatalf("explicit 0 was overwritten with %d; presence tracking is what makes 0 mean disabled", cfg.Firewall.ConnRateLimit)
	}
	if _, ok := findResult(Validate(cfg), "error", "firewall.conn_rate_limit"); ok {
		t.Error("a loaded config with an explicit 0 must validate")
	}
}

func TestConnRateLimitNullKeepsDefault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "implicit", value: ""},
		{name: "null", value: "null"},
		{name: "tilde", value: "~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte("firewall:\n  enabled: true\n  conn_rate_limit: " + tc.value + "\n"))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			if got, want := cfg.Firewall.ConnRateLimit, firewall.DefaultConfig().ConnRateLimit; got != want {
				t.Errorf("null conn_rate_limit = %d, want shipped default %d", got, want)
			}
		})
	}
}

// Null-means-unset is a property of the presence tracking itself, not a
// special case for one key. Every field whose zero value is a real setting
// depends on it: `x: null` keeps the shipped default, while an explicit zero,
// empty list, or false stays the operator's choice.
func TestFirewallNullKeysKeepDefaultsAcrossFields(t *testing.T) {
	def := firewall.DefaultConfig()

	t.Run("null keeps defaults", func(t *testing.T) {
		cfg, err := LoadBytes([]byte("firewall:\n  enabled: true\n  conn_limit: null\n  restricted_tcp: null\n"))
		if err != nil {
			t.Fatalf("LoadBytes: %v", err)
		}
		if cfg.Firewall.ConnLimit != def.ConnLimit {
			t.Errorf("null conn_limit = %d, want shipped default %d", cfg.Firewall.ConnLimit, def.ConnLimit)
		}
		if !samePortList(cfg.Firewall.RestrictedTCP, def.RestrictedTCP) {
			t.Errorf("null restricted_tcp = %v, want shipped default %v", cfg.Firewall.RestrictedTCP, def.RestrictedTCP)
		}
	})

	t.Run("aliased null keeps defaults", func(t *testing.T) {
		cfg, err := LoadBytes([]byte("firewall:\n  enabled: true\n  conn_rate_limit: &unset null\n  conn_limit: *unset\n  restricted_tcp: *unset\n"))
		if err != nil {
			t.Fatalf("LoadBytes: %v", err)
		}
		if cfg.Firewall.ConnRateLimit != def.ConnRateLimit {
			t.Errorf("aliased null conn_rate_limit = %d, want shipped default %d", cfg.Firewall.ConnRateLimit, def.ConnRateLimit)
		}
		if cfg.Firewall.ConnLimit != def.ConnLimit {
			t.Errorf("aliased null conn_limit = %d, want shipped default %d", cfg.Firewall.ConnLimit, def.ConnLimit)
		}
		if !samePortList(cfg.Firewall.RestrictedTCP, def.RestrictedTCP) {
			t.Errorf("aliased null restricted_tcp = %v, want shipped default %v", cfg.Firewall.RestrictedTCP, def.RestrictedTCP)
		}
	})

	t.Run("explicit zero values are kept", func(t *testing.T) {
		cfg, err := LoadBytes([]byte("firewall:\n  enabled: true\n  conn_limit: 0\n  restricted_tcp: []\n"))
		if err != nil {
			t.Fatalf("LoadBytes: %v", err)
		}
		if cfg.Firewall.ConnLimit != 0 {
			t.Errorf("explicit conn_limit 0 was overwritten with %d", cfg.Firewall.ConnLimit)
		}
		if len(cfg.Firewall.RestrictedTCP) != 0 {
			t.Errorf("explicit empty restricted_tcp was overwritten with %v", cfg.Firewall.RestrictedTCP)
		}
	})
}

func samePortList(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestConnRateLimitExplicitZeroInDropInSurvivesLoad(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confDir := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("firewall:\n  enabled: true\n  conn_rate_limit: 50\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "10-firewall.yaml"), []byte("firewall:\n  conn_rate_limit: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithDir(main, confDir)
	if err != nil {
		t.Fatalf("LoadWithDir: %v", err)
	}
	if cfg.Firewall.ConnRateLimit != 0 {
		t.Fatalf("explicit 0 in partial drop-in was overwritten with %d", cfg.Firewall.ConnRateLimit)
	}
}

func TestConnRateLimitNullDropInKeepsDefault(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confDir := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("firewall:\n  enabled: true\n  conn_rate_limit: 50\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "10-firewall.yaml"), []byte("firewall:\n  conn_rate_limit: null\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithDir(main, confDir)
	if err != nil {
		t.Fatalf("LoadWithDir: %v", err)
	}
	if got, want := cfg.Firewall.ConnRateLimit, firewall.DefaultConfig().ConnRateLimit; got != want {
		t.Errorf("null drop-in conn_rate_limit = %d, want shipped default %d", got, want)
	}
}
