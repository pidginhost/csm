package config

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// E3: conn_rate_limit had three different meanings for 0. The engine skips
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
