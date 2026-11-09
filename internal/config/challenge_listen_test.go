package config

import (
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/netutil"
)

func pinChallengeHost(t *testing.T, addrs ...string) {
	t.Helper()
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	}))
}

func TestChallengeSocketPath(t *testing.T) {
	for _, tc := range []struct {
		in   string
		path string
		ok   bool
	}{
		{"unix:/run/csm/challenge.sock", "/run/csm/challenge.sock", true},
		{" UNIX:/run/x.sock ", "/run/x.sock", true},
		{"unix:", "", true},
		{"unix:run/c.sock", "run/c.sock", true},
		{"127.0.0.1", "", false},
		{"0.0.0.0", "", false},
		{"", "", false},
		{"[::1]", "", false},
		{"unixhost", "", false},
	} {
		path, ok := ChallengeSocketPath(tc.in)
		if path != tc.path || ok != tc.ok {
			t.Errorf("ChallengeSocketPath(%q) = (%q, %v), want (%q, %v)", tc.in, path, ok, tc.path, tc.ok)
		}
	}
}

func TestChallengeLocalTrustErrorNamesEntryAndFix(t *testing.T) {
	pinChallengeHost(t, "203.0.113.10")
	err := ChallengeLocalTrustError([]string{"127.0.0.1"})
	if err == nil {
		t.Fatal("loopback entry: want error")
	}
	for _, want := range []string{`"127.0.0.1"`, "127.0.0.0/8", ChallengeSocketExample, "challenge.listen_group", "direct mode"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if err := ChallengeLocalTrustError([]string{"203.0.113.0/24"}); err == nil || !strings.Contains(err.Error(), "203.0.113.10") {
		t.Errorf("host range: got %v, want error naming 203.0.113.10", err)
	}
	if err := ChallengeLocalTrustError([]string{"198.51.100.7"}); err != nil {
		t.Errorf("remote proxy: got %v, want nil", err)
	}
}

func TestValidateChallengeSocketNeedsAbsolutePath(t *testing.T) {
	for _, addr := range []string{"unix:", "unix:run/c.sock"} {
		cfg := baseValidationConfig()
		cfg.Challenge.Enabled = true
		cfg.Challenge.ListenPort = 8439
		cfg.Challenge.ListenAddr = addr
		cfg.Challenge.ListenGroup = "nginx"
		if !hasResult(Validate(cfg), "error", "challenge.listen_addr") {
			t.Errorf("%q: want error on challenge.listen_addr", addr)
		}
	}
}

func TestValidateChallengeSocketNeedsGroup(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.ListenAddr = ChallengeSocketExample
	if !hasResult(Validate(cfg), "error", "challenge.listen_group") {
		t.Fatal("empty group: want error on challenge.listen_group")
	}
	cfg.Challenge.ListenGroup = "nginx"
	results := Validate(cfg)
	if hasResult(results, "error", "challenge.listen_group") || hasResult(results, "error", "challenge.listen_addr") {
		t.Fatalf("valid socket config rejected: %v", results)
	}
}

func TestValidateWarnsHostLocalTrustedProxy(t *testing.T) {
	pinChallengeHost(t, "203.0.113.10")
	cfg := baseValidationConfig()
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.TrustedProxies = []string{"127.0.0.1"}
	results := Validate(cfg)
	if hasResult(results, "error", "challenge.trusted_proxies") {
		t.Fatal("host-local trust must never be a validation error: it would stop the daemon")
	}
	i := slices.IndexFunc(results, func(r ValidationResult) bool {
		return r.Level == "warn" && r.Field == "challenge.trusted_proxies"
	})
	if i < 0 {
		t.Fatalf("want warn on challenge.trusted_proxies, got %v", results)
	}
	if want := ChallengeLocalTrustError(cfg.Challenge.TrustedProxies).Error(); results[i].Message != want {
		t.Errorf("message = %q, want %q", results[i].Message, want)
	}
}

func TestValidateIgnoresChallengeSocketWhenDisabled(t *testing.T) {
	pinChallengeHost(t, "203.0.113.10")
	cfg := baseValidationConfig()
	cfg.Challenge.Enabled = false
	cfg.Challenge.ListenAddr = "unix:"
	cfg.Challenge.TrustedProxies = []string{"127.0.0.1"}
	for _, r := range Validate(cfg) {
		if strings.HasPrefix(r.Field, "challenge.") && r.Level != "ok" {
			t.Errorf("disabled challenge reported %s %s: %s", r.Level, r.Field, r.Message)
		}
	}
}

func TestEffectiveFirewallSkipsSocketListener(t *testing.T) {
	cfg := &Config{Firewall: &firewall.FirewallConfig{Enabled: true, RestrictedTCP: []int{8439}}}
	cfg.Challenge.Enabled = true
	cfg.Challenge.PortGate.Enabled = true
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.ListenAddr = ChallengeSocketExample
	got := EffectiveFirewallConfig(cfg)
	if slices.Contains(got.TCPIn, 8439) {
		t.Errorf("socket listener opened TCP 8439: %v", got.TCPIn)
	}
	if !slices.Contains(got.RestrictedTCP, 8439) {
		t.Errorf("socket listener removed 8439 from RestrictedTCP: %v", got.RestrictedTCP)
	}
	cfg.Challenge.ListenAddr = "0.0.0.0"
	if got := EffectiveFirewallConfig(cfg); !slices.Contains(got.TCPIn, 8439) {
		t.Fatalf("control: public listener should open 8439, got %v", got.TCPIn)
	}
}
