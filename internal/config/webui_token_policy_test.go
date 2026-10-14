package config

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestWebUICredentialExplicitExpiry(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	day := 24 * time.Hour
	for _, tc := range []struct {
		name, issued, expires string
		current               bool
	}{
		{"default inside seven days", at(-6 * day), "", true},
		{"default after seven days", at(-7 * day), "", false},
		{"explicit year", at(-30 * day), at(335 * day), true},
		{"explicit last second", at(-30 * day), at(time.Second), true},
		{"explicit exact deadline", at(-30 * day), at(0), false},
		{"explicit shorter than default", at(-2 * day), at(-day), false},
		{"expiry before issue", at(-time.Hour), at(-2 * time.Hour), false},
		{"malformed expiry", at(-day), "next year", false},
		{"undated with expiry", "", at(day), false},
		{"future issue with expiry", at(time.Hour), at(30 * day), false},
	} {
		if got := WebUITokenCurrent(tc.issued, tc.expires, now); got != tc.current {
			t.Errorf("%s: current = %v, want %v", tc.name, got, tc.current)
		}
	}
}

// longToken passes the length check, so only expiry warnings remain.
func longToken() string { return rand.Text() + rand.Text() }

func webUIWarnings(t *testing.T, yamlText string) []ValidationResult {
	t.Helper()
	cfg, err := LoadBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var out []ValidationResult
	for _, r := range Validate(cfg) {
		if r.Level == "warn" && strings.HasPrefix(r.Field, "webui.") {
			out = append(out, r)
		}
	}
	return out
}

func TestWebUICredentialExpiryWarningsHonourExpiresAt(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	future := now.Add(300 * 24 * time.Hour).Format(time.RFC3339)
	for _, tc := range []struct {
		name, yaml, warnField string
	}{
		{"token", fmt.Sprintf("webui:\n  tokens:\n    - name: a\n      token: %q\n      scope: admin\n      issued_at: %q\n      expires_at: %q\n", longToken(), old, future), ""},
		{"token malformed", fmt.Sprintf("webui:\n  tokens:\n    - name: a\n      token: %q\n      scope: admin\n      issued_at: %q\n      expires_at: soon\n", longToken(), old), "webui.tokens[0].expires_at"},
		{"legacy", fmt.Sprintf("webui:\n  auth_token: %q\n  auth_token_issued_at: %q\n  auth_token_expires_at: %q\n", longToken(), old, future), ""},
		{"metrics", fmt.Sprintf("webui:\n  metrics_token: %q\n  metrics_token_issued_at: %q\n  metrics_token_expires_at: %q\n", longToken(), old, future), ""},
		{"metrics malformed", fmt.Sprintf("webui:\n  metrics_token: %q\n  metrics_token_issued_at: %q\n  metrics_token_expires_at: soon\n", longToken(), old), "webui.metrics_token_expires_at"},
	} {
		warnings := webUIWarnings(t, tc.yaml)
		if tc.warnField == "" {
			for _, w := range warnings {
				t.Errorf("%s: unexpected warning %s: %s", tc.name, w.Field, w.Message)
			}
			continue
		}
		found := false
		for _, w := range warnings {
			found = found || w.Field == tc.warnField
		}
		if !found {
			t.Errorf("%s: no warning on %s, got %v", tc.name, tc.warnField, warnings)
		}
	}
}

func TestLegacyTokenKeepsExpiry(t *testing.T) {
	expires := time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	cfg, err := LoadBytes(fmt.Appendf(nil, "webui:\n  auth_token: %q\n  auth_token_issued_at: %q\n  auth_token_expires_at: %q\n",
		longToken(), time.Now().UTC().Format(time.RFC3339), expires))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WebUI.Tokens) != 1 || cfg.WebUI.Tokens[0].ExpiresAt != expires {
		t.Fatal("legacy token lost its expiry")
	}
}

func TestWebUITokenScopeAndSourceValidation(t *testing.T) {
	issued := time.Now().UTC().Format(time.RFC3339)
	load := func(scope, extra string) error {
		_, err := LoadBytes(fmt.Appendf(nil, "webui:\n  tokens:\n    - name: a\n      token: %q\n      scope: %s\n      issued_at: %q\n%s",
			rand.Text(), scope, issued, extra))
		return err
	}
	for _, tc := range []struct {
		name, scope, extra string
		ok                 bool
	}{
		{"unban scope", "unban", "", true},
		{"unknown scope", "unblock", "", false},
		{"sources", "unban", "      allowed_ips: [\"203.0.113.10\", \"198.51.100.0/24\", \"2001:db8::/32\"]\n", true},
		{"bad address", "admin", "      allowed_ips: [\"not-an-ip\"]\n", false},
		{"bad prefix", "admin", "      allowed_ips: [\"203.0.113.0/33\"]\n", false},
		{"empty entry", "read", "      allowed_ips: [\"\"]\n", false},
		{"zoned address", "admin", "      allowed_ips: [\"2001:db8::1%eth0\"]\n", false},
		{"zoned mapped address", "admin", "      allowed_ips: [\"::ffff:192.0.2.1%eth0\"]\n", false},
		{"zoned prefix", "admin", "      allowed_ips: [\"2001:db8::1%eth0/128\"]\n", false},
	} {
		if err := load(tc.scope, tc.extra); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestWebUITokenSourceMatching(t *testing.T) {
	for _, tc := range []struct {
		name, source, allowed, denied string
	}{
		{"IPv4 address", "192.0.2.10", "::ffff:192.0.2.10", "192.0.2.11"},
		{"mapped address", "::ffff:192.0.2.10", "192.0.2.10", "192.0.2.11"},
		{"IPv4 prefix host bits", "192.0.2.129/25", "::ffff:192.0.2.255", "192.0.2.127"},
		{"mapped prefix host bits", "::ffff:192.0.2.129/121", "192.0.2.255", "192.0.2.127"},
		{"mapped host prefix", "::ffff:192.0.2.10/128", "::ffff:192.0.2.10", "192.0.2.11"},
		{"IPv6 prefix host bits", "2001:db8:1::1234/48", "2001:db8:1::ffff%eth0", "2001:db8:2::1"},
		{"IPv6 address", "2001:db8::1", "2001:db8::1%eth0", "2001:db8::2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes(fmt.Appendf(nil, "webui:\n  tokens:\n    - name: panel\n      token: %q\n      scope: unban\n      issued_at: %q\n      allowed_ips: [%q]\n",
				longToken(), time.Now().UTC().Format(time.RFC3339), tc.source))
			if err != nil {
				t.Fatal(err)
			}
			tok := cfg.WebUI.Tokens[0]
			if !tok.AcceptsFrom(netip.MustParseAddr(tc.allowed)) {
				t.Errorf("source %s rejected peer %s", tc.source, tc.allowed)
			}
			if tok.AcceptsFrom(netip.MustParseAddr(tc.denied)) {
				t.Errorf("source %s admitted peer %s", tc.source, tc.denied)
			}
			if tok.AcceptsFrom(netip.Addr{}) {
				t.Error("restricted token admitted an invalid peer")
			}
		})
	}
}
