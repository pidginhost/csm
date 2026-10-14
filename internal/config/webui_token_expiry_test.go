package config

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebUICredentialWithoutDatesStaysValid(t *testing.T) {
	// Configurations written before credential dates existed keep working.
	for _, yamlText := range []string{
		fmt.Sprintf("webui:\n  auth_token: %q\n", longToken()),
		fmt.Sprintf("webui:\n  metrics_token: %q\n", longToken()),
		fmt.Sprintf("webui:\n  tokens:\n    - name: a\n      token: %q\n      scope: admin\n", longToken()),
		fmt.Sprintf("webui:\n  auth_token: %q\n  auth_token_issued_at: %q\n", longToken(), time.Now().UTC().Add(-365*24*time.Hour).Format(time.RFC3339)),
	} {
		for _, w := range webUIWarnings(t, yamlText) {
			t.Errorf("unexpected warning %s: %s", w.Field, w.Message)
		}
	}
}

func TestWebUICredentialBadIssueTimeWarns(t *testing.T) {
	for _, issued := range []string{"yesterday", time.Now().UTC().Add(time.Hour).Format(time.RFC3339)} {
		cfg, err := LoadBytes(fmt.Appendf(nil, "webui:\n  auth_token: %q\n  auth_token_issued_at: %q\n", rand.Text(), issued))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range Validate(cfg) {
			if r.Level == "warn" && strings.HasPrefix(r.Field, "webui.tokens[") && strings.Contains(r.Message, "issued_at") {
				found = true
			}
		}
		if !found {
			t.Errorf("issue time %q was not reported", issued)
		}
	}
}

func TestBrowserSessionLifetimeMaximum(t *testing.T) {
	for _, tc := range []struct {
		duration string
		allowed  bool
	}{
		{"168h", true}, {"720h", true}, {"720h1s", false},
	} {
		cfg := &Config{}
		cfg.WebUI.SessionLifetime = tc.duration
		_, _, err := cfg.BrowserSessionDurations()
		if (err == nil) != tc.allowed {
			t.Errorf("lifetime %s accepted=%v, want %v", tc.duration, err == nil, tc.allowed)
		}
	}
}

func TestLegacyTokenKeepsIssueTimeAcrossLoads(t *testing.T) {
	issued := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	data := fmt.Appendf(nil, "webui:\n  auth_token: %q\n  auth_token_issued_at: %q\n", rand.Text(), issued)
	for range 2 {
		cfg, err := LoadBytes(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.WebUI.Tokens) != 1 {
			t.Fatal("legacy token not loaded")
		}
		if cfg.WebUI.Tokens[0].IssuedAt != issued {
			t.Fatal("legacy token lost its fixed issue time")
		}
	}
}

func TestWebUICredentialDateInputsFailClosed(t *testing.T) {
	for _, kind := range []string{"scoped", "legacy", "metrics"} {
		for _, field := range []string{"issued_at", "expires_at"} {
			for _, value := range []string{`"not-a-date"`, `" "`, "false", "0", "[]", "{}"} {
				t.Run(kind+"/"+field+"/"+value, func(t *testing.T) {
					key, indent := field, "      "
					body := fmt.Sprintf("webui:\n  tokens:\n    - name: operator\n      scope: admin\n      token: %q\n", longToken())
					if kind != "scoped" {
						prefix := "auth_token"
						if kind == "metrics" {
							prefix = "metrics_token"
						}
						key, indent = prefix+"_"+field, "  "
						body = fmt.Sprintf("webui:\n  %s: %q\n", prefix, longToken())
					}
					data := []byte(body + indent + key + ": " + value + "\n")
					dir := t.TempDir()
					if err := os.WriteFile(filepath.Join(dir, "token.yaml"), data, 0600); err != nil {
						t.Fatal(err)
					}
					for _, dropIn := range []bool{false, true} {
						cfg, err := LoadBytes(data)
						if dropIn {
							cfg, err = LoadBytesWithDir(nil, dir)
						}
						if err != nil {
							continue // Invalid YAML types may reject the configuration outright.
						}
						issued, expires := cfg.WebUI.MetricsTokenIssuedAt, cfg.WebUI.MetricsTokenExpiresAt
						warningField := "webui.metrics_token_" + field
						if kind != "metrics" {
							if len(cfg.WebUI.Tokens) != 1 {
								t.Fatal("credential missing after loading")
							}
							issued, expires = cfg.WebUI.Tokens[0].IssuedAt, cfg.WebUI.Tokens[0].ExpiresAt
							warningField = "webui.tokens[0]." + field
						}
						if WebUITokenCurrent(issued, expires, time.Now()) {
							t.Fatalf("malformed date authenticated (drop-in=%v)", dropIn)
						}
						found := false
						for _, warning := range Validate(cfg) {
							if warning.Level == "warn" && warning.Field == warningField && strings.Contains(warning.Message, "credential disabled") {
								found = true
							}
						}
						if !found {
							t.Fatalf("missing disabled credential warning (drop-in=%v)", dropIn)
						}
					}
				})
			}
		}
	}
}
