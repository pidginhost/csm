package config

import (
	"crypto/rand"
	"fmt"
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
