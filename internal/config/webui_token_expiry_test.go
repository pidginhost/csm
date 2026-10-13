package config

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWebUICredentialExpiryWarnings(t *testing.T) {
	// Missing dates must refuse authentication without stopping monitoring.
	for _, field := range []string{"auth_token", "metrics_token"} {
		cfg, err := LoadBytes(fmt.Appendf(nil, "webui:\n  %s: %q\n", field, rand.Text()))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range Validate(cfg) {
			if r.Level == "warn" && (r.Field == "webui."+field+"_issued_at" || strings.HasPrefix(r.Field, "webui.tokens[")) && strings.Contains(r.Message, "issued_at") {
				found = true
			}
		}
		if !found {
			t.Errorf("undated %s was not reported", field)
		}
	}
}

func TestBrowserSessionSevenDayMaximum(t *testing.T) {
	for _, tc := range []struct {
		duration string
		allowed  bool
	}{
		{"168h", true}, {"168h1s", false}, {"720h", false},
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
