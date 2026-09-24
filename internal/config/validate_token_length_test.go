package config

import (
	"strings"
	"testing"
)

// A short Web UI or metrics token can be guessed. It is reported as a
// warning, which startup, `csm validate` and `csm doctor` print, and never
// as an error: an existing short token must not stop the daemon.
func TestValidateWarnsAboutShortTokens(t *testing.T) {
	short := strings.Repeat("a", minWebUITokenLength-1)
	long := strings.Repeat("b", 64)
	cases := []struct {
		field string
		set   func(*Config)
	}{
		{"webui.tokens", func(c *Config) {
			c.WebUI.Enabled = true
			c.WebUI.Tokens = []WebUIToken{{Name: "ops", Token: short, Scope: "admin"}}
		}},
		{"webui.auth_token", func(c *Config) {
			c.WebUI.Enabled = true
			c.WebUI.AuthToken = short
			c.WebUI.Tokens = nil
		}},
		{"webui.metrics_token", func(c *Config) { c.WebUI.MetricsToken = short }},
	}
	for _, tc := range cases {
		cfg := baseValidationConfig()
		tc.set(cfg)
		results := Validate(cfg)
		if !hasResult(results, "warn", tc.field) {
			t.Errorf("%s: no warning for a %d-character token", tc.field, len(short))
		}
		for _, r := range results {
			if r.Level == "error" && strings.HasPrefix(r.Field, tc.field) {
				t.Errorf("%s: short token is an error (%s); it must only warn", tc.field, r.Message)
			}
			if strings.Contains(r.Message, short) {
				t.Errorf("%s: the token value appears in a result", tc.field)
			}
		}
	}

	cfg := baseValidationConfig()
	cfg.WebUI.Enabled = true
	cfg.WebUI.Tokens = []WebUIToken{{Name: "ops", Token: long, Scope: "admin"}}
	cfg.WebUI.MetricsToken = strings.Repeat("c", 64)
	for _, field := range []string{"webui.tokens", "webui.metrics_token"} {
		if hasResult(Validate(cfg), "warn", field) {
			t.Errorf("%s: warning for a long token", field)
		}
	}
}
