package config

import (
	"strings"
	"testing"
)

// Webhook and heartbeat URLs are credentials: Slack and Discord webhooks put
// the token in the path, generic ones in the query or userinfo. validate and
// config show echoed them in full.
func TestRedactURLKeepsSchemeAndHostOnly(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://hooks.slack.com/services/T000/B000/XXXXXXXX", "https://hooks.slack.com/[REDACTED]"},
		{"https://discord.com/api/webhooks/1234/abcdef", "https://discord.com/[REDACTED]"},
		{"https://alerts.example.com/hook?token=abc", "https://alerts.example.com/[REDACTED]"},
		{"https://user:pass@alerts.example.com/", "https://alerts.example.com/[REDACTED]"},
		{"https://alerts.example.com:8443/", "https://alerts.example.com:8443/"},
		{"https://alerts.example.com", "https://alerts.example.com"},
		{"", ""},
		{"not a url", "[REDACTED]"},
	}
	for _, tc := range cases {
		if got := RedactURL(tc.in); got != tc.want {
			t.Errorf("RedactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRedactConfigHidesWebhookAndHeartbeatURLPaths(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Webhook.URL = "https://hooks.slack.com/services/T000/B000/XXXXXXXX"
	cfg.Alerts.Heartbeat.URL = "https://hc.example.com/ping/abcd-1234"
	cfg.AutoResponse.VerdictCallback.URL = "https://panel.example.com/verdict?key=abc"
	cfg.Reputation.Upstream.URL = "https://intel.example.com/api/v1"

	r := Redact(cfg)
	for name, got := range map[string]string{
		"alerts.webhook.url":                 r.Alerts.Webhook.URL,
		"alerts.heartbeat.url":               r.Alerts.Heartbeat.URL,
		"auto_response.verdict_callback.url": r.AutoResponse.VerdictCallback.URL,
		"reputation.upstream.url":            r.Reputation.Upstream.URL,
	} {
		if !strings.HasSuffix(got, "[REDACTED]") {
			t.Errorf("%s = %q, want host-only with the path redacted", name, got)
		}
	}
	if cfg.Alerts.Webhook.URL != "https://hooks.slack.com/services/T000/B000/XXXXXXXX" {
		t.Fatal("Redact modified the original config")
	}
	if got := redactConfigScalarForLog("alerts.webhook.url", cfg.Alerts.Webhook.URL); got != "https://hooks.slack.com/[REDACTED]" {
		t.Errorf("hot-reload log value = %q", got)
	}
}

func TestValidateDoesNotEchoWebhookOrHeartbeatURL(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://hooks.slack.com/services/T000/B000/XXXXXXXX"
	cfg.Alerts.Webhook.Type = "slack"
	cfg.Alerts.Heartbeat.Enabled = true
	cfg.Alerts.Heartbeat.URL = "https://hc.example.com/ping/abcd-1234"

	for _, r := range Validate(cfg) {
		if r.Field != "alerts.webhook.url" && r.Field != "alerts.heartbeat.url" {
			continue
		}
		for _, secret := range []string{"XXXXXXXX", "abcd-1234"} {
			if strings.Contains(r.Message, secret) {
				t.Errorf("%s result echoes the URL secret: %q", r.Field, r.Message)
			}
		}
	}
}
