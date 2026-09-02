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
	cfg.Reputation.Rspamd.URL = "https://rspamd.example.com/check?token=def"
	cfg.Reputation.Upstream.URL = "https://intel.example.com/api/v1"
	cfg.Reputation.Report.Targets = append(cfg.Reputation.Report.Targets, struct {
		Name      string `yaml:"name"`
		URL       string `yaml:"url"`
		Transport string `yaml:"transport"`
		NodeID    string `yaml:"node_id"`
		KeyID     string `yaml:"key_id"`
		KeyEnv    string `yaml:"key_env"`
		TokenEnv  string `yaml:"token_env"`
	}{URL: "https://reports.example.com/ingest?secret=ghi"})

	r := Redact(cfg)
	for name, got := range map[string]string{
		"alerts.webhook.url":                 r.Alerts.Webhook.URL,
		"alerts.heartbeat.url":               r.Alerts.Heartbeat.URL,
		"auto_response.verdict_callback.url": r.AutoResponse.VerdictCallback.URL,
		"reputation.rspamd.url":              r.Reputation.Rspamd.URL,
		"reputation.upstream.url":            r.Reputation.Upstream.URL,
		"reputation.report.targets[0].url":   r.Reputation.Report.Targets[0].URL,
	} {
		if !strings.HasSuffix(got, "[REDACTED]") {
			t.Errorf("%s = %q, want host-only with the path redacted", name, got)
		}
	}
	if cfg.Alerts.Webhook.URL != "https://hooks.slack.com/services/T000/B000/XXXXXXXX" {
		t.Fatal("Redact modified the original config")
	}
	if cfg.Reputation.Report.Targets[0].URL != "https://reports.example.com/ingest?secret=ghi" {
		t.Fatal("Redact modified the original report target")
	}
	for path, raw := range map[string]string{
		"alerts.webhook.url":                 cfg.Alerts.Webhook.URL,
		"alerts.heartbeat.url":               cfg.Alerts.Heartbeat.URL,
		"auto_response.verdict_callback.url": cfg.AutoResponse.VerdictCallback.URL,
		"reputation.rspamd.url":              cfg.Reputation.Rspamd.URL,
		"reputation.upstream.url":            cfg.Reputation.Upstream.URL,
	} {
		if got := redactConfigScalarForLog(path, raw); !strings.HasSuffix(got, "[REDACTED]") {
			t.Errorf("hot-reload log value for %s = %q", path, got)
		}
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
