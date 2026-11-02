package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// TestConfigSummaryHoldsNoSecret plants a marker in every secret field
// Redact knows and checks none of it reaches the summary.
func TestConfigSummaryHoldsNoSecret(t *testing.T) {
	const marker = "SECRET-MARKER-9f3a"
	cfg := &config.Config{Hostname: "h", Mode: "standard", StatePath: "/var/lib/csm"}
	cfg.WebUI.Listen = "0.0.0.0:9443"
	cfg.WebUI.AuthToken = marker
	cfg.WebUI.MetricsToken = marker
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "a", Token: marker, Scope: "admin"}}
	cfg.MCP.Tokens = []config.MCPToken{{Name: "agent", Token: marker}}
	cfg.Alerts.Webhook.HMACSecret = marker
	cfg.GeoIP.LicenseKey = marker
	cfg.Reputation.AbuseIPDBKey = marker
	cfg.Reputation.Rspamd.Token = marker
	cfg.Reputation.Upstream.Token = marker
	cfg.AutoResponse.VerdictCallback.HMACSecret = marker
	cfg.Challenge.Secret = marker
	cfg.Challenge.CaptchaFallback.SecretKey = marker
	cfg.Challenge.VerifiedSession.AdminSecret = marker
	cfg.Sentry.DSN = marker
	cfg.Integrity.BinaryHash = marker
	cfg.Integrity.ConfigHash = marker

	out, err := json.Marshal(ConfigSummary(cfg, platform.Info{OS: platform.OSAlma, Panel: platform.PanelCPanel}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), marker) {
		t.Fatalf("summary leaks a secret: %s", out)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if m["hostname"] != "h" || m["webui_listen"] != "0.0.0.0:9443" {
		t.Errorf("summary: %s", out)
	}
	if m["platform"].(map[string]any)["panel"] != "cpanel" {
		t.Errorf("platform: %v", m["platform"])
	}
	if m["firewall"].(map[string]any)["enabled"] != false {
		t.Errorf("nil firewall should read disabled: %v", m["firewall"])
	}
}
