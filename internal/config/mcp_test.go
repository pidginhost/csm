package config

import (
	"strings"
	"testing"
	"time"
)

func mcpBase() *Config {
	cfg := &Config{}
	cfg.WebUI.Enabled = true
	cfg.WebUI.Listen = "0.0.0.0:9443"
	cfg.WebUI.Tokens = []WebUIToken{{Name: "admin", Token: strings.Repeat("a", 48), Scope: "admin"}}
	cfg.MCP.Enabled = true
	cfg.MCP.Listen = DefaultMCPListen
	cfg.MCP.Tokens = []MCPToken{{Name: "agent", Token: strings.Repeat("b", 48)}}
	return cfg
}

func mcpResultsByLevel(cfg *Config) (errs, warns []string) {
	for _, r := range mcpResults(cfg, time.Now()) {
		switch r.Level {
		case "error":
			errs = append(errs, r.Field+": "+r.Message)
		case "warn":
			warns = append(warns, r.Field+": "+r.Message)
		}
	}
	return errs, warns
}

func TestMCPValidationHappyPath(t *testing.T) {
	errs, warns := mcpResultsByLevel(mcpBase())
	if len(errs) != 0 || len(warns) != 0 {
		t.Fatalf("errors %v warnings %v", errs, warns)
	}
}

func TestMCPValidationNeedsWebUI(t *testing.T) {
	cfg := mcpBase()
	cfg.WebUI.Enabled = false
	errs, _ := mcpResultsByLevel(cfg)
	if len(errs) != 1 || !strings.Contains(errs[0], "webui.enabled") {
		t.Fatalf("errors %v", errs)
	}
}

func TestMCPValidationNeedsUsableToken(t *testing.T) {
	cfg := mcpBase()
	cfg.MCP.Tokens = nil
	if errs, _ := mcpResultsByLevel(cfg); len(errs) != 1 || !strings.Contains(errs[0], "no usable token") {
		t.Fatalf("no tokens: %v", errs)
	}
	cfg.MCP.Tokens = []MCPToken{{Name: "old", Token: strings.Repeat("b", 48), ExpiresAt: "2020-01-01T00:00:00Z"}}
	errs, warns := mcpResultsByLevel(cfg)
	if len(errs) != 1 || !strings.Contains(errs[0], "no usable token") {
		t.Fatalf("expired token: %v", errs)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "expires_at") {
		t.Fatalf("expired token warning: %v", warns)
	}
}

func TestMCPValidationWarnsOffLoopbackAndShortToken(t *testing.T) {
	cfg := mcpBase()
	cfg.MCP.Listen = "0.0.0.0:9444"
	cfg.MCP.Tokens[0].Token = "short"
	errs, warns := mcpResultsByLevel(cfg)
	if len(errs) != 0 {
		t.Fatalf("errors %v", errs)
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "off the loopback") || !strings.Contains(joined, "guessable") {
		t.Fatalf("warnings %v", warns)
	}
}

func TestMCPValidationListenForms(t *testing.T) {
	cfg := mcpBase()
	cfg.MCP.Listen = "unix:/run/csm/mcp.sock"
	if errs, _ := mcpResultsByLevel(cfg); len(errs) != 0 {
		t.Fatalf("unix socket: %v", errs)
	}
	if err := validateMCPTokens(cfg); err != nil {
		t.Fatalf("unix socket hard validation: %v", err)
	}
	cfg.MCP.Listen = "unix:relative.sock"
	if err := validateMCPTokens(cfg); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative socket accepted: %v", err)
	}
	cfg.MCP.Listen = "nonsense"
	if errs, _ := mcpResultsByLevel(cfg); len(errs) != 1 || !strings.Contains(errs[0], "host:port") {
		t.Fatalf("bad listen: %v", errs)
	}
	cfg.MCP.Listen = cfg.WebUI.Listen
	if errs, _ := mcpResultsByLevel(cfg); len(errs) == 0 {
		t.Fatal("same address as webui accepted")
	}
}

func TestMCPTokensHardValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"empty name", func(c *Config) { c.MCP.Tokens[0].Name = " " }, "empty name"},
		{"empty token", func(c *Config) { c.MCP.Tokens[0].Token = "" }, "empty token"},
		{"bad allowed ip", func(c *Config) { c.MCP.Tokens[0].AllowedIPs = []string{"nope"} }, "allowed_ips"},
		{"duplicate name", func(c *Config) {
			c.MCP.Tokens = append(c.MCP.Tokens, MCPToken{Name: "agent", Token: strings.Repeat("c", 48)})
		}, "duplicate name"},
		{"duplicate token", func(c *Config) {
			c.MCP.Tokens = append(c.MCP.Tokens, MCPToken{Name: "other", Token: c.MCP.Tokens[0].Token})
		}, "duplicate token"},
		{"webui token reused", func(c *Config) { c.MCP.Tokens[0].Token = c.WebUI.Tokens[0].Token }, "also a webui token"},
		{"metrics token reused", func(c *Config) {
			c.WebUI.MetricsToken = strings.Repeat("m", 48)
			c.MCP.Tokens[0].Token = c.WebUI.MetricsToken
		}, "metrics_token"},
	}
	for _, tc := range cases {
		cfg := mcpBase()
		tc.mutate(cfg)
		err := validateMCPTokens(cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
	// Hard validation applies while disabled too, so enabling later is safe.
	cfg := mcpBase()
	cfg.MCP.Enabled = false
	cfg.MCP.Tokens[0].Token = ""
	if err := validateMCPTokens(cfg); err == nil {
		t.Error("disabled block with an empty token accepted")
	}
}

func TestMCPLoadsFromYAMLAndRedacts(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
webui:
  enabled: true
  tokens:
    - {name: admin, token: ` + strings.Repeat("a", 48) + `, scope: admin}
mcp:
  enabled: true
  tokens:
    - name: agent
      token: ` + strings.Repeat("b", 48) + `
      allowed_ips: ["203.0.113.0/24"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCP.Listen != DefaultMCPListen {
		t.Errorf("listen default = %q", cfg.MCP.Listen)
	}
	red := Redact(cfg)
	if red.MCP.Tokens[0].Token != RedactedValue {
		t.Errorf("mcp token not redacted: %q", red.MCP.Tokens[0].Token)
	}
	if cfg.MCP.Tokens[0].Token == RedactedValue {
		t.Error("Redact modified the original")
	}
	if MCPUnixSocketPath("unix:/a.sock") != "/a.sock" || MCPUnixSocketPath("127.0.0.1:1") != "" {
		t.Error("MCPUnixSocketPath")
	}
}
