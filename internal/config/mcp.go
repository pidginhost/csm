package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// MCPConfig is the mcp: block. The endpoint answers at /mcp on the Web UI
// listener. Every credential in Tokens is read-only; there is no scope
// field because the endpoint has no other scope.
type MCPConfig struct {
	Enabled bool       `yaml:"enabled"`
	Tokens  []MCPToken `yaml:"tokens"`
}

// MCPToken is one entry in MCP.Tokens. It carries the same dates and
// source restriction as WebUIToken but no scope.
type MCPToken struct {
	Name       string   `yaml:"name"`
	Token      string   `yaml:"token"`
	IssuedAt   string   `yaml:"issued_at"`
	ExpiresAt  string   `yaml:"expires_at,omitempty"`
	AllowedIPs []string `yaml:"allowed_ips,omitempty"`
}

// AcceptsFrom reports whether the token may be used from addr, as
// WebUIToken.AcceptsFrom does.
func (t MCPToken) AcceptsFrom(addr netip.Addr) bool {
	return WebUIToken{AllowedIPs: t.AllowedIPs}.AcceptsFrom(addr)
}

// Current reports whether the credential is usable at now.
func (t MCPToken) Current(now time.Time) bool {
	return WebUITokenCurrent(t.IssuedAt, t.ExpiresAt, now)
}

// validateMCPTokens is the hard validation that aborts a config load:
// malformed entries are refused whether or not the endpoint is enabled, so
// a later `enabled: true` cannot start with credentials nobody checked.
func validateMCPTokens(cfg *Config) error {
	seenNames := make(map[string]struct{}, len(cfg.MCP.Tokens))
	seenTokens := make(map[string]struct{}, len(cfg.MCP.Tokens))
	for i, tok := range cfg.MCP.Tokens {
		name := strings.TrimSpace(tok.Name)
		if name == "" {
			return fmt.Errorf("mcp.tokens[%d]: empty name", i)
		}
		for j, src := range tok.AllowedIPs {
			if _, err := parseTokenSource(src); err != nil {
				return fmt.Errorf("mcp.tokens[%d].allowed_ips[%d]: %q is not an IP address or CIDR", i, j, src)
			}
		}
		if tok.Token == "" {
			return fmt.Errorf("mcp.tokens[%d]: empty token", i)
		}
		if _, ok := seenNames[name]; ok {
			return fmt.Errorf("mcp.tokens[%d]: duplicate name %q", i, tok.Name)
		}
		seenNames[name] = struct{}{}
		if _, ok := seenTokens[tok.Token]; ok {
			return fmt.Errorf("mcp.tokens[%d]: duplicate token", i)
		}
		seenTokens[tok.Token] = struct{}{}
		for _, web := range cfg.WebUI.Tokens {
			if web.Token != "" && web.Token == tok.Token {
				return fmt.Errorf("mcp.tokens[%d]: token is also a webui token; the MCP endpoint needs its own credential", i)
			}
		}
		if cfg.WebUI.MetricsToken != "" && cfg.WebUI.MetricsToken == tok.Token {
			return fmt.Errorf("mcp.tokens[%d]: token is also webui.metrics_token; the MCP endpoint needs its own credential", i)
		}
	}
	return nil
}

// mcpResults is the soft validation `csm validate` prints for the block.
func mcpResults(cfg *Config, now time.Time) []ValidationResult {
	var results []ValidationResult
	for i, tok := range cfg.MCP.Tokens {
		if tok.Token != "" && len(tok.Token) < minWebUITokenLength {
			results = append(results, ValidationResult{"warn", "mcp.tokens", fmt.Sprintf("token %q is shorter than %d characters and guessable; replace it with a random value", tok.Name, minWebUITokenLength)})
		}
		if field, problem := webUITokenProblem(tok.IssuedAt, tok.ExpiresAt, now); field != "" {
			results = append(results, ValidationResult{"warn", fmt.Sprintf("mcp.tokens[%d].%s", i, field),
				"credential disabled: " + problem + "; correct the date or replace the token"})
		}
	}
	if !cfg.MCP.Enabled {
		return results
	}
	if !cfg.WebUI.Enabled {
		results = append(results, ValidationResult{"error", "mcp.enabled", "the MCP endpoint reads through the Web UI server; set webui.enabled: true or disable mcp"})
	}
	usable := 0
	for _, tok := range cfg.MCP.Tokens {
		if tok.Token != "" && tok.Current(now) {
			usable++
		}
	}
	if usable == 0 {
		results = append(results, ValidationResult{"error", "mcp.tokens", "mcp enabled but no usable token configured"})
	}
	results = append(results, ValidationResult{"ok", "mcp", "served at https://" + cfg.WebUI.Listen + "/mcp"})
	return results
}
