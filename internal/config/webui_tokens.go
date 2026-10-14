package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// DefaultWebUITokenLifetime is how long a credential without an explicit
// expiry stays valid after its issue time.
const DefaultWebUITokenLifetime = 7 * 24 * time.Hour

// WebUITokenCurrent uses the persisted issue time so restarting or reloading
// cannot renew a stolen credential. An explicit expiry replaces the default
// lifetime. Missing or malformed dates fail closed.
func WebUITokenCurrent(issuedAt, expiresAt string, now time.Time) bool {
	field, _ := webUITokenProblem(issuedAt, expiresAt, now)
	return field == ""
}

// webUITokenProblem names the date field that disables a credential and why,
// or returns an empty field for a current credential.
func webUITokenProblem(issuedAt, expiresAt string, now time.Time) (field, problem string) {
	issued, err := time.Parse(time.RFC3339, issuedAt)
	if err != nil || issued.IsZero() || now.Before(issued) {
		return "issued_at", "issued_at must be a valid RFC3339 issue time that is not in the future"
	}
	deadline, deadlineField := issued.Add(DefaultWebUITokenLifetime), "issued_at"
	if expiresAt != "" {
		deadline, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil || !deadline.After(issued) {
			return "expires_at", "expires_at must be a valid RFC3339 time after issued_at"
		}
		deadlineField = "expires_at"
	}
	if !now.Before(deadline) {
		return deadlineField, "expired at " + deadline.UTC().Format(time.RFC3339)
	}
	return "", ""
}

func tokenExpiryWarnings(cfg *Config, now time.Time) []ValidationResult {
	var out []ValidationResult
	check := func(token, issuedAt, expiresAt, prefix string) {
		if token == "" {
			return
		}
		if field, problem := webUITokenProblem(issuedAt, expiresAt, now); field != "" {
			out = append(out, ValidationResult{"warn", prefix + field,
				"credential disabled: " + problem + "; replace the token and its issue time together"})
		}
	}
	for i, tok := range cfg.WebUI.Tokens {
		check(tok.Token, tok.IssuedAt, tok.ExpiresAt, fmt.Sprintf("webui.tokens[%d].", i))
	}
	if len(cfg.WebUI.Tokens) == 0 {
		check(cfg.WebUI.AuthToken, cfg.WebUI.AuthTokenIssuedAt, cfg.WebUI.AuthTokenExpiresAt, "webui.auth_token_")
	}
	check(cfg.WebUI.MetricsToken, cfg.WebUI.MetricsTokenIssuedAt, cfg.WebUI.MetricsTokenExpiresAt, "webui.metrics_token_")
	return out
}

// parseTokenSource reads one allowed_ips entry: an address or a CIDR.
func parseTokenSource(src string) (netip.Prefix, error) {
	if strings.Contains(src, "/") {
		p, err := netip.ParsePrefix(src)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(src)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// AcceptsFrom reports whether the token may be used from addr. A token
// without AllowedIPs is accepted from any address; a restricted token never
// accepts an invalid address.
func (t WebUIToken) AcceptsFrom(addr netip.Addr) bool {
	if len(t.AllowedIPs) == 0 {
		return true
	}
	addr = addr.WithZone("").Unmap()
	for _, src := range t.AllowedIPs {
		if p, err := parseTokenSource(src); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}
