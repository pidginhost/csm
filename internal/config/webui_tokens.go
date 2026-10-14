package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// WebUITokenCurrent reports whether a credential is usable at now. It expires
// only at its expires_at; issued_at records when it was generated. Credentials
// without dates never expire, as in configurations written before dates
// existed. Malformed or future dates fail closed.
func WebUITokenCurrent(issuedAt, expiresAt string, now time.Time) bool {
	field, _ := webUITokenProblem(issuedAt, expiresAt, now)
	return field == ""
}

// webUITokenProblem names the date field that disables a credential and why,
// or returns an empty field for a current credential.
func webUITokenProblem(issuedAt, expiresAt string, now time.Time) (field, problem string) {
	var issued time.Time
	if issuedAt != "" {
		var err error
		issued, err = time.Parse(time.RFC3339, issuedAt)
		if err != nil || issued.IsZero() || now.Before(issued) {
			return "issued_at", "issued_at must be a valid RFC3339 issue time that is not in the future"
		}
	}
	if expiresAt == "" {
		return "", ""
	}
	deadline, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !deadline.After(issued) {
		return "expires_at", "expires_at must be a valid RFC3339 time after issued_at"
	}
	if !now.Before(deadline) {
		return "expires_at", "expired at " + deadline.UTC().Format(time.RFC3339)
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
				"credential disabled: " + problem + "; correct the date or replace the token"})
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
		p = p.Masked()
		// Peers are unmapped before matching. Keep mapped networks in
		// the same address family, including their effective mask width.
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p, nil
	}
	addr, err := netip.ParseAddr(src)
	if err != nil {
		return netip.Prefix{}, err
	}
	// PrefixFrom drops zones, which would silently widen an entry meant
	// to restrict a credential to one interface.
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("token source addresses must not include a zone")
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
