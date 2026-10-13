package config

import (
	"fmt"
	"time"
)

const MaxWebUITokenLifetime = 7 * 24 * time.Hour

// WebUITokenCurrent uses the persisted issue time so restarting or reloading
// cannot renew a stolen credential. Missing or malformed dates fail closed.
func WebUITokenCurrent(issuedAt string, now time.Time) bool {
	issued, err := time.Parse(time.RFC3339, issuedAt)
	return err == nil && !issued.IsZero() && !now.Before(issued) && now.Before(issued.Add(MaxWebUITokenLifetime))
}

func tokenExpiryWarnings(cfg *Config, now time.Time) []ValidationResult {
	var out []ValidationResult
	check := func(token, issuedAt, field string) {
		if token != "" && !WebUITokenCurrent(issuedAt, now) {
			out = append(out, ValidationResult{"warn", field,
				"credential disabled: issued_at must be a valid RFC3339 issue time within the last seven days; replace the token and its issue time together"})
		}
	}
	for i, tok := range cfg.WebUI.Tokens {
		check(tok.Token, tok.IssuedAt, fmt.Sprintf("webui.tokens[%d].issued_at", i))
	}
	if len(cfg.WebUI.Tokens) == 0 {
		check(cfg.WebUI.AuthToken, cfg.WebUI.AuthTokenIssuedAt, "webui.auth_token_issued_at")
	}
	check(cfg.WebUI.MetricsToken, cfg.WebUI.MetricsTokenIssuedAt, "webui.metrics_token_issued_at")
	return out
}
