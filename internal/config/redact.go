package config

const redactedValue = "***REDACTED***"

var sensitiveScalarPaths = map[string]struct{}{
	"alerts.webhook.hmac_secret":                 {},
	"auto_response.verdict_callback.hmac_secret": {},
	"challenge.captcha_fallback.secret_key":      {},
	"challenge.secret":                           {},
	"challenge.verified_session.admin_secret":    {},
	"geoip.license_key":                          {},
	"integrity.binary_hash":                      {},
	"integrity.config_hash":                      {},
	"reputation.abuseipdb_key":                   {},
	"reputation.rspamd.token":                    {},
	"reputation.upstream.token":                  {},
	"sentry.dsn":                                 {},
	"webui.auth_token":                           {},
	"webui.metrics_token":                        {},
}

// Redact returns a copy of the config with sensitive fields replaced.
// Empty fields are left empty (not replaced with the redaction marker).
// The original config is not modified.
func Redact(cfg *Config) *Config {
	// Shallow copy the struct
	c := *cfg

	// Redact secrets (only if non-empty)
	if c.WebUI.AuthToken != "" {
		c.WebUI.AuthToken = redactedValue
	}
	if c.WebUI.MetricsToken != "" {
		c.WebUI.MetricsToken = redactedValue
	}
	if len(c.WebUI.Tokens) > 0 {
		c.WebUI.Tokens = append([]WebUIToken(nil), c.WebUI.Tokens...)
		for i := range c.WebUI.Tokens {
			if c.WebUI.Tokens[i].Token != "" {
				c.WebUI.Tokens[i].Token = redactedValue
			}
		}
	}
	if c.Alerts.Webhook.HMACSecret != "" {
		c.Alerts.Webhook.HMACSecret = redactedValue
	}
	if c.GeoIP.LicenseKey != "" {
		c.GeoIP.LicenseKey = redactedValue
	}
	if c.Reputation.AbuseIPDBKey != "" {
		c.Reputation.AbuseIPDBKey = redactedValue
	}
	if c.Reputation.Rspamd.Token != "" {
		c.Reputation.Rspamd.Token = redactedValue
	}
	if c.Reputation.Upstream.Token != "" {
		c.Reputation.Upstream.Token = redactedValue
	}
	if c.AutoResponse.VerdictCallback.HMACSecret != "" {
		c.AutoResponse.VerdictCallback.HMACSecret = redactedValue
	}
	if c.Challenge.Secret != "" {
		c.Challenge.Secret = redactedValue
	}
	if c.Challenge.CaptchaFallback.SecretKey != "" {
		c.Challenge.CaptchaFallback.SecretKey = redactedValue
	}
	if c.Challenge.VerifiedSession.AdminSecret != "" {
		c.Challenge.VerifiedSession.AdminSecret = redactedValue
	}
	if c.Integrity.BinaryHash != "" {
		c.Integrity.BinaryHash = redactedValue
	}
	if c.Integrity.ConfigHash != "" {
		c.Integrity.ConfigHash = redactedValue
	}
	if c.Integrity.ConfdHash != "" {
		c.Integrity.ConfdHash = redactedValue
	}
	if c.Sentry.DSN != "" {
		c.Sentry.DSN = redactedValue
	}

	// Deep-copy Firewall pointer so we don't share it with the original
	if cfg.Firewall != nil {
		fw := *cfg.Firewall
		c.Firewall = &fw
	}

	return &c
}

func redactConfigScalarForLog(keyPath, value string) string {
	if value == "" {
		return value
	}
	if _, ok := sensitiveScalarPaths[keyPath]; ok {
		return redactedValue
	}
	return value
}
