package config

import (
	"reflect"
	"slices"
)

const redactedValue = "***REDACTED***"

// RedactedValue is the placeholder Redact writes over a secret. A settings
// save that sends it back means "keep the stored secret".
const RedactedValue = redactedValue

var sensitiveScalarPaths = map[string]struct{}{
	"alerts.webhook.hmac_secret":                 {},
	"auto_response.verdict_callback.hmac_secret": {},
	"challenge.captcha_fallback.secret_key":      {},
	"challenge.secret":                           {},
	"challenge.verified_session.admin_secret":    {},
	"geoip.license_key":                          {},
	"integrity.binary_hash":                      {},
	"integrity.config_hash":                      {},
	"integrity.confd_hash":                       {},
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
	if len(c.MCP.Tokens) > 0 {
		c.MCP.Tokens = append([]MCPToken(nil), c.MCP.Tokens...)
		for i := range c.MCP.Tokens {
			if c.MCP.Tokens[i].Token != "" {
				c.MCP.Tokens[i].Token = redactedValue
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

	// Credential-bearing URLs keep scheme and host only.
	c.Stalwart.APIURL = RedactURL(c.Stalwart.APIURL)
	c.Alerts.Webhook.URL = RedactURL(c.Alerts.Webhook.URL)
	c.Alerts.Heartbeat.URL = RedactURL(c.Alerts.Heartbeat.URL)
	c.AutoResponse.VerdictCallback.URL = RedactURL(c.AutoResponse.VerdictCallback.URL)
	c.Reputation.Rspamd.URL = RedactURL(c.Reputation.Rspamd.URL)
	c.Reputation.Upstream.URL = RedactURL(c.Reputation.Upstream.URL)
	if len(c.Reputation.Report.Targets) > 0 {
		targets := slices.Clone(c.Reputation.Report.Targets)
		for i := range targets {
			targets[i].URL = RedactURL(targets[i].URL)
		}
		c.Reputation.Report.Targets = targets
	}

	// Deep-copy Firewall pointer so we don't share it with the original
	if cfg.Firewall != nil {
		fw := *cfg.Firewall
		c.Firewall = &fw
	}

	return &c
}

// SecretValues returns the configured value of every field Redact hides,
// longest first, so free text such as a log excerpt can be scrubbed of them
// before it leaves the host. It is derived from Redact, so a field added
// there is covered here without a second list.
func SecretValues(cfg *Config) []string {
	var out []string
	collectRedacted(reflect.ValueOf(cfg).Elem(), reflect.ValueOf(Redact(cfg)).Elem(), &out)
	// Longest first: a token inside a URL must not be replaced before the URL.
	slices.SortStableFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

func collectRedacted(orig, red reflect.Value, out *[]string) {
	switch orig.Kind() {
	case reflect.String:
		if orig.String() != red.String() {
			*out = append(*out, orig.String())
		}
	case reflect.Pointer:
		if !orig.IsNil() && !red.IsNil() {
			collectRedacted(orig.Elem(), red.Elem(), out)
		}
	case reflect.Struct:
		for i := 0; i < orig.NumField(); i++ {
			collectRedacted(orig.Field(i), red.Field(i), out)
		}
	case reflect.Slice:
		for i := 0; i < min(orig.Len(), red.Len()); i++ {
			collectRedacted(orig.Index(i), red.Index(i), out)
		}
	}
}

func redactConfigScalarForLog(keyPath, value string) string {
	if value == "" {
		return value
	}
	if _, ok := sensitiveScalarPaths[keyPath]; ok {
		return redactedValue
	}
	if _, ok := urlScalarPaths[keyPath]; ok {
		return RedactURL(value)
	}
	return value
}
