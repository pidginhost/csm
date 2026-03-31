package config

const redactedValue = "***REDACTED***"

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
	if c.GeoIP.LicenseKey != "" {
		c.GeoIP.LicenseKey = redactedValue
	}
	if c.Reputation.AbuseIPDBKey != "" {
		c.Reputation.AbuseIPDBKey = redactedValue
	}
	if c.Challenge.Secret != "" {
		c.Challenge.Secret = redactedValue
	}
	if c.Integrity.BinaryHash != "" {
		c.Integrity.BinaryHash = redactedValue
	}
	if c.Integrity.ConfigHash != "" {
		c.Integrity.ConfigHash = redactedValue
	}

	// Deep-copy Firewall pointer so we don't share it with the original
	if cfg.Firewall != nil {
		fw := *cfg.Firewall
		c.Firewall = &fw
	}

	return &c
}
