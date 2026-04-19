package config

import "testing"

func TestRedact(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.WebUI.AuthToken = "secret-token"
	cfg.GeoIP.LicenseKey = "license-key"
	cfg.GeoIP.AccountID = "account-123"
	cfg.Reputation.AbuseIPDBKey = "abuse-key"
	cfg.Challenge.Secret = "challenge-secret"
	cfg.Integrity.BinaryHash = "abc123"
	cfg.Integrity.ConfigHash = "def456"
	cfg.Sentry.DSN = "https://token@sentry.example.com/1"
	cfg.Alerts.Email.SMTP = "localhost:25"

	redacted := Redact(cfg)

	// Redacted fields
	if redacted.WebUI.AuthToken != "***REDACTED***" {
		t.Errorf("auth_token not redacted: %q", redacted.WebUI.AuthToken)
	}
	if redacted.GeoIP.LicenseKey != "***REDACTED***" {
		t.Errorf("license_key not redacted: %q", redacted.GeoIP.LicenseKey)
	}
	if redacted.Reputation.AbuseIPDBKey != "***REDACTED***" {
		t.Errorf("abuseipdb_key not redacted: %q", redacted.Reputation.AbuseIPDBKey)
	}
	if redacted.Challenge.Secret != "***REDACTED***" {
		t.Errorf("challenge.secret not redacted: %q", redacted.Challenge.Secret)
	}
	if redacted.Integrity.BinaryHash != "***REDACTED***" {
		t.Errorf("binary_hash not redacted: %q", redacted.Integrity.BinaryHash)
	}
	if redacted.Integrity.ConfigHash != "***REDACTED***" {
		t.Errorf("config_hash not redacted: %q", redacted.Integrity.ConfigHash)
	}
	if redacted.Sentry.DSN != "***REDACTED***" {
		t.Errorf("sentry.dsn not redacted: %q", redacted.Sentry.DSN)
	}

	// Not redacted
	if redacted.GeoIP.AccountID != "account-123" {
		t.Errorf("account_id should not be redacted: %q", redacted.GeoIP.AccountID)
	}
	if redacted.Alerts.Email.SMTP != "localhost:25" {
		t.Errorf("smtp should not be redacted: %q", redacted.Alerts.Email.SMTP)
	}

	// Original untouched
	if cfg.WebUI.AuthToken != "secret-token" {
		t.Error("original config was mutated")
	}
}

func TestRedactEmptyFields(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	redacted := Redact(cfg)

	// Empty fields stay empty
	if redacted.WebUI.AuthToken != "" {
		t.Errorf("empty auth_token should stay empty, got %q", redacted.WebUI.AuthToken)
	}
}
