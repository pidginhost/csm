package config

import "testing"

func TestRedact(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.WebUI.AuthToken = "secret-token"
	cfg.WebUI.MetricsToken = "metrics-secret"
	cfg.WebUI.Tokens = []WebUIToken{{Name: "admin", Token: "admin-secret", Scope: "admin"}}
	cfg.Alerts.Webhook.HMACSecret = "webhook-secret"
	cfg.GeoIP.LicenseKey = "license-key"
	cfg.GeoIP.AccountID = "account-123"
	cfg.Reputation.AbuseIPDBKey = "abuse-key"
	cfg.Challenge.Secret = "challenge-secret"
	cfg.Challenge.CaptchaFallback.SecretKey = "captcha-secret"
	cfg.Challenge.VerifiedSession.AdminSecret = "verified-secret"
	cfg.Integrity.BinaryHash = "abc123"
	cfg.Integrity.ConfigHash = "def456"
	cfg.Integrity.ConfdHash = "fedcba"
	cfg.Sentry.DSN = "https://token@sentry.example.com/1"
	cfg.Alerts.Email.SMTP = "localhost:25"

	redacted := Redact(cfg)

	// Redacted fields
	if redacted.WebUI.AuthToken != "***REDACTED***" {
		t.Errorf("auth_token not redacted: %q", redacted.WebUI.AuthToken)
	}
	if redacted.WebUI.MetricsToken != "***REDACTED***" {
		t.Errorf("metrics_token not redacted: %q", redacted.WebUI.MetricsToken)
	}
	if redacted.WebUI.Tokens[0].Token != "***REDACTED***" {
		t.Errorf("webui token not redacted: %q", redacted.WebUI.Tokens[0].Token)
	}
	if redacted.Alerts.Webhook.HMACSecret != "***REDACTED***" {
		t.Errorf("webhook hmac_secret not redacted: %q", redacted.Alerts.Webhook.HMACSecret)
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
	if redacted.Challenge.CaptchaFallback.SecretKey != "***REDACTED***" {
		t.Errorf("challenge.captcha_fallback.secret_key not redacted: %q", redacted.Challenge.CaptchaFallback.SecretKey)
	}
	if redacted.Challenge.VerifiedSession.AdminSecret != "***REDACTED***" {
		t.Errorf("challenge.verified_session.admin_secret not redacted: %q", redacted.Challenge.VerifiedSession.AdminSecret)
	}
	if redacted.Integrity.BinaryHash != "***REDACTED***" {
		t.Errorf("binary_hash not redacted: %q", redacted.Integrity.BinaryHash)
	}
	if redacted.Integrity.ConfigHash != "***REDACTED***" {
		t.Errorf("config_hash not redacted: %q", redacted.Integrity.ConfigHash)
	}
	if redacted.Integrity.ConfdHash != "***REDACTED***" {
		t.Errorf("confd_hash not redacted: %q", redacted.Integrity.ConfdHash)
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
	if cfg.WebUI.Tokens[0].Token != "admin-secret" {
		t.Error("original webui token was mutated")
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

func TestRedactConfigScalarForLogRedactsConfdHash(t *testing.T) {
	got := redactConfigScalarForLog("integrity.confd_hash", "sha256:abc")
	if got != "***REDACTED***" {
		t.Fatalf("confd_hash log redaction = %q", got)
	}
}
