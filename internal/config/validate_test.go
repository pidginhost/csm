package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestLoadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: test.example\nunknown_option: true\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("Load() = nil error, want unknown field rejection")
	}
}

func countLevel(results []ValidationResult, level string) int {
	n := 0
	for _, r := range results {
		if r.Level == level {
			n++
		}
	}
	return n
}

func hasResult(results []ValidationResult, level, field string) bool {
	for _, r := range results {
		if r.Level == level && r.Field == field {
			return true
		}
	}
	return false
}

func baseValidationConfig() *Config {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.Alerts.MaxPerHour = 10
	cfg.MailLogs.Source = "auto"
	cfg.Thresholds.MailBruteAccountKey = "builtin:dovecot-user"
	return cfg
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{"empty", "", true},
		{"placeholder", "SET_HOSTNAME_HERE", true},
		{"valid", "server1.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Hostname: tt.hostname}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			results := Validate(cfg)
			got := hasResult(results, "error", "hostname")
			if got != tt.wantErr {
				t.Errorf("hostname=%q: hasResult(error,hostname)=%v, want %v; results=%v", tt.hostname, got, tt.wantErr, results)
			}
		})
	}
}

func TestValidateAlerts(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	results := Validate(cfg)
	if !hasResult(results, "error", "alerts") {
		t.Errorf("expected error for no alert method; results=%v", results)
	}
}

func TestValidateEmailAlerts(t *testing.T) {
	t.Run("no recipients", func(t *testing.T) {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.SMTP = "localhost:25"
		cfg.Alerts.Email.From = "csm@test.com"
		results := Validate(cfg)
		if !hasResult(results, "error", "alerts.email.to") {
			t.Errorf("expected error for empty recipients; results=%v", results)
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"SET_EMAIL_HERE"}
		cfg.Alerts.Email.SMTP = "localhost:25"
		cfg.Alerts.Email.From = "csm@test.com"
		results := Validate(cfg)
		if !hasResult(results, "error", "alerts.email.to") {
			t.Errorf("expected error for invalid email; results=%v", results)
		}
	})

	t.Run("no at sign", func(t *testing.T) {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"bademail"}
		cfg.Alerts.Email.SMTP = "localhost:25"
		cfg.Alerts.Email.From = "csm@test.com"
		results := Validate(cfg)
		if !hasResult(results, "error", "alerts.email.to") {
			t.Errorf("expected error for email without @; results=%v", results)
		}
	})

	t.Run("no from", func(t *testing.T) {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"admin@test.com"}
		cfg.Alerts.Email.SMTP = "localhost:25"
		results := Validate(cfg)
		if !hasResult(results, "error", "alerts.email.from") {
			t.Errorf("expected error for empty from; results=%v", results)
		}
	})

	t.Run("no smtp", func(t *testing.T) {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"admin@test.com"}
		cfg.Alerts.Email.From = "csm@test.com"
		results := Validate(cfg)
		if !hasResult(results, "error", "alerts.email.smtp") {
			t.Errorf("expected error for empty smtp; results=%v", results)
		}
	})

	t.Run("valid", func(t *testing.T) {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"admin@test.com"}
		cfg.Alerts.Email.SMTP = "localhost:25"
		cfg.Alerts.Email.From = "csm@test.com"
		cfg.Alerts.Email.DisabledChecks = []string{"email_spam_outbreak", "perf_memory"}
		cfg.Alerts.MaxPerHour = 10
		results := Validate(cfg)
		if countLevel(results, "error") != 0 {
			t.Errorf("expected no errors for valid email config; results=%v", results)
		}
	})
}

func TestValidateWebhook(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Webhook.Enabled = true
	results := Validate(cfg)
	if !hasResult(results, "error", "alerts.webhook.url") {
		t.Errorf("expected error for empty webhook URL; results=%v", results)
	}
}

func TestValidatePhpanelWebhookRequiresHMACSecret(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://panel.example/csm"
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.MaxPerHour = 10
	results := Validate(cfg)
	if !hasResult(results, "error", "alerts.webhook.hmac_secret") {
		t.Errorf("expected error for missing phpanel HMAC secret; results=%v", results)
	}
}

func TestValidatePhpanelWebhookAcceptsHMACSecretEnv(t *testing.T) {
	t.Setenv("CSM_PHPANEL_HMAC_TEST", "secret")
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://panel.example/csm"
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.HMACSecretEnv = "CSM_PHPANEL_HMAC_TEST"
	cfg.Alerts.MaxPerHour = 10
	results := Validate(cfg)
	if hasResult(results, "error", "alerts.webhook.hmac_secret_env") ||
		hasResult(results, "error", "alerts.webhook.hmac_secret") {
		t.Errorf("did not expect HMAC secret error; results=%v", results)
	}
}

func TestValidateVerdictCallbackRequiresSecret(t *testing.T) {
	t.Setenv("CSM_VERDICT_HMAC_TEST", "")
	cfg := baseValidationConfig()
	cfg.AutoResponse.VerdictCallback.Enabled = true
	cfg.AutoResponse.VerdictCallback.URL = "https://panel.example.com/api/csm/verdict"
	cfg.AutoResponse.VerdictCallback.HMACSecretEnv = "CSM_VERDICT_HMAC_TEST"

	results := Validate(cfg)
	if !hasResult(results, "error", "auto_response.verdict_callback.hmac_secret_env") {
		t.Fatalf("expected error for missing verdict callback HMAC env secret; results=%v", results)
	}
	if hasResult(results, "warn", "auto_response.verdict_callback.hmac_secret") {
		t.Fatalf("missing verdict callback secret must be a blocking error, not a warning; results=%v", results)
	}
}

func TestValidateVerdictCallbackAllowsExplicitUnsignedOptIn(t *testing.T) {
	t.Setenv("CSM_VERDICT_HMAC_TEST", "")
	cfg := baseValidationConfig()
	cfg.AutoResponse.VerdictCallback.Enabled = true
	cfg.AutoResponse.VerdictCallback.URL = "https://panel.example.com/api/csm/verdict"
	cfg.AutoResponse.VerdictCallback.HMACSecretEnv = "CSM_VERDICT_HMAC_TEST"
	cfg.AutoResponse.VerdictCallback.AllowUnsigned = true

	results := Validate(cfg)
	if hasResult(results, "error", "auto_response.verdict_callback.hmac_secret_env") ||
		hasResult(results, "warn", "auto_response.verdict_callback.hmac_secret") {
		t.Fatalf("explicit allow_unsigned should not report missing verdict callback secret; results=%v", results)
	}
}

func TestValidateHeartbeat(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Heartbeat.Enabled = true
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	results := Validate(cfg)
	if !hasResult(results, "error", "alerts.heartbeat.url") {
		t.Errorf("expected error for empty heartbeat URL; results=%v", results)
	}
}

// auto_response.block_ips: true silently no-ops when the firewall is
// disabled or missing -- the engine that would apply nft rules is not
// running. Operators need a config-time warning instead of finding out
// from "nothing got blocked" in production.
func TestValidate_BlockIPsRequiresFirewallEnabled(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	// cfg.Firewall is nil -- block_ips will be a no-op.
	results := Validate(cfg)
	if !hasResult(results, "warn", "auto_response.block_ips") {
		t.Fatalf("expected warn for block_ips without firewall; results=%v", results)
	}
}

func TestValidate_BlockIPsWithFirewallDisabled(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.Firewall = &firewall.FirewallConfig{Enabled: false}
	results := Validate(cfg)
	if !hasResult(results, "warn", "auto_response.block_ips") {
		t.Fatalf("expected warn when firewall disabled; results=%v", results)
	}
}

func TestValidate_BlockIPsWarnsWhenLoadedConfigOmitsFirewall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(path, []byte(`
hostname: test
alerts:
  email:
    enabled: true
    to:
      - a@b.com
    from: csm@test.com
    smtp: localhost:25
  max_per_hour: 10
mail_logs:
  source: auto
thresholds:
  mail_brute_account_key: builtin:dovecot-user
auto_response:
  enabled: true
  block_ips: true
`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Firewall == nil || cfg.Firewall.Enabled {
		t.Fatalf("Load() should apply a disabled default firewall; got %#v", cfg.Firewall)
	}
	results := Validate(cfg)
	if !hasResult(results, "warn", "auto_response.block_ips") {
		t.Fatalf("expected warn for loaded config with missing firewall section; results=%v", results)
	}
}

func TestValidate_BlockIPsWithFirewallEnabledSilent(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true, ConnRateLimit: 100, InfraIPs: []string{"127.0.0.1"}}
	results := Validate(cfg)
	if hasResult(results, "warn", "auto_response.block_ips") {
		t.Fatalf("did not expect block_ips warn when firewall is enabled; results=%v", results)
	}
}

func TestValidateMaxPerHour(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.MaxPerHour = -1
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	results := Validate(cfg)
	if !hasResult(results, "error", "alerts.max_per_hour") {
		t.Errorf("expected error for negative max_per_hour; results=%v", results)
	}
}

func TestValidateWebUI(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.WebUI.Enabled = true
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	results := Validate(cfg)
	if !hasResult(results, "error", "webui.tokens") {
		t.Errorf("expected error for missing webui token; results=%v", results)
	}
}

func TestValidateWebUIAcceptsReadOnlyToken(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.WebUI.Enabled = true
	cfg.WebUI.Tokens = []WebUIToken{{Name: "phpanel", Token: "read-secret", Scope: "read"}}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.Alerts.MaxPerHour = 10
	results := Validate(cfg)
	if hasResult(results, "error", "webui.tokens") {
		t.Errorf("did not expect webui token error; results=%v", results)
	}
	if !hasResult(results, "warn", "webui.tokens") {
		t.Errorf("expected warning for read-only webui token set; results=%v", results)
	}
}

func TestValidateTrustedCountries(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.Suppressions.TrustedCountries = []string{"USA"} // 3 letters, invalid
	results := Validate(cfg)
	if !hasResult(results, "error", "suppressions.trusted_countries") {
		t.Errorf("expected error for invalid country code; results=%v", results)
	}
}

func TestValidateMailLogsSource(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.MailLogs.Source = "kafka"
	results := Validate(cfg)
	if !hasResult(results, "error", "mail_logs.source") {
		t.Fatalf("expected error for invalid mail log source; results=%v", results)
	}
}

func TestValidateMailBruteAccountKey(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Thresholds.MailBruteAccountKey = `regex:user=[^,\s]+`
	results := Validate(cfg)
	if !hasResult(results, "error", "thresholds.mail_brute_account_key") {
		t.Fatalf("expected error for regex without capture group; results=%v", results)
	}
}

func TestValidateDurations(t *testing.T) {
	base := func() *Config {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"a@b.com"}
		cfg.Alerts.Email.SMTP = "localhost:25"
		cfg.Alerts.Email.From = "csm@test.com"
		cfg.Alerts.MaxPerHour = 10
		return cfg
	}

	t.Run("bad block_expiry", func(t *testing.T) {
		cfg := base()
		cfg.AutoResponse.BlockExpiry = "notaduration"
		results := Validate(cfg)
		if !hasResult(results, "error", "auto_response.block_expiry") {
			t.Errorf("expected error for bad block_expiry; results=%v", results)
		}
	})

	t.Run("bad signatures.update_interval", func(t *testing.T) {
		cfg := base()
		cfg.Signatures.UpdateInterval = "xyz"
		results := Validate(cfg)
		if !hasResult(results, "error", "signatures.update_interval") {
			t.Errorf("expected error for bad update_interval; results=%v", results)
		}
	})

	t.Run("bad email_av.scan_timeout", func(t *testing.T) {
		cfg := base()
		cfg.EmailAV.ScanTimeout = "abc"
		results := Validate(cfg)
		if !hasResult(results, "error", "email_av.scan_timeout") {
			t.Errorf("expected error for bad scan_timeout; results=%v", results)
		}
	})

	t.Run("bad geoip.update_interval", func(t *testing.T) {
		cfg := base()
		cfg.GeoIP.UpdateInterval = "nope"
		results := Validate(cfg)
		if !hasResult(results, "error", "geoip.update_interval") {
			t.Errorf("expected error for bad geoip update_interval; results=%v", results)
		}
	})

	t.Run("bad reputation.bot_ranges.update_interval", func(t *testing.T) {
		cfg := base()
		cfg.Reputation.BotRanges.UpdateInterval = "soon"
		results := Validate(cfg)
		if !hasResult(results, "error", "reputation.bot_ranges.update_interval") {
			t.Errorf("expected error for bad bot_ranges update_interval; results=%v", results)
		}
	})

	t.Run("short reputation.bot_ranges.update_interval", func(t *testing.T) {
		cfg := base()
		cfg.Reputation.BotRanges.UpdateInterval = "30m"
		results := Validate(cfg)
		if !hasResult(results, "error", "reputation.bot_ranges.update_interval") {
			t.Errorf("expected error for short bot_ranges update_interval; results=%v", results)
		}
	})

	t.Run("bad permblock_interval", func(t *testing.T) {
		cfg := base()
		cfg.AutoResponse.PermBlockInterval = "bad"
		results := Validate(cfg)
		if !hasResult(results, "error", "auto_response.permblock_interval") {
			t.Errorf("expected error for bad permblock_interval; results=%v", results)
		}
	})

	t.Run("empty durations are fine", func(t *testing.T) {
		cfg := base()
		results := Validate(cfg)
		if countLevel(results, "error") != 0 {
			t.Errorf("expected no errors for empty durations; results=%v", results)
		}
	})
}

func TestValidateFirewall(t *testing.T) {
	base := func() *Config {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"a@b.com"}
		cfg.Alerts.Email.SMTP = "localhost:25"
		cfg.Alerts.Email.From = "csm@test.com"
		cfg.Firewall = &firewall.FirewallConfig{Enabled: true, ConnRateLimit: 30}
		cfg.InfraIPs = []string{"10.0.0.0/8"}
		return cfg
	}

	t.Run("conn_rate_limit=0 error", func(t *testing.T) {
		cfg := base()
		cfg.Firewall.ConnRateLimit = 0
		results := Validate(cfg)
		if !hasResult(results, "error", "firewall.conn_rate_limit") {
			t.Errorf("expected error for conn_rate_limit=0; results=%v", results)
		}
	})

	t.Run("conn_limit=0 valid", func(t *testing.T) {
		cfg := base()
		cfg.Firewall.ConnLimit = 0
		results := Validate(cfg)
		if hasResult(results, "error", "firewall.conn_limit") {
			t.Errorf("conn_limit=0 should be valid (disabled); results=%v", results)
		}
	})

	t.Run("conn_limit=-1 error", func(t *testing.T) {
		cfg := base()
		cfg.Firewall.ConnLimit = -1
		results := Validate(cfg)
		if !hasResult(results, "error", "firewall.conn_limit") {
			t.Errorf("expected error for conn_limit=-1; results=%v", results)
		}
	})
}

func TestValidateChallenge(t *testing.T) {
	base := func() *Config {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"a@b.com"}
		cfg.Alerts.Email.SMTP = "localhost:25"
		cfg.Alerts.Email.From = "csm@test.com"
		return cfg
	}

	t.Run("difficulty 6", func(t *testing.T) {
		cfg := base()
		cfg.Challenge.Difficulty = 6
		results := Validate(cfg)
		if !hasResult(results, "error", "challenge.difficulty") {
			t.Errorf("expected error for difficulty=6; results=%v", results)
		}
	})

	t.Run("difficulty -1", func(t *testing.T) {
		cfg := base()
		cfg.Challenge.Difficulty = -1
		results := Validate(cfg)
		if !hasResult(results, "error", "challenge.difficulty") {
			t.Errorf("expected error for difficulty=-1; results=%v", results)
		}
	})

	t.Run("listen_port negative", func(t *testing.T) {
		cfg := base()
		cfg.Challenge.ListenPort = -1
		results := Validate(cfg)
		if !hasResult(results, "error", "challenge.listen_port") {
			t.Errorf("expected error for listen_port=-1; results=%v", results)
		}
	})

	t.Run("listen_port zero when enabled", func(t *testing.T) {
		cfg := base()
		cfg.Challenge.Enabled = true
		cfg.Challenge.ListenPort = 0
		results := Validate(cfg)
		if !hasResult(results, "error", "challenge.listen_port") {
			t.Errorf("expected error for listen_port=0 when enabled; results=%v", results)
		}
	})

	t.Run("listen_port zero when disabled is fine", func(t *testing.T) {
		cfg := base()
		cfg.Challenge.Enabled = false
		cfg.Challenge.ListenPort = 0
		results := Validate(cfg)
		if hasResult(results, "error", "challenge.listen_port") {
			t.Errorf("did not expect listen_port error when challenge disabled; results=%v", results)
		}
	})

	t.Run("listen_port above tcp range", func(t *testing.T) {
		cfg := base()
		cfg.Challenge.ListenPort = 65536
		results := Validate(cfg)
		if !hasResult(results, "error", "challenge.listen_port") {
			t.Errorf("expected error for listen_port=65536; results=%v", results)
		}
	})
}

func TestValidateEmailAV(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.EmailAV.Enabled = true
	cfg.EmailAV.MaxAttachmentSize = -1
	results := Validate(cfg)
	if !hasResult(results, "error", "email_av.max_attachment_size") {
		t.Errorf("expected error for negative max_attachment_size; results=%v", results)
	}
}

func TestValidateSignaturesRequireSigningKeyForRemoteUpdates(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"

	cfg.Signatures.UpdateURL = "https://example.com/rules.yml"
	results := Validate(cfg)
	if !hasResult(results, "error", "signatures.signing_key") {
		t.Fatalf("expected signing_key error for remote yaml updates; results=%v", results)
	}

	cfg.Signatures.SigningKey = "abcd"
	results = Validate(cfg)
	if hasResult(results, "error", "signatures.signing_key") {
		t.Fatalf("unexpected signing_key error when key configured; results=%v", results)
	}
}

func TestValidateSignaturesRequireSigningKeyForForge(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"

	cfg.Signatures.YaraForge.Enabled = true
	results := Validate(cfg)
	if !hasResult(results, "error", "signatures.signing_key") {
		t.Fatalf("expected signing_key error for forge updates; results=%v", results)
	}
}

func TestValidateSignaturesRequireDownloadURLForForge(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"

	cfg.Signatures.SigningKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Signatures.YaraForge.Enabled = true
	results := Validate(cfg)
	if !hasResult(results, "error", "signatures.yara_forge.download_url") {
		t.Fatalf("expected download_url error for forge updates; results=%v", results)
	}
}

func TestValidateSignaturesRejectUnsafeUpdateURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "bad scheme", url: "ftp://example.com/rules.yml"},
		{name: "localhost", url: "https://localhost/rules.yml"},
		{name: "localhost trailing dot", url: "https://localhost./rules.yml"},
		{name: "loopback IPv4", url: "https://127.0.0.1/rules.yml"},
		{name: "private IPv4", url: "https://10.1.2.3/rules.yml"},
		{name: "private IPv6", url: "https://[fd00::1]/rules.yml"},
		{name: "link local IPv6 zone", url: "https://[fe80::1%25lo0]/rules.yml"},
		{name: "unspecified IPv4", url: "https://0.0.0.0/rules.yml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseValidationConfig()
			cfg.Signatures.SigningKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			cfg.Signatures.UpdateURL = tt.url

			results := Validate(cfg)
			if !hasResult(results, "error", "signatures.update_url") {
				t.Fatalf("expected update_url error for %q; results=%v", tt.url, results)
			}
		})
	}
}

func TestValidateSignaturesRejectUnsafeForgeDownloadURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "bad scheme", url: "ftp://example.com/rules.zip"},
		{name: "localhost", url: "https://localhost/rules.zip"},
		{name: "loopback IPv6 zone", url: "https://[::1%25lo0]/rules.zip"},
		{name: "private IPv4 mapped IPv6", url: "https://[::ffff:10.1.2.3]/rules.zip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseValidationConfig()
			cfg.Signatures.SigningKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			cfg.Signatures.YaraForge.DownloadURL = tt.url

			results := Validate(cfg)
			if !hasResult(results, "error", "signatures.yara_forge.download_url") {
				t.Fatalf("expected yara_forge.download_url error for %q; results=%v", tt.url, results)
			}
		})
	}
}

func TestValidateSignaturesAllowsPublicForgeTemplates(t *testing.T) {
	tests := []string{
		"HTTPS://rules.example/csm/{version}/yara-forge-rules-{tier}.zip",
		"https://rules-{tier}.example/csm/{version}/rules.zip",
	}

	for _, url := range tests {
		t.Run(url, func(t *testing.T) {
			cfg := baseValidationConfig()
			cfg.Signatures.SigningKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			cfg.Signatures.YaraForge.DownloadURL = url

			results := Validate(cfg)
			if hasResult(results, "error", "signatures.yara_forge.download_url") {
				t.Fatalf("unexpected yara_forge.download_url error for %q; results=%v", url, results)
			}
		})
	}
}

func TestValidateWarningGeoIP(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	f := false
	cfg.GeoIP.AutoUpdate = &f
	cfg.GeoIP.AccountID = "12345"
	cfg.GeoIP.LicenseKey = "key"
	results := Validate(cfg)
	if !hasResult(results, "warn", "geoip") {
		t.Errorf("expected warning for geoip credentials with auto_update=false; results=%v", results)
	}
}

func TestValidateWarningAutoResponse(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.AutoResponse.Enabled = true
	// all actions false
	results := Validate(cfg)
	if !hasResult(results, "warn", "auto_response") {
		t.Errorf("expected warning for auto_response enabled with no actions; results=%v", results)
	}
}

func TestValidateWarningInfraIPs(t *testing.T) {
	base := func() *Config {
		cfg := &Config{Hostname: "test"}
		cfg.Alerts.Email.Enabled = true
		cfg.Alerts.Email.To = []string{"a@b.com"}
		cfg.Alerts.Email.SMTP = "localhost:25"
		cfg.Alerts.Email.From = "csm@test.com"
		return cfg
	}

	t.Run("both empty", func(t *testing.T) {
		cfg := base()
		cfg.Firewall = &firewall.FirewallConfig{}
		results := Validate(cfg)
		if !hasResult(results, "warn", "infra_ips") {
			t.Errorf("expected warning when both infra_ips are empty; results=%v", results)
		}
	})

	t.Run("top-level set", func(t *testing.T) {
		cfg := base()
		cfg.InfraIPs = []string{"10.0.0.0/8"}
		cfg.Firewall = &firewall.FirewallConfig{}
		results := Validate(cfg)
		if hasResult(results, "warn", "infra_ips") {
			t.Errorf("should not warn when top-level infra_ips set; results=%v", results)
		}
	})

	t.Run("firewall set", func(t *testing.T) {
		cfg := base()
		cfg.Firewall = &firewall.FirewallConfig{InfraIPs: []string{"10.0.0.0/8"}}
		results := Validate(cfg)
		if hasResult(results, "warn", "infra_ips") {
			t.Errorf("should not warn when firewall infra_ips set; results=%v", results)
		}
	})
}

func TestValidateWarningFirewallLockout(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true, ConnRateLimit: 30}
	// no infra_ips anywhere
	results := Validate(cfg)
	if !hasResult(results, "warn", "firewall") {
		t.Errorf("expected warning for firewall enabled with no infra_ips; results=%v", results)
	}
}

func TestValidateWarningNetblockThreshold(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 1
	results := Validate(cfg)
	if !hasResult(results, "warn", "auto_response.netblock_threshold") {
		t.Errorf("expected warning for netblock_threshold < 2; results=%v", results)
	}
}

func TestValidateWarningPermblockCount(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = 1
	results := Validate(cfg)
	if !hasResult(results, "warn", "auto_response.permblock_count") {
		t.Errorf("expected warning for permblock_count < 2; results=%v", results)
	}
}

func TestValidateDeepStatePath(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{StatePath: dir}
	results := ValidateDeep(cfg)
	if !hasResult(results, "ok", "state_path") {
		t.Error("expected ok for writable state_path")
	}

	cfg.StatePath = "/nonexistent/path/csm-test"
	results = ValidateDeep(cfg)
	if !hasResult(results, "error", "state_path") {
		t.Error("expected error for non-existent state_path")
	}
}

func TestValidateDeepRulesDir(t *testing.T) {
	// Empty dir
	dir := t.TempDir()
	cfg := &Config{StatePath: t.TempDir()}
	cfg.Signatures.RulesDir = dir
	results := ValidateDeep(cfg)
	if !hasResult(results, "error", "signatures.rules_dir") {
		t.Error("expected error for empty rules dir")
	}

	// Dir with yaml file
	_ = os.WriteFile(dir+"/test.yaml", []byte("rules: []"), 0644)
	results = ValidateDeep(cfg)
	if !hasResult(results, "ok", "signatures.rules_dir") {
		t.Error("expected ok for rules dir with yaml")
	}
}

func TestValidateDeepTLSFiles(t *testing.T) {
	cfg := &Config{StatePath: t.TempDir()}
	cfg.WebUI.Enabled = true
	cfg.WebUI.AuthToken = "test"

	// No custom TLS paths -> no check
	results := ValidateDeep(cfg)
	if hasResult(results, "error", "webui.tls_cert") {
		t.Error("unexpected error when no custom TLS cert set")
	}

	// Custom paths that don't exist
	cfg.WebUI.TLSCert = "/nonexistent/cert.pem"
	cfg.WebUI.TLSKey = "/nonexistent/key.pem"
	results = ValidateDeep(cfg)
	if !hasResult(results, "error", "webui.tls_cert") {
		t.Error("expected error for missing TLS cert")
	}
	if !hasResult(results, "error", "webui.tls_key") {
		t.Error("expected error for missing TLS key")
	}
}

func TestValidateDeepGeoIP(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{StatePath: dir}
	cfg.GeoIP.AccountID = "123"
	cfg.GeoIP.LicenseKey = "key"
	cfg.GeoIP.Editions = []string{"GeoLite2-City"}

	// Missing db file
	results := ValidateDeep(cfg)
	if !hasResult(results, "error", "geoip") {
		t.Error("expected error for missing geoip db")
	}

	// Create the db file
	geoDir := dir + "/geoip"
	_ = os.MkdirAll(geoDir, 0755)
	_ = os.WriteFile(geoDir+"/GeoLite2-City.mmdb", []byte("test"), 0644)
	results = ValidateDeep(cfg)
	if !hasResult(results, "ok", "geoip") {
		t.Error("expected ok for present geoip db")
	}
}

func TestValidate_MailBruteForceRanges(t *testing.T) {
	cases := []struct {
		name    string
		apply   func(*Config)
		field   string
		wantErr bool
	}{
		{"threshold=1 rejected", func(c *Config) { c.Thresholds.MailBruteForceThreshold = 1 }, "thresholds.mail_bruteforce_threshold", true},
		{"threshold=2 accepted", func(c *Config) { c.Thresholds.MailBruteForceThreshold = 2 }, "thresholds.mail_bruteforce_threshold", false},
		{"threshold=51 rejected", func(c *Config) { c.Thresholds.MailBruteForceThreshold = 51 }, "thresholds.mail_bruteforce_threshold", true},
		{"window=0 accepted", func(c *Config) { c.Thresholds.MailBruteForceWindowMin = 0 }, "thresholds.mail_bruteforce_window_min", false},
		{"window=1 accepted", func(c *Config) { c.Thresholds.MailBruteForceWindowMin = 1 }, "thresholds.mail_bruteforce_window_min", false},
		{"window=61 rejected", func(c *Config) { c.Thresholds.MailBruteForceWindowMin = 61 }, "thresholds.mail_bruteforce_window_min", true},
		{"suppress=0 accepted", func(c *Config) { c.Thresholds.MailBruteForceSuppressMin = 0 }, "thresholds.mail_bruteforce_suppress_min", false},
		{"suppress=1 accepted", func(c *Config) { c.Thresholds.MailBruteForceSuppressMin = 1 }, "thresholds.mail_bruteforce_suppress_min", false},
		{"suppress=1441 rejected", func(c *Config) { c.Thresholds.MailBruteForceSuppressMin = 1441 }, "thresholds.mail_bruteforce_suppress_min", true},
		{"subnet_threshold=1 rejected", func(c *Config) { c.Thresholds.MailBruteForceSubnetThresh = 1 }, "thresholds.mail_bruteforce_subnet_threshold", true},
		{"subnet_threshold=2 accepted", func(c *Config) { c.Thresholds.MailBruteForceSubnetThresh = 2 }, "thresholds.mail_bruteforce_subnet_threshold", false},
		{"subnet_threshold=65 rejected", func(c *Config) { c.Thresholds.MailBruteForceSubnetThresh = 65 }, "thresholds.mail_bruteforce_subnet_threshold", true},
		{"account_spray=1 rejected", func(c *Config) { c.Thresholds.MailAccountSprayThreshold = 1 }, "thresholds.mail_account_spray_threshold", true},
		{"account_spray=2 accepted", func(c *Config) { c.Thresholds.MailAccountSprayThreshold = 2 }, "thresholds.mail_account_spray_threshold", false},
		{"account_spray=201 rejected", func(c *Config) { c.Thresholds.MailAccountSprayThreshold = 201 }, "thresholds.mail_account_spray_threshold", true},
		{"max_tracked=999 rejected", func(c *Config) { c.Thresholds.MailBruteForceMaxTracked = 999 }, "thresholds.mail_bruteforce_max_tracked", true},
		{"max_tracked=1000 accepted", func(c *Config) { c.Thresholds.MailBruteForceMaxTracked = 1000 }, "thresholds.mail_bruteforce_max_tracked", false},
		{"max_tracked=200001 rejected", func(c *Config) { c.Thresholds.MailBruteForceMaxTracked = 200001 }, "thresholds.mail_bruteforce_max_tracked", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.MailBruteForceThreshold = 5
			cfg.Thresholds.MailBruteForceWindowMin = 10
			cfg.Thresholds.MailBruteForceSuppressMin = 60
			cfg.Thresholds.MailBruteForceSubnetThresh = 8
			cfg.Thresholds.MailAccountSprayThreshold = 12
			cfg.Thresholds.MailBruteForceMaxTracked = 20000
			tc.apply(cfg)

			results := Validate(cfg)
			hasErr := hasResult(results, "error", tc.field)
			if hasErr != tc.wantErr {
				t.Errorf("hasErr = %v, want %v (results=%v)", hasErr, tc.wantErr, results)
			}
		})
	}
}

func TestValidate_DomlogMaxFilesRange(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero uses default", 0, false},
		{"minimum accepted", 1, false},
		{"maximum accepted", 100000, false},
		{"negative rejected", -1, true},
		{"above maximum rejected", 100001, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.DomlogMaxFiles = tc.value

			results := Validate(cfg)
			hasErr := hasResult(results, "error", "thresholds.domlog_max_files")
			if hasErr != tc.wantErr {
				t.Errorf("hasErr = %v, want %v (results=%v)", hasErr, tc.wantErr, results)
			}
		})
	}
}

func TestValidate_CrontabBase64BlobMaxBytesRange(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero uses default", 0, false},
		{"minimum accepted", 1024, false},
		{"maximum accepted", 1048576, false},
		{"mid-range aligned", 32768, false},
		{"below minimum rejected", 1020, true},
		{"above maximum rejected", 1048580, true},
		{"non-multiple-of-4 rejected", 1025, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.CrontabBase64BlobMaxBytes = tc.value

			results := Validate(cfg)
			hasErr := hasResult(results, "error", "thresholds.crontab_base64_blob_max_bytes")
			if hasErr != tc.wantErr {
				t.Errorf("hasErr = %v, want %v (results=%v)", hasErr, tc.wantErr, results)
			}
		})
	}
}

func TestValidate_AccountScanMaxFilesRange(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero uses default", 0, false},
		{"minimum accepted", 1, false},
		{"maximum accepted", 100000, false},
		{"negative rejected", -1, true},
		{"above maximum rejected", 100001, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.AccountScanMaxFiles = tc.value

			results := Validate(cfg)
			hasErr := hasResult(results, "error", "thresholds.account_scan_max_files")
			if hasErr != tc.wantErr {
				t.Errorf("hasErr = %v, want %v (results=%v)", hasErr, tc.wantErr, results)
			}
		})
	}
}

func TestValidate_MailLogTailLinesRange(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero uses default", 0, false},
		{"minimum accepted", 10, false},
		{"too small rejected", 9, true},
		{"maximum accepted", 100000, false},
		{"above maximum rejected", 100001, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.MailLogTailLines = tc.value
			if got := hasResult(Validate(cfg), "error", "thresholds.mail_log_tail_lines"); got != tc.wantErr {
				t.Errorf("hasErr = %v, want %v", got, tc.wantErr)
			}
		})
	}
}

func TestValidate_SyslogMessagesTailLinesRange(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero uses default", 0, false},
		{"minimum accepted", 10, false},
		{"too small rejected", 9, true},
		{"maximum accepted", 100000, false},
		{"above maximum rejected", 100001, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.SyslogMessagesTailLines = tc.value
			if got := hasResult(Validate(cfg), "error", "thresholds.syslog_messages_tail_lines"); got != tc.wantErr {
				t.Errorf("hasErr = %v, want %v", got, tc.wantErr)
			}
		})
	}
}

func TestValidate_CredStuffingDistinctAccountsRange(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero uses default", 0, false},
		{"minimum accepted", 2, false},
		{"default accepted", 5, false},
		{"maximum accepted", 200, false},
		{"too small rejected", 1, true},
		{"negative rejected", -1, true},
		{"above maximum rejected", 201, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.CredStuffingDistinctAccounts = tc.value
			if got := hasResult(Validate(cfg), "error", "thresholds.cred_stuffing_distinct_accounts"); got != tc.wantErr {
				t.Errorf("hasErr = %v, want %v", got, tc.wantErr)
			}
		})
	}
}

func TestValidate_DomlogMaxAgeMinRange(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero uses default", 0, false},
		{"minimum accepted", 1, false},
		{"common production value accepted", 30, false},
		{"maximum accepted", 1440, false},
		{"negative rejected", -1, true},
		{"above maximum rejected", 1441, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.DomlogMaxAgeMin = tc.value

			results := Validate(cfg)
			hasErr := hasResult(results, "error", "thresholds.domlog_max_age_min")
			if hasErr != tc.wantErr {
				t.Errorf("hasErr = %v, want %v (results=%v)", hasErr, tc.wantErr, results)
			}
		})
	}
}

func TestValidate_DomlogTailLinesRange(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero uses default", 0, false},
		{"too small rejected", 9, true},
		{"minimum accepted", 10, false},
		{"maximum accepted", 100000, false},
		{"negative rejected", -1, true},
		{"above maximum rejected", 100001, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.DomlogTailLines = tc.value

			results := Validate(cfg)
			hasErr := hasResult(results, "error", "thresholds.domlog_tail_lines")
			if hasErr != tc.wantErr {
				t.Errorf("hasErr = %v, want %v (results=%v)", hasErr, tc.wantErr, results)
			}
		})
	}
}

func TestValidate_HTTPScannerProfileThresholds(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		field   string
		wantErr bool
	}{
		{"min requests disabled", func(c *Config) { c.Thresholds.HTTPScannerMinRequests = 0 }, "thresholds.http_scanner_min_requests", false},
		{"min requests positive", func(c *Config) { c.Thresholds.HTTPScannerMinRequests = 30 }, "thresholds.http_scanner_min_requests", false},
		{"min requests negative", func(c *Config) { c.Thresholds.HTTPScannerMinRequests = -1 }, "thresholds.http_scanner_min_requests", true},
		{"error percent default", func(c *Config) { c.Thresholds.HTTPScannerErrorPct = 0 }, "thresholds.http_scanner_error_pct", false},
		{"error percent minimum", func(c *Config) { c.Thresholds.HTTPScannerErrorPct = 1 }, "thresholds.http_scanner_error_pct", false},
		{"error percent maximum", func(c *Config) { c.Thresholds.HTTPScannerErrorPct = 100 }, "thresholds.http_scanner_error_pct", false},
		{"error percent negative", func(c *Config) { c.Thresholds.HTTPScannerErrorPct = -1 }, "thresholds.http_scanner_error_pct", true},
		{"error percent above max", func(c *Config) { c.Thresholds.HTTPScannerErrorPct = 101 }, "thresholds.http_scanner_error_pct", true},
		{"distinct paths default", func(c *Config) { c.Thresholds.HTTPScannerMinDistinctPaths = 0 }, "thresholds.http_scanner_min_distinct_paths", false},
		{"distinct paths minimum", func(c *Config) { c.Thresholds.HTTPScannerMinDistinctPaths = 1 }, "thresholds.http_scanner_min_distinct_paths", false},
		{"distinct paths maximum", func(c *Config) { c.Thresholds.HTTPScannerMinDistinctPaths = HTTPScannerMaxDistinctPaths }, "thresholds.http_scanner_min_distinct_paths", false},
		{"distinct paths negative", func(c *Config) { c.Thresholds.HTTPScannerMinDistinctPaths = -1 }, "thresholds.http_scanner_min_distinct_paths", true},
		{"distinct paths above cap", func(c *Config) { c.Thresholds.HTTPScannerMinDistinctPaths = HTTPScannerMaxDistinctPaths + 1 }, "thresholds.http_scanner_min_distinct_paths", true},
		{"status codes default", func(c *Config) { c.Thresholds.HTTPScannerStatusCodes = nil }, "thresholds.http_scanner_status_codes", false},
		{"status codes accepted", func(c *Config) { c.Thresholds.HTTPScannerStatusCodes = []int{404, 403, 301} }, "thresholds.http_scanner_status_codes", false},
		{"status code too low", func(c *Config) { c.Thresholds.HTTPScannerStatusCodes = []int{99} }, "thresholds.http_scanner_status_codes", true},
		{"status code too high", func(c *Config) { c.Thresholds.HTTPScannerStatusCodes = []int{600} }, "thresholds.http_scanner_status_codes", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseValidationConfig()
			tc.mutate(cfg)
			results := Validate(cfg)
			if got := hasResult(results, "error", tc.field); got != tc.wantErr {
				t.Errorf("has error on %s = %v, want %v; results=%v", tc.field, got, tc.wantErr, results)
			}
		})
	}
}

func TestValidate_HTTPScannerAction(t *testing.T) {
	cases := []struct {
		action  string
		wantErr bool
	}{
		{"", false},
		{"challenge", false},
		{"block", false},
		{"captcha", true},
		{"BLOCK", true},
	}
	for _, tc := range cases {
		t.Run("action="+tc.action, func(t *testing.T) {
			cfg := baseValidationConfig()
			cfg.AutoResponse.HTTPScannerAction = tc.action
			results := Validate(cfg)
			if got := hasResult(results, "error", "auto_response.http_scanner_action"); got != tc.wantErr {
				t.Errorf("has error = %v, want %v; results=%v", got, tc.wantErr, results)
			}
		})
	}
}

func TestValidateDeepSectionAlertsOnlyProbesAlerts(t *testing.T) {
	cfg := &Config{}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.SMTP = "127.0.0.1:1" // likely-unreachable; probe runs

	// Also wire up a broken email_av section that would fail if we accidentally
	// ran its deep probe.
	cfg.EmailAV.Enabled = true
	cfg.EmailAV.ClamdSocket = "/nonexistent/clamd.sock"

	// Running ValidateDeepSection(cfg, "alerts") must exercise only the alerts
	// probes and must not touch email_av.
	results := ValidateDeepSection(cfg, "alerts")
	for _, r := range results {
		if strings.HasPrefix(r.Field, "email_av") {
			t.Errorf("alerts section triggered email_av probe: %v", r)
		}
	}

	// Cross-check: asking for email_av should include email_av results.
	emailAVResults := ValidateDeepSection(cfg, "email_av")
	for _, r := range emailAVResults {
		if strings.HasPrefix(r.Field, "alerts") {
			t.Errorf("email_av section triggered alerts probe: %v", r)
		}
	}
}

func TestValidateDeepSectionChallengeChecksPortAvailability(t *testing.T) {
	cfg := &Config{}
	cfg.Challenge.ListenPort = 8439
	// The challenge case has no deep probe in v1 (probeListenPortAvailable
	// is not yet implemented). ValidateDeepSection must return nil without
	// panic, not leak probes from other sections.
	results := ValidateDeepSection(cfg, "challenge")
	if len(results) != 0 {
		t.Errorf("challenge deep section expected 0 results (no probe implemented), got %d: %v", len(results), results)
	}
}

func TestValidate_PHPRelayBounds(t *testing.T) {
	cfg := &Config{}
	cfg.EmailProtection.PHPRelay.Enabled = true
	cfg.EmailProtection.PHPRelay.RateWindowMin = 5
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 5
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 0 // auto-derive
	cfg.EmailProtection.PHPRelay.ReputationFailuresPer24h = 3
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	cfg.EmailProtection.PHPRelay.BaselineSigma = 3.0
	cfg.EmailProtection.PHPRelay.BaselineObservationDays = 7
	cfg.EmailProtection.PHPRelay.PoliciesDir = t.TempDir()

	res := Validate(cfg)
	for _, r := range res {
		if r.Level == "error" && strings.HasPrefix(r.Field, "email_protection.php_relay") {
			t.Errorf("unexpected php_relay error: %+v", r)
		}
	}

	// Invalid: rate_window_min out of range
	cfg.EmailProtection.PHPRelay.RateWindowMin = 999
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.rate_window_min") {
		t.Errorf("expected error for out-of-range rate_window_min, got %+v", res)
	}

	// Tighter bounds drop edge values that the laxer initial draft accepted.
	cfg.EmailProtection.PHPRelay.RateWindowMin = 5 // reset to valid
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 200
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.header_score_volume_min") {
		t.Errorf("header_score_volume_min=200 must be invalid (>100), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 1
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.header_score_volume_min") {
		t.Errorf("header_score_volume_min=1 must be invalid (<2), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 5 // reset to valid

	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 5000
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.absolute_volume_per_hour") {
		t.Errorf("absolute_volume_per_hour=5000 must be invalid (>1000), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30 // reset to valid

	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 9000
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.account_volume_per_hour") {
		t.Errorf("account_volume_per_hour=9000 must be invalid (>5000), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 0 // reset to valid (auto-derive)

	cfg.EmailProtection.PHPRelay.ReputationFailuresPer24h = 100
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.reputation_failures_per_24h") {
		t.Errorf("reputation_failures_per_24h=100 must be invalid (>50), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.ReputationFailuresPer24h = 3 // reset to valid

	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 50
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.fanout_distinct_scripts") {
		t.Errorf("fanout_distinct_scripts=50 must be invalid (>20), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3 // reset to valid

	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 101
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.fanout_distinct_recipients") {
		t.Errorf("fanout_distinct_recipients=101 must be invalid (>100), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 0 // reset to valid (gate disabled)
	res = Validate(cfg)
	if hasErrorOnField(res, "email_protection.php_relay.fanout_distinct_recipients") {
		t.Errorf("fanout_distinct_recipients=0 must be valid (disabled), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5 // reset to valid

	cfg.EmailProtection.PHPRelay.BaselineSigma = 1.5
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.baseline_sigma") {
		t.Errorf("baseline_sigma=1.5 must be invalid (<2.0), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.BaselineSigma = 8.0
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.baseline_sigma") {
		t.Errorf("baseline_sigma=8.0 must be invalid (>6.0), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.BaselineSigma = 3.0 // reset to valid

	cfg.EmailProtection.PHPRelay.BaselineObservationDays = 60
	res = Validate(cfg)
	if !hasErrorOnField(res, "email_protection.php_relay.baseline_observation_days") {
		t.Errorf("baseline_observation_days=60 must be invalid (>30), got %+v", res)
	}
	cfg.EmailProtection.PHPRelay.BaselineObservationDays = 7 // reset to valid

	cfg.AutoResponse.PHPRelay.MaxActionsPerMinute = 5000
	res = Validate(cfg)
	if !hasErrorOnField(res, "auto_response.php_relay.max_actions_per_minute") {
		t.Errorf("max_actions_per_minute=5000 must be invalid (>600), got %+v", res)
	}
	cfg.AutoResponse.PHPRelay.MaxActionsPerMinute = 60

	cfg.AutoResponse.MaxBlocksPerHour = -1
	res = Validate(cfg)
	if !hasErrorOnField(res, "auto_response.max_blocks_per_hour") {
		t.Errorf("max_blocks_per_hour=-1 must be invalid, got %+v", res)
	}
}

// ValidationResult exposes a Field, not a Key. Match the existing struct
// shape in internal/config/validate.go.
func hasErrorOnField(rs []ValidationResult, field string) bool {
	for _, r := range rs {
		if r.Level == "error" && r.Field == field {
			return true
		}
	}
	return false
}

func TestValidate_SMTPBruteForceRanges(t *testing.T) {
	cases := []struct {
		name    string
		apply   func(*Config)
		field   string
		wantErr bool
	}{
		{"threshold=1 rejected", func(c *Config) { c.Thresholds.SMTPBruteForceThreshold = 1 }, "thresholds.smtp_bruteforce_threshold", true},
		{"threshold=2 accepted", func(c *Config) { c.Thresholds.SMTPBruteForceThreshold = 2 }, "thresholds.smtp_bruteforce_threshold", false},
		{"threshold=51 rejected", func(c *Config) { c.Thresholds.SMTPBruteForceThreshold = 51 }, "thresholds.smtp_bruteforce_threshold", true},
		{"window=0 accepted", func(c *Config) { c.Thresholds.SMTPBruteForceWindowMin = 0 }, "thresholds.smtp_bruteforce_window_min", false},
		{"window=61 rejected", func(c *Config) { c.Thresholds.SMTPBruteForceWindowMin = 61 }, "thresholds.smtp_bruteforce_window_min", true},
		{"suppress=0 accepted", func(c *Config) { c.Thresholds.SMTPBruteForceSuppressMin = 0 }, "thresholds.smtp_bruteforce_suppress_min", false},
		{"suppress=1441 rejected", func(c *Config) { c.Thresholds.SMTPBruteForceSuppressMin = 1441 }, "thresholds.smtp_bruteforce_suppress_min", true},
		{"subnet_threshold=1 rejected", func(c *Config) { c.Thresholds.SMTPBruteForceSubnetThresh = 1 }, "thresholds.smtp_bruteforce_subnet_threshold", true},
		{"subnet_threshold=65 rejected", func(c *Config) { c.Thresholds.SMTPBruteForceSubnetThresh = 65 }, "thresholds.smtp_bruteforce_subnet_threshold", true},
		{"account_spray=1 rejected", func(c *Config) { c.Thresholds.SMTPAccountSprayThreshold = 1 }, "thresholds.smtp_account_spray_threshold", true},
		{"account_spray=201 rejected", func(c *Config) { c.Thresholds.SMTPAccountSprayThreshold = 201 }, "thresholds.smtp_account_spray_threshold", true},
		{"max_tracked=999 rejected", func(c *Config) { c.Thresholds.SMTPBruteForceMaxTracked = 999 }, "thresholds.smtp_bruteforce_max_tracked", true},
		{"max_tracked=200001 rejected", func(c *Config) { c.Thresholds.SMTPBruteForceMaxTracked = 200001 }, "thresholds.smtp_bruteforce_max_tracked", true},
		{"window=1 accepted", func(c *Config) { c.Thresholds.SMTPBruteForceWindowMin = 1 }, "thresholds.smtp_bruteforce_window_min", false},
		{"suppress=1 accepted", func(c *Config) { c.Thresholds.SMTPBruteForceSuppressMin = 1 }, "thresholds.smtp_bruteforce_suppress_min", false},
		{"subnet_threshold=2 accepted", func(c *Config) { c.Thresholds.SMTPBruteForceSubnetThresh = 2 }, "thresholds.smtp_bruteforce_subnet_threshold", false},
		{"account_spray=2 accepted", func(c *Config) { c.Thresholds.SMTPAccountSprayThreshold = 2 }, "thresholds.smtp_account_spray_threshold", false},
		{"max_tracked=1000 accepted", func(c *Config) { c.Thresholds.SMTPBruteForceMaxTracked = 1000 }, "thresholds.smtp_bruteforce_max_tracked", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Hostname: "test"}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"admin@test.com"}
			cfg.Alerts.Email.SMTP = "localhost:25"
			cfg.Alerts.Email.From = "csm@test.com"
			cfg.Alerts.MaxPerHour = 10
			cfg.Thresholds.SMTPBruteForceThreshold = 5
			cfg.Thresholds.SMTPBruteForceWindowMin = 10
			cfg.Thresholds.SMTPBruteForceSuppressMin = 60
			cfg.Thresholds.SMTPBruteForceSubnetThresh = 8
			cfg.Thresholds.SMTPAccountSprayThreshold = 12
			cfg.Thresholds.SMTPBruteForceMaxTracked = 20000
			tc.apply(cfg)

			results := Validate(cfg)
			hasErr := hasResult(results, "error", tc.field)
			if hasErr != tc.wantErr {
				t.Errorf("hasErr = %v, want %v (results=%v)", hasErr, tc.wantErr, results)
			}
		})
	}
}

func TestValidateDirectSMTPEgressBounds(t *testing.T) {
	cfg := &Config{Hostname: "test"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"admin@test.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@test.com"
	cfg.Alerts.MaxPerHour = 10
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Backend = "auto"
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}

	results := Validate(cfg)
	if hasResult(results, "error", "detection.direct_smtp_egress") {
		t.Fatalf("valid direct_smtp_egress config rejected: %v", results)
	}

	cfg.Detection.DirectSMTPEgress.Ports = []int{65561}
	results = Validate(cfg)
	if !hasResult(results, "error", "detection.direct_smtp_egress") {
		t.Fatalf("invalid direct_smtp_egress port was not rejected: %v", results)
	}

	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	cfg.Detection.DirectSMTPEgress.Backend = "sideways"
	results = Validate(cfg)
	if !hasResult(results, "error", "detection.direct_smtp_egress") {
		t.Fatalf("invalid direct_smtp_egress backend was not rejected: %v", results)
	}
}

func TestValidateBPFEnforcementRejectsEnableWithoutFeature(t *testing.T) {
	cfg := &Config{Hostname: "h"}
	cfg.BPFEnforcement.Enabled = true
	// No DirectSMTPEgress, no other feature flag set.
	results := Validate(cfg)
	if !hasResult(results, "error", "bpf_enforcement") {
		t.Errorf("enforcement enabled with no feature gate must fail validation: %v", results)
	}
}

func TestValidateBPFEnforcementAcceptsEnableWithFeature(t *testing.T) {
	cfg := &Config{Hostname: "h"}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	cfg.Detection.DirectSMTPEgress.Enabled = true
	results := Validate(cfg)
	if hasResult(results, "error", "bpf_enforcement") {
		t.Errorf("expected pass; got %v", results)
	}
}

func TestValidateBPFEnforcementRequiresDetectorEnabled(t *testing.T) {
	cfg := &Config{Hostname: "h"}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	cfg.Detection.DirectSMTPEgress.Enabled = false
	results := Validate(cfg)
	if !hasResult(results, "error", "bpf_enforcement") {
		t.Errorf("enforcement on a disabled detector must fail validation: %v", results)
	}
}

func TestValidateBPFEnforcementRejectsLegacyConnectionTracker(t *testing.T) {
	cfg := &Config{Hostname: "h"}
	cfg.Detection.ConnectionTrackerBackend = "legacy"
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	results := Validate(cfg)
	if !hasResult(results, "error", "bpf_enforcement") {
		t.Fatalf("BPF enforcement with legacy connection tracker must fail: %v", results)
	}
}

func TestValidateBPFEnforcementRejectsLegacyDirectSMTPBackend(t *testing.T) {
	cfg := &Config{Hostname: "h"}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Backend = "legacy"
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	results := Validate(cfg)
	if !hasResult(results, "error", "bpf_enforcement") {
		t.Fatalf("BPF enforcement with legacy direct SMTP backend must fail: %v", results)
	}
}
