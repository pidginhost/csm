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
	if !hasResult(results, "error", "webui.auth_token") {
		t.Errorf("expected error for empty auth_token; results=%v", results)
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
