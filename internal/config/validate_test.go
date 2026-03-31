package config

import (
	"testing"

	"github.com/pidginhost/cpanel-security-monitor/internal/firewall"
)

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
