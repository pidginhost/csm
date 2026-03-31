package config

import (
	"fmt"
	"strings"
	"time"
)

// ValidationResult represents a single validation finding.
type ValidationResult struct {
	Level   string // "error", "warn", "ok"
	Field   string // dotted path matching YAML keys
	Message string
}

// String implements the Stringer interface for nice printing.
func (v ValidationResult) String() string {
	return fmt.Sprintf("[%s] %s: %s", strings.ToUpper(v.Level), v.Field, v.Message)
}

// Validate checks the config for errors, warnings, and emits OK for valid sections.
func Validate(cfg *Config) []ValidationResult {
	var results []ValidationResult

	// --- Hostname ---
	if cfg.Hostname == "" || cfg.Hostname == "SET_HOSTNAME_HERE" {
		results = append(results, ValidationResult{"error", "hostname", "hostname is not set"})
	} else {
		results = append(results, ValidationResult{"ok", "hostname", "hostname is set"})
	}

	// --- Alerts ---
	if !cfg.Alerts.Email.Enabled && !cfg.Alerts.Webhook.Enabled {
		results = append(results, ValidationResult{"error", "alerts", "no alert method enabled (enable email or webhook)"})
	}

	// --- Email alerts ---
	if cfg.Alerts.Email.Enabled {
		if len(cfg.Alerts.Email.To) == 0 {
			results = append(results, ValidationResult{"error", "alerts.email.to", "email alerts enabled but no recipients configured"})
		} else {
			valid := true
			for _, to := range cfg.Alerts.Email.To {
				if to == "SET_EMAIL_HERE" || !strings.Contains(to, "@") {
					results = append(results, ValidationResult{"error", "alerts.email.to", fmt.Sprintf("invalid email recipient: %s", to)})
					valid = false
				}
			}
			if valid {
				results = append(results, ValidationResult{"ok", "alerts.email.to", "email recipients configured"})
			}
		}

		if cfg.Alerts.Email.From == "" {
			results = append(results, ValidationResult{"error", "alerts.email.from", "email alerts enabled but no from address configured"})
		}

		if cfg.Alerts.Email.SMTP == "" {
			results = append(results, ValidationResult{"error", "alerts.email.smtp", "email alerts enabled but no SMTP server configured"})
		} else {
			results = append(results, ValidationResult{"ok", "alerts.email.smtp", "SMTP server configured"})
		}
	}

	// --- Webhook ---
	if cfg.Alerts.Webhook.Enabled {
		if cfg.Alerts.Webhook.URL == "" {
			results = append(results, ValidationResult{"error", "alerts.webhook.url", "webhook alerts enabled but no URL configured"})
		} else {
			results = append(results, ValidationResult{"ok", "alerts.webhook.url", "webhook URL configured"})
		}
	}

	// --- Heartbeat ---
	if cfg.Alerts.Heartbeat.Enabled {
		if cfg.Alerts.Heartbeat.URL == "" {
			results = append(results, ValidationResult{"error", "alerts.heartbeat.url", "heartbeat enabled but no URL configured"})
		} else {
			results = append(results, ValidationResult{"ok", "alerts.heartbeat.url", "heartbeat URL configured"})
		}
	}

	// --- MaxPerHour ---
	if cfg.Alerts.MaxPerHour <= 0 {
		results = append(results, ValidationResult{"error", "alerts.max_per_hour", "max_per_hour must be > 0"})
	}

	// --- WebUI ---
	if cfg.WebUI.Enabled {
		if cfg.WebUI.AuthToken == "" {
			results = append(results, ValidationResult{"error", "webui.auth_token", "webui enabled but no auth_token configured"})
		}
	}
	if cfg.WebUI.Listen != "" {
		results = append(results, ValidationResult{"ok", "webui.listen", "webui listen address configured"})
	}

	// --- Trusted countries ---
	for _, cc := range cfg.Suppressions.TrustedCountries {
		if len(cc) != 2 {
			results = append(results, ValidationResult{"error", "suppressions.trusted_countries", fmt.Sprintf("invalid country code: %q (expected 2-letter ISO code)", cc)})
		}
	}

	// --- Duration fields (only check if non-empty) ---
	if cfg.AutoResponse.BlockExpiry != "" {
		if _, err := time.ParseDuration(cfg.AutoResponse.BlockExpiry); err != nil {
			results = append(results, ValidationResult{"error", "auto_response.block_expiry", fmt.Sprintf("unparseable duration: %s", cfg.AutoResponse.BlockExpiry)})
		}
	}
	if cfg.Signatures.UpdateInterval != "" {
		if _, err := time.ParseDuration(cfg.Signatures.UpdateInterval); err != nil {
			results = append(results, ValidationResult{"error", "signatures.update_interval", fmt.Sprintf("unparseable duration: %s", cfg.Signatures.UpdateInterval)})
		}
	}
	if cfg.EmailAV.ScanTimeout != "" {
		if _, err := time.ParseDuration(cfg.EmailAV.ScanTimeout); err != nil {
			results = append(results, ValidationResult{"error", "email_av.scan_timeout", fmt.Sprintf("unparseable duration: %s", cfg.EmailAV.ScanTimeout)})
		}
	}
	if cfg.GeoIP.UpdateInterval != "" {
		if _, err := time.ParseDuration(cfg.GeoIP.UpdateInterval); err != nil {
			results = append(results, ValidationResult{"error", "geoip.update_interval", fmt.Sprintf("unparseable duration: %s", cfg.GeoIP.UpdateInterval)})
		}
	}
	if cfg.AutoResponse.PermBlockInterval != "" {
		if _, err := time.ParseDuration(cfg.AutoResponse.PermBlockInterval); err != nil {
			results = append(results, ValidationResult{"error", "auto_response.permblock_interval", fmt.Sprintf("unparseable duration: %s", cfg.AutoResponse.PermBlockInterval)})
		}
	}

	// --- Firewall ---
	if cfg.Firewall != nil && cfg.Firewall.Enabled {
		if cfg.Firewall.ConnRateLimit <= 0 {
			results = append(results, ValidationResult{"error", "firewall.conn_rate_limit", "conn_rate_limit must be > 0 when firewall enabled"})
		}
		if cfg.Firewall.ConnLimit < 0 {
			results = append(results, ValidationResult{"error", "firewall.conn_limit", "conn_limit must be >= 0 when firewall enabled (0 = disabled)"})
		}
		if cfg.Firewall.ConnRateLimit > 0 && cfg.Firewall.ConnLimit >= 0 {
			results = append(results, ValidationResult{"ok", "firewall", "firewall configuration valid"})
		}
	}

	// --- Challenge ---
	if cfg.Challenge.Difficulty < 0 || cfg.Challenge.Difficulty > 5 {
		results = append(results, ValidationResult{"error", "challenge.difficulty", fmt.Sprintf("difficulty must be 0-5, got %d", cfg.Challenge.Difficulty)})
	}

	// --- EmailAV ---
	if cfg.EmailAV.Enabled && cfg.EmailAV.MaxAttachmentSize <= 0 {
		results = append(results, ValidationResult{"error", "email_av.max_attachment_size", "max_attachment_size must be > 0 when email_av enabled"})
	}

	// --- Warnings ---
	results = append(results, validateWarnings(cfg)...)

	return results
}

// validateWarnings checks for non-fatal configuration issues.
func validateWarnings(cfg *Config) []ValidationResult {
	var results []ValidationResult

	// GeoIP credentials set but auto_update explicitly false
	if cfg.GeoIP.AccountID != "" && cfg.GeoIP.LicenseKey != "" {
		if cfg.GeoIP.AutoUpdate != nil && !*cfg.GeoIP.AutoUpdate {
			results = append(results, ValidationResult{"warn", "geoip", "GeoIP credentials configured but auto_update is disabled"})
		}
	}

	// Auto-response enabled but no actions
	if cfg.AutoResponse.Enabled {
		if !cfg.AutoResponse.KillProcesses && !cfg.AutoResponse.QuarantineFiles && !cfg.AutoResponse.BlockIPs {
			results = append(results, ValidationResult{"warn", "auto_response", "auto_response enabled but no actions configured (kill/quarantine/block all false)"})
		}
	}

	// Infra IPs both empty
	fwInfra := cfg.Firewall != nil && len(cfg.Firewall.InfraIPs) > 0
	topInfra := len(cfg.InfraIPs) > 0
	if !topInfra && !fwInfra {
		results = append(results, ValidationResult{"warn", "infra_ips", "no infra_ips configured in either top-level or firewall section"})
	}

	// Firewall enabled but no infra IPs (lockout risk)
	if cfg.Firewall != nil && cfg.Firewall.Enabled && !topInfra && !fwInfra {
		results = append(results, ValidationResult{"warn", "firewall", "firewall enabled but no infra_ips configured — risk of lockout"})
	}

	// Netblock threshold too low
	if cfg.AutoResponse.NetBlock && cfg.AutoResponse.NetBlockThreshold < 2 {
		results = append(results, ValidationResult{"warn", "auto_response.netblock_threshold", fmt.Sprintf("netblock_threshold=%d is very low (< 2), may cause excessive blocking", cfg.AutoResponse.NetBlockThreshold)})
	}

	// Permblock count too low
	if cfg.AutoResponse.PermBlock && cfg.AutoResponse.PermBlockCount < 2 {
		results = append(results, ValidationResult{"warn", "auto_response.permblock_count", fmt.Sprintf("permblock_count=%d is very low (< 2), may permanently block too quickly", cfg.AutoResponse.PermBlockCount)})
	}

	return results
}
