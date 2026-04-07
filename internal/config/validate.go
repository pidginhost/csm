package config

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
		results = append(results, ValidationResult{"ok", "hostname", cfg.Hostname})
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
				results = append(results, ValidationResult{"ok", "alerts.email.to", strings.Join(cfg.Alerts.Email.To, ", ")})
			}
		}

		if cfg.Alerts.Email.From == "" {
			results = append(results, ValidationResult{"error", "alerts.email.from", "email alerts enabled but no from address configured"})
		}

		if cfg.Alerts.Email.SMTP == "" {
			results = append(results, ValidationResult{"error", "alerts.email.smtp", "email alerts enabled but no SMTP server configured"})
		} else {
			results = append(results, ValidationResult{"ok", "alerts.email.smtp", cfg.Alerts.Email.SMTP})
		}
	}

	// --- Webhook ---
	if cfg.Alerts.Webhook.Enabled {
		if cfg.Alerts.Webhook.URL == "" {
			results = append(results, ValidationResult{"error", "alerts.webhook.url", "webhook alerts enabled but no URL configured"})
		} else {
			results = append(results, ValidationResult{"ok", "alerts.webhook.url", cfg.Alerts.Webhook.URL})
		}
	}

	// --- Heartbeat ---
	if cfg.Alerts.Heartbeat.Enabled {
		if cfg.Alerts.Heartbeat.URL == "" {
			results = append(results, ValidationResult{"error", "alerts.heartbeat.url", "heartbeat enabled but no URL configured"})
		} else {
			results = append(results, ValidationResult{"ok", "alerts.heartbeat.url", cfg.Alerts.Heartbeat.URL})
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
	if cfg.WebUI.Enabled && cfg.WebUI.AuthToken != "" {
		results = append(results, ValidationResult{"ok", "webui", fmt.Sprintf("listening on %s", cfg.WebUI.Listen)})
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
			results = append(results, ValidationResult{"ok", "firewall", fmt.Sprintf("enabled, conn_rate_limit=%d, conn_limit=%d", cfg.Firewall.ConnRateLimit, cfg.Firewall.ConnLimit)})
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

	// --- EmailProtection ---
	if cfg.EmailProtection.RateWarnThreshold > 0 && cfg.EmailProtection.RateWarnThreshold < 10 {
		results = append(results, ValidationResult{"warn", "email_protection.rate_warn_threshold", "rate_warn_threshold < 10 may cause excessive alerts"})
	}
	if cfg.EmailProtection.RateCritThreshold > 0 && cfg.EmailProtection.RateCritThreshold <= cfg.EmailProtection.RateWarnThreshold {
		results = append(results, ValidationResult{"error", "email_protection.rate_crit_threshold", "rate_crit_threshold must be > rate_warn_threshold"})
	}
	if cfg.EmailProtection.RateWindowMin > 0 && (cfg.EmailProtection.RateWindowMin < 5 || cfg.EmailProtection.RateWindowMin > 60) {
		results = append(results, ValidationResult{"error", "email_protection.rate_window_min", "rate_window_min must be between 5 and 60"})
	}
	if cfg.EmailProtection.PasswordCheckIntervalMin > 0 && cfg.EmailProtection.PasswordCheckIntervalMin < 60 {
		results = append(results, ValidationResult{"warn", "email_protection.password_check_interval_min", "password_check_interval_min < 60 may cause high CPU from doveadm"})
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
		results = append(results, ValidationResult{"warn", "firewall", "firewall enabled but no infra_ips configured - risk of lockout"})
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

// ValidateDeep performs connectivity probes against configured services.
// It does NOT call Validate(); the caller should invoke both separately.
func ValidateDeep(cfg *Config) []ValidationResult {
	var results []ValidationResult

	// State directory
	results = append(results, probeStatePath(cfg.StatePath)...)

	// Signature rules directory
	if cfg.Signatures.RulesDir != "" {
		results = append(results, probeRulesDir(cfg.Signatures.RulesDir)...)
	}

	// SMTP
	if cfg.Alerts.Email.Enabled && cfg.Alerts.Email.SMTP != "" {
		results = append(results, probeSMTP(cfg.Alerts.Email.SMTP)...)
	}

	// ClamAV socket
	if cfg.EmailAV.Enabled && cfg.EmailAV.ClamdSocket != "" {
		results = append(results, probeClamd(cfg.EmailAV.ClamdSocket)...)
	}

	// TLS cert/key (only when custom paths set)
	if cfg.WebUI.TLSCert != "" {
		if _, err := os.Stat(cfg.WebUI.TLSCert); err != nil {
			results = append(results, ValidationResult{"error", "webui.tls_cert", fmt.Sprintf("file not found: %s", cfg.WebUI.TLSCert)})
		} else {
			results = append(results, ValidationResult{"ok", "webui.tls_cert", cfg.WebUI.TLSCert})
		}
	}
	if cfg.WebUI.TLSKey != "" {
		if _, err := os.Stat(cfg.WebUI.TLSKey); err != nil {
			results = append(results, ValidationResult{"error", "webui.tls_key", fmt.Sprintf("file not found: %s", cfg.WebUI.TLSKey)})
		} else {
			results = append(results, ValidationResult{"ok", "webui.tls_key", cfg.WebUI.TLSKey})
		}
	}

	// Webhook
	if cfg.Alerts.Webhook.Enabled && cfg.Alerts.Webhook.URL != "" {
		results = append(results, probeWebhook(cfg.Alerts.Webhook.URL)...)
	}

	// GeoIP database files
	if cfg.GeoIP.AccountID != "" && cfg.GeoIP.LicenseKey != "" && len(cfg.GeoIP.Editions) > 0 {
		results = append(results, probeGeoIPDBs(cfg.StatePath, cfg.GeoIP.Editions)...)
	}

	return results
}

// probeStatePath checks that the state directory exists and is writable.
func probeStatePath(path string) []ValidationResult {
	info, err := os.Stat(path)
	if err != nil {
		return []ValidationResult{{"error", "state_path", fmt.Sprintf("directory not found: %s", path)}}
	}
	if !info.IsDir() {
		return []ValidationResult{{"error", "state_path", fmt.Sprintf("not a directory: %s", path)}}
	}

	probe := filepath.Join(path, ".csm-validate-probe")
	f, err := os.Create(probe)
	if err != nil {
		return []ValidationResult{{"error", "state_path", fmt.Sprintf("directory not writable: %s", path)}}
	}
	f.Close()
	os.Remove(probe)

	return []ValidationResult{{"ok", "state_path", path}}
}

// probeRulesDir checks that the rules directory exists and contains rule files.
func probeRulesDir(path string) []ValidationResult {
	info, err := os.Stat(path)
	if err != nil {
		return []ValidationResult{{"error", "signatures.rules_dir", fmt.Sprintf("directory not found: %s", path)}}
	}
	if !info.IsDir() {
		return []ValidationResult{{"error", "signatures.rules_dir", fmt.Sprintf("not a directory: %s", path)}}
	}

	// Check for rule files
	for _, pattern := range []string{"*.yaml", "*.yml", "*.yar", "*.yara"} {
		matches, _ := filepath.Glob(filepath.Join(path, pattern))
		if len(matches) > 0 {
			return []ValidationResult{{"ok", "signatures.rules_dir", fmt.Sprintf("%s (%d rule files)", path, len(matches))}}
		}
	}

	return []ValidationResult{{"error", "signatures.rules_dir", fmt.Sprintf("no rule files (.yaml/.yml/.yar/.yara) found in %s", path)}}
}

// probeSMTP attempts a TCP dial to the SMTP server.
func probeSMTP(addr string) []ValidationResult {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return []ValidationResult{{"error", "alerts.email.smtp", fmt.Sprintf("cannot connect to %s: %v", addr, err)}}
	}
	_ = conn.Close()
	return []ValidationResult{{"ok", "alerts.email.smtp", fmt.Sprintf("connected to %s", addr)}}
}

// probeClamd attempts to connect to the ClamAV unix socket.
func probeClamd(socket string) []ValidationResult {
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return []ValidationResult{{"error", "email_av.clamd_socket", fmt.Sprintf("cannot connect to %s: %v", socket, err)}}
	}
	_ = conn.Close()
	return []ValidationResult{{"ok", "email_av.clamd_socket", fmt.Sprintf("connected to %s", socket)}}
}

// probeWebhook performs an HTTP HEAD request to verify the webhook endpoint is reachable.
// DNS/TCP/TLS failures are errors; HTTP status codes (even 401/403/404/405) mean reachable.
func probeWebhook(url string) []ValidationResult {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Head(url)
	if err != nil {
		return []ValidationResult{{"error", "alerts.webhook.url", fmt.Sprintf("cannot reach %s: %v", url, err)}}
	}
	resp.Body.Close()
	return []ValidationResult{{"ok", "alerts.webhook.url", fmt.Sprintf("reachable (HTTP %d)", resp.StatusCode)}}
}

// probeGeoIPDBs checks that expected GeoIP database files exist on disk.
func probeGeoIPDBs(statePath string, editions []string) []ValidationResult {
	var results []ValidationResult
	allOK := true
	for _, edition := range editions {
		dbPath := filepath.Join(statePath, "geoip", edition+".mmdb")
		if _, err := os.Stat(dbPath); err != nil {
			results = append(results, ValidationResult{"error", "geoip", fmt.Sprintf("database not found: %s", dbPath)})
			allOK = false
		}
	}
	if allOK {
		results = append(results, ValidationResult{"ok", "geoip", fmt.Sprintf("all %d edition databases present", len(editions))})
	}
	return results
}
