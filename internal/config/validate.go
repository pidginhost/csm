package config

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/sshdconf"
	"golang.org/x/text/language"
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
		switch cfg.Alerts.Webhook.Type {
		case "", "slack", "discord", "generic", "phpanel":
		default:
			results = append(results, ValidationResult{"error", "alerts.webhook.type", fmt.Sprintf("unknown webhook type %q", cfg.Alerts.Webhook.Type)})
		}
		if cfg.Alerts.Webhook.Type == "phpanel" {
			secret := cfg.Alerts.Webhook.HMACSecret
			if cfg.Alerts.Webhook.HMACSecretEnv != "" {
				if v := os.Getenv(cfg.Alerts.Webhook.HMACSecretEnv); v != "" {
					secret = v
				}
			}
			if secret == "" {
				field := "alerts.webhook.hmac_secret"
				if cfg.Alerts.Webhook.HMACSecretEnv != "" {
					field = "alerts.webhook.hmac_secret_env"
				}
				results = append(results, ValidationResult{"error", field, "phpanel webhook enabled but no HMAC secret configured"})
			}
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
		if err := validateWebUITokens(cfg); err != nil {
			results = append(results, ValidationResult{"error", "webui.tokens", err.Error()})
		}
		tokenCount, adminCount := webUITokenCounts(cfg)
		if tokenCount == 0 {
			results = append(results, ValidationResult{"error", "webui.tokens", "webui enabled but no auth token configured"})
		} else {
			results = append(results, ValidationResult{"ok", "webui", fmt.Sprintf("listening on %s", cfg.WebUI.Listen)})
			if adminCount == 0 {
				results = append(results, ValidationResult{"warn", "webui.tokens", "no admin-scope token configured; browser login and admin API calls are disabled"})
			}
		}
	}

	// --- Trusted countries ---
	for _, cc := range cfg.Suppressions.TrustedCountries {
		if len(cc) != 2 {
			results = append(results, ValidationResult{"error", "suppressions.trusted_countries", fmt.Sprintf("invalid country code: %q (expected 2-letter ISO code)", cc)})
		}
	}

	// --- Block digest ---
	switch cfg.Alerts.BlockDigest.SendOn {
	case "", "any", "customer":
	default:
		results = append(results, ValidationResult{"error", "alerts.block_digest.send_on", fmt.Sprintf("unknown send_on %q (want any|customer)", cfg.Alerts.BlockDigest.SendOn)})
	}
	switch cfg.Alerts.BlockDigest.Channel {
	case "":
		if cfg.Alerts.BlockDigest.Enabled && !cfg.Alerts.Email.Enabled && !cfg.Alerts.Webhook.Enabled {
			results = append(results, ValidationResult{"error", "alerts.block_digest.channel", "empty channel requires email or webhook alerts to be enabled"})
		}
	case "email":
		if cfg.Alerts.BlockDigest.Enabled && !cfg.Alerts.Email.Enabled {
			results = append(results, ValidationResult{"error", "alerts.block_digest.channel", "channel email requires email alerts to be enabled"})
		}
	case "webhook":
		if cfg.Alerts.BlockDigest.Enabled && !cfg.Alerts.Webhook.Enabled {
			results = append(results, ValidationResult{"error", "alerts.block_digest.channel", "channel webhook requires webhook alerts to be enabled"})
		}
	default:
		results = append(results, ValidationResult{"error", "alerts.block_digest.channel", fmt.Sprintf("unknown channel %q (want email|webhook)", cfg.Alerts.BlockDigest.Channel)})
	}
	if cfg.Alerts.BlockDigest.Interval != "" {
		if d, err := time.ParseDuration(cfg.Alerts.BlockDigest.Interval); err != nil {
			results = append(results, ValidationResult{"error", "alerts.block_digest.interval", fmt.Sprintf("unparseable duration: %s", cfg.Alerts.BlockDigest.Interval)})
		} else if d <= 0 {
			results = append(results, ValidationResult{"error", "alerts.block_digest.interval", "interval must be > 0"})
		}
	}
	for _, cc := range cfg.Alerts.BlockDigest.Countries {
		if len(cc) != 2 {
			results = append(results, ValidationResult{"error", "alerts.block_digest.countries", fmt.Sprintf("invalid country code: %q (expected 2-letter ISO code)", cc)})
		}
	}
	if cfg.Alerts.BlockDigest.MinBlock < 0 {
		results = append(results, ValidationResult{"error", "alerts.block_digest.min_block", "min_block must be >= 0"})
	}

	// --- Duration fields (only check if non-empty) ---
	if cfg.AutoResponse.BlockExpiry != "" {
		if _, err := time.ParseDuration(cfg.AutoResponse.BlockExpiry); err != nil {
			results = append(results, ValidationResult{"error", "auto_response.block_expiry", fmt.Sprintf("unparseable duration: %s", cfg.AutoResponse.BlockExpiry)})
		}
	}
	if v := strings.ToLower(strings.TrimSpace(cfg.AutoResponse.VirtualPatchExposedFiles)); v != "" &&
		v != VirtualPatchOff && v != VirtualPatchManual && v != VirtualPatchAuto {
		results = append(results, ValidationResult{"error", "auto_response.virtual_patch_exposed_files", fmt.Sprintf("must be off, manual, or auto (got %q)", cfg.AutoResponse.VirtualPatchExposedFiles)})
	}
	if v := cfg.Thresholds.DropperUnlinkTTLSec; v != 0 && (v < MinDropperUnlinkTTLSec || v > MaxDropperUnlinkTTLSec) {
		results = append(results, ValidationResult{"error", "thresholds.dropper_unlink_ttl_sec", fmt.Sprintf("must be between %d and %d seconds (got %d)", MinDropperUnlinkTTLSec, MaxDropperUnlinkTTLSec, v)})
	}
	if cfg.Signatures.UpdateInterval != "" {
		if _, err := time.ParseDuration(cfg.Signatures.UpdateInterval); err != nil {
			results = append(results, ValidationResult{"error", "signatures.update_interval", fmt.Sprintf("unparseable duration: %s", cfg.Signatures.UpdateInterval)})
		}
	}
	if cfg.Signatures.YaraForge.UpdateInterval != "" {
		if _, err := time.ParseDuration(cfg.Signatures.YaraForge.UpdateInterval); err != nil {
			results = append(results, ValidationResult{"error", "signatures.yara_forge.update_interval", fmt.Sprintf("unparseable duration: %s", cfg.Signatures.YaraForge.UpdateInterval)})
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
	if cfg.Reputation.BotRanges.UpdateInterval != "" {
		if d, err := time.ParseDuration(cfg.Reputation.BotRanges.UpdateInterval); err != nil {
			results = append(results, ValidationResult{"error", "reputation.bot_ranges.update_interval", fmt.Sprintf("unparseable duration: %s", cfg.Reputation.BotRanges.UpdateInterval)})
		} else if d < time.Hour {
			results = append(results, ValidationResult{"error", "reputation.bot_ranges.update_interval", "update_interval must be at least 1h"})
		}
	}
	if cfg.AutoResponse.PermBlockInterval != "" {
		if _, err := time.ParseDuration(cfg.AutoResponse.PermBlockInterval); err != nil {
			results = append(results, ValidationResult{"error", "auto_response.permblock_interval", fmt.Sprintf("unparseable duration: %s", cfg.AutoResponse.PermBlockInterval)})
		}
	}
	if cfg.AutoResponse.MailAuthRecovery.DownGrace != "" {
		if d, err := time.ParseDuration(cfg.AutoResponse.MailAuthRecovery.DownGrace); err != nil {
			results = append(results, ValidationResult{"error", "auto_response.mail_auth_recovery.down_grace", fmt.Sprintf("unparseable duration: %s", cfg.AutoResponse.MailAuthRecovery.DownGrace)})
		} else if d <= 0 {
			results = append(results, ValidationResult{"error", "auto_response.mail_auth_recovery.down_grace", "down_grace must be > 0"})
		}
	}

	// --- Retention ---
	if cfg.Retention.Enabled {
		if cfg.Retention.SweepInterval != "" {
			if _, err := time.ParseDuration(cfg.Retention.SweepInterval); err != nil {
				results = append(results, ValidationResult{"error", "retention.sweep_interval", fmt.Sprintf("unparseable duration: %s", cfg.Retention.SweepInterval)})
			}
		}
		if cfg.Retention.FindingsDays < 0 {
			results = append(results, ValidationResult{"error", "retention.findings_days", fmt.Sprintf("findings_days must be >= 0 (0 disables the sweep), got %d", cfg.Retention.FindingsDays)})
		}
		if cfg.Retention.HistoryDays < 0 {
			results = append(results, ValidationResult{"error", "retention.history_days", fmt.Sprintf("history_days must be >= 0, got %d", cfg.Retention.HistoryDays)})
		}
		if cfg.Retention.ReputationDays < 0 {
			results = append(results, ValidationResult{"error", "retention.reputation_days", fmt.Sprintf("reputation_days must be >= 0, got %d", cfg.Retention.ReputationDays)})
		}
	}
	if cfg.Retention.CompactMinSizeMB < 0 {
		results = append(results, ValidationResult{"error", "retention.compact_min_size_mb", fmt.Sprintf("compact_min_size_mb must be >= 0, got %d", cfg.Retention.CompactMinSizeMB)})
	}
	if cfg.Retention.CompactFillRatio < 0 || cfg.Retention.CompactFillRatio > 1 || (cfg.Retention.Enabled && cfg.Retention.CompactFillRatio == 0) {
		results = append(results, ValidationResult{"error", "retention.compact_fill_ratio", fmt.Sprintf("compact_fill_ratio must be in (0, 1], got %v", cfg.Retention.CompactFillRatio)})
	}

	// --- Firewall ---
	if cfg.Firewall != nil {
		for _, e := range validateDOSExemptRanges(cfg.Firewall.DOSExemptRanges) {
			results = append(results, ValidationResult{"error", "firewall.dos_exempt_ranges", e})
		}
		if cfg.Firewall.Enabled {
			// 0 disables the connection meter: it is what the engine does with
			// the value and what the web UI's own help text promises. Absent
			// keys are filled from the shipped defaults before validation runs
			// (see applyFirewallFieldDefaults), so a 0 reaching here is always
			// the operator's explicit choice rather than an unset field.
			if cfg.Firewall.ConnRateLimit < 0 {
				results = append(results, ValidationResult{"error", "firewall.conn_rate_limit", fmt.Sprintf("conn_rate_limit must be >= 0 when firewall enabled (0 = disabled), got %d", cfg.Firewall.ConnRateLimit)})
			}
			if cfg.Firewall.ConnLimit < 0 {
				results = append(results, ValidationResult{"error", "firewall.conn_limit", "conn_limit must be >= 0 when firewall enabled (0 = disabled)"})
			}
			if cfg.Firewall.ConnRateLimit >= 0 && cfg.Firewall.ConnLimit >= 0 {
				results = append(results, ValidationResult{"ok", "firewall", fmt.Sprintf("enabled, conn_rate_limit=%s, conn_limit=%s",
					limitSummary(cfg.Firewall.ConnRateLimit), limitSummary(cfg.Firewall.ConnLimit))})
			}
		}
		results = append(results, firewallLockoutResults(cfg)...)
		results = append(results, firewallValueResults(cfg.Firewall)...)
	}
	results = append(results, centralActionResults(cfg)...)
	results = append(results, blockAtSeverityResults(cfg)...)

	// --- Challenge ---
	if cfg.Challenge.Difficulty < 0 || cfg.Challenge.Difficulty > 5 {
		results = append(results, ValidationResult{"error", "challenge.difficulty", fmt.Sprintf("difficulty must be 0-5, got %d", cfg.Challenge.Difficulty)})
	}
	if cfg.Challenge.ListenPort < 0 || cfg.Challenge.ListenPort > 65535 {
		results = append(results, ValidationResult{"error", "challenge.listen_port", fmt.Sprintf("listen_port must be 0-65535, got %d", cfg.Challenge.ListenPort)})
	} else if cfg.Challenge.Enabled && cfg.Challenge.ListenPort == 0 {
		results = append(results, ValidationResult{"error", "challenge.listen_port", fmt.Sprintf("listen_port must be 1-65535 when challenge.enabled, got %d", cfg.Challenge.ListenPort)})
	}

	// --- EmailAV ---
	if cfg.EmailAV.Enabled && cfg.EmailAV.MaxAttachmentSize <= 0 {
		results = append(results, ValidationResult{"error", "email_av.max_attachment_size", "max_attachment_size must be > 0 when email_av enabled"})
	}
	if cfg.EmailAV.FailMode != "" && cfg.EmailAV.FailMode != "open" && cfg.EmailAV.FailMode != "tempfail" {
		results = append(results, ValidationResult{"error", "email_av.fail_mode",
			fmt.Sprintf("invalid fail_mode %q: must be \"open\" or \"tempfail\"", cfg.EmailAV.FailMode)})
	}
	if cfg.Signatures.UpdateURL != "" && cfg.Signatures.SigningKey == "" {
		results = append(results, ValidationResult{"error", "signatures.signing_key",
			"signing_key is required when signatures.update_url is configured"})
	}
	if cfg.Signatures.YaraForge.Enabled && cfg.Signatures.SigningKey == "" {
		results = append(results, ValidationResult{"error", "signatures.signing_key",
			"signing_key is required when signatures.yara_forge.enabled is true"})
	}
	if cfg.Signatures.YaraForge.Enabled && cfg.Signatures.YaraForge.DownloadURL == "" {
		results = append(results, ValidationResult{"error", "signatures.yara_forge.download_url",
			"download_url is required because upstream YARA Forge releases do not publish CSM detached signatures"})
	}
	if cfg.Signatures.YaraForge.DownloadURL != "" {
		if err := validateSignatureURL(cfg.Signatures.YaraForge.DownloadURL, true); err != nil {
			results = append(results, ValidationResult{"error", "signatures.yara_forge.download_url", err.Error()})
		}
	}
	if cfg.Signatures.UpdateURL != "" {
		if err := validateSignatureURL(cfg.Signatures.UpdateURL, false); err != nil {
			results = append(results, ValidationResult{"error", "signatures.update_url", err.Error()})
		}
	}

	if err := validateDirectSMTPEgress(cfg); err != nil {
		results = append(results, ValidationResult{"error", "detection.direct_smtp_egress", err.Error()})
	}

	if err := validateBPFEnforcement(cfg); err != nil {
		results = append(results, ValidationResult{"error", "bpf_enforcement", err.Error()})
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

	if cfg.Thresholds.FTPFailWindowMin != 0 &&
		(cfg.Thresholds.FTPFailWindowMin < 1 || cfg.Thresholds.FTPFailWindowMin > 1440) {
		results = append(results, ValidationResult{"error", "thresholds.ftp_fail_window_min",
			fmt.Sprintf("ftp_fail_window_min must be between 1 and 1440, got %d", cfg.Thresholds.FTPFailWindowMin)})
	}

	// --- EmailProtection.PHPRelay bounds ---
	// Bounds checks fire only when the operator has supplied a value
	// (zero means "use the applyDefaults value" or, for AccountVolumePerHour,
	// "auto-derive from cPanel maxemailsperhour"). PoliciesDir is NOT
	// validated here -- filesystem state probes belong in ValidateDeep.
	pr := cfg.EmailProtection.PHPRelay
	if pr.RateWindowMin != 0 && (pr.RateWindowMin < 1 || pr.RateWindowMin > 60) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.rate_window_min", fmt.Sprintf("rate_window_min must be between 1 and 60, got %d", pr.RateWindowMin)})
	}
	if pr.HeaderScoreVolumeMin != 0 && (pr.HeaderScoreVolumeMin < 2 || pr.HeaderScoreVolumeMin > 100) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.header_score_volume_min", fmt.Sprintf("header_score_volume_min must be between 2 and 100, got %d", pr.HeaderScoreVolumeMin)})
	}
	if pr.AbsoluteVolumePerHour != 0 && (pr.AbsoluteVolumePerHour < 10 || pr.AbsoluteVolumePerHour > 1000) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.absolute_volume_per_hour", fmt.Sprintf("absolute_volume_per_hour must be between 10 and 1000, got %d", pr.AbsoluteVolumePerHour)})
	}
	// AccountVolumePerHour: 0 is the documented "auto-derive" sentinel;
	// only reject explicitly out-of-range positive values.
	if pr.AccountVolumePerHour < 0 || pr.AccountVolumePerHour > 5000 {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.account_volume_per_hour", fmt.Sprintf("account_volume_per_hour must be between 0 (auto-derive) and 5000, got %d", pr.AccountVolumePerHour)})
	}
	if pr.ReputationFailuresPer24h != 0 && (pr.ReputationFailuresPer24h < 1 || pr.ReputationFailuresPer24h > 50) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.reputation_failures_per_24h", fmt.Sprintf("reputation_failures_per_24h must be between 1 and 50, got %d", pr.ReputationFailuresPer24h)})
	}
	if pr.FanoutDistinctScripts != 0 && (pr.FanoutDistinctScripts < 2 || pr.FanoutDistinctScripts > 20) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.fanout_distinct_scripts", fmt.Sprintf("fanout_distinct_scripts must be between 2 and 20, got %d", pr.FanoutDistinctScripts)})
	}
	if pr.FanoutDistinctRecipients != 0 && (pr.FanoutDistinctRecipients < 1 || pr.FanoutDistinctRecipients > 100) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.fanout_distinct_recipients", fmt.Sprintf("fanout_distinct_recipients must be between 1 and 100, got %d", pr.FanoutDistinctRecipients)})
	}
	if pr.FanoutWindowMin != 0 && (pr.FanoutWindowMin < 1 || pr.FanoutWindowMin > 60) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.fanout_window_min", fmt.Sprintf("fanout_window_min must be between 1 and 60, got %d", pr.FanoutWindowMin)})
	}
	if pr.BaselineSigma != 0 && (pr.BaselineSigma < 2.0 || pr.BaselineSigma > 6.0) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.baseline_sigma", fmt.Sprintf("baseline_sigma must be between 2.0 and 6.0, got %v", pr.BaselineSigma)})
	}
	if pr.BaselineObservationDays != 0 && (pr.BaselineObservationDays < 1 || pr.BaselineObservationDays > 30) {
		results = append(results, ValidationResult{"error", "email_protection.php_relay.baseline_observation_days", fmt.Sprintf("baseline_observation_days must be between 1 and 30, got %d", pr.BaselineObservationDays)})
	}

	// --- AutoResponse.PHPRelay bounds ---
	if cfg.AutoResponse.PHPRelay.MaxActionsPerMinute != 0 && (cfg.AutoResponse.PHPRelay.MaxActionsPerMinute < 1 || cfg.AutoResponse.PHPRelay.MaxActionsPerMinute > 600) {
		results = append(results, ValidationResult{"error", "auto_response.php_relay.max_actions_per_minute", fmt.Sprintf("max_actions_per_minute must be between 1 and 600, got %d", cfg.AutoResponse.PHPRelay.MaxActionsPerMinute)})
	}
	if cfg.AutoResponse.MaxBlocksPerHour < 0 {
		results = append(results, ValidationResult{"error", "auto_response.max_blocks_per_hour", fmt.Sprintf("max_blocks_per_hour must be >= 0 (0 uses default %d), got %d", DefaultMaxBlocksPerHour, cfg.AutoResponse.MaxBlocksPerHour)})
	}
	if cfg.AutoResponse.MailAuthRecovery.MaxRestartsPerHour < 0 {
		results = append(results, ValidationResult{"error", "auto_response.mail_auth_recovery.max_restarts_per_hour", fmt.Sprintf("max_restarts_per_hour must be >= 0 (0 uses default 3), got %d", cfg.AutoResponse.MailAuthRecovery.MaxRestartsPerHour)})
	}
	if cfg.AutoResponse.MailAuthRecovery.RestartEnabled && strings.TrimSpace(cfg.AutoResponse.MailAuthRecovery.RestartCommand) == "" {
		results = append(results, ValidationResult{"error", "auto_response.mail_auth_recovery.restart_command", "restart_command is required when restart_enabled is true"})
	}

	// --- SMTP brute-force thresholds ---
	t := cfg.Thresholds
	if t.ExposedFileScanDepth != 0 &&
		(t.ExposedFileScanDepth < 1 || t.ExposedFileScanDepth > MaxExposedFileScanDepth) {
		results = append(results, ValidationResult{
			"error",
			"thresholds.exposed_file_scan_depth",
			fmt.Sprintf("exposed_file_scan_depth must be between 1 and %d", MaxExposedFileScanDepth),
		})
	}
	if t.DomlogMaxFiles != 0 && (t.DomlogMaxFiles < 1 || t.DomlogMaxFiles > 100000) {
		results = append(results, ValidationResult{"error", "thresholds.domlog_max_files", "domlog_max_files must be between 1 and 100000"})
	}
	if t.AccountScanMaxFiles != 0 && (t.AccountScanMaxFiles < 1 || t.AccountScanMaxFiles > 100000) {
		results = append(results, ValidationResult{"error", "thresholds.account_scan_max_files", "account_scan_max_files must be between 1 and 100000"})
	}
	if t.FullScanMaxFileMB != 0 && (t.FullScanMaxFileMB < 1 || t.FullScanMaxFileMB > 4096) {
		results = append(results, ValidationResult{"error", "thresholds.full_scan_max_file_mb", "full_scan_max_file_mb must be between 1 and 4096"})
	}
	if t.ScanJobRetention != 0 && (t.ScanJobRetention < 1 || t.ScanJobRetention > 1000) {
		results = append(results, ValidationResult{"error", "thresholds.scan_job_retention", "scan_job_retention must be between 1 and 1000"})
	}
	if t.CrontabBase64BlobMaxBytes != 0 {
		if t.CrontabBase64BlobMaxBytes < 1024 || t.CrontabBase64BlobMaxBytes > 1048576 {
			results = append(results, ValidationResult{"error", "thresholds.crontab_base64_blob_max_bytes", "crontab_base64_blob_max_bytes must be between 1024 and 1048576"})
		} else if t.CrontabBase64BlobMaxBytes%4 != 0 {
			results = append(results, ValidationResult{"error", "thresholds.crontab_base64_blob_max_bytes", "crontab_base64_blob_max_bytes must be a multiple of 4 (standard base64 alignment)"})
		}
	}
	if t.DomlogTailLines != 0 && (t.DomlogTailLines < 10 || t.DomlogTailLines > 100000) {
		results = append(results, ValidationResult{"error", "thresholds.domlog_tail_lines", "domlog_tail_lines must be between 10 and 100000"})
	}
	if t.DomlogMaxAgeMin != 0 && (t.DomlogMaxAgeMin < 1 || t.DomlogMaxAgeMin > 1440) {
		results = append(results, ValidationResult{"error", "thresholds.domlog_max_age_min", "domlog_max_age_min must be between 1 and 1440"})
	}
	if t.MailLogTailLines != 0 && (t.MailLogTailLines < 10 || t.MailLogTailLines > 100000) {
		results = append(results, ValidationResult{"error", "thresholds.mail_log_tail_lines", "mail_log_tail_lines must be between 10 and 100000"})
	}
	if t.SyslogMessagesTailLines != 0 && (t.SyslogMessagesTailLines < 10 || t.SyslogMessagesTailLines > 100000) {
		results = append(results, ValidationResult{"error", "thresholds.syslog_messages_tail_lines", "syslog_messages_tail_lines must be between 10 and 100000"})
	}
	if t.CredStuffingDistinctAccounts != 0 && (t.CredStuffingDistinctAccounts < 2 || t.CredStuffingDistinctAccounts > 200) {
		results = append(results, ValidationResult{"error", "thresholds.cred_stuffing_distinct_accounts", "cred_stuffing_distinct_accounts must be between 2 and 200"})
	}
	if t.HTTPScannerMinRequests < 0 {
		results = append(results, ValidationResult{"error", "thresholds.http_scanner_min_requests", "http_scanner_min_requests must be >= 0 (0 disables the detector)"})
	}
	if t.HTTPScannerErrorPct != 0 && (t.HTTPScannerErrorPct < 1 || t.HTTPScannerErrorPct > 100) {
		results = append(results, ValidationResult{"error", "thresholds.http_scanner_error_pct", "http_scanner_error_pct must be between 1 and 100"})
	}
	if t.HTTPScannerMinDistinctPaths != 0 && (t.HTTPScannerMinDistinctPaths < 1 || t.HTTPScannerMinDistinctPaths > HTTPScannerMaxDistinctPaths) {
		results = append(results, ValidationResult{"error", "thresholds.http_scanner_min_distinct_paths", fmt.Sprintf("http_scanner_min_distinct_paths must be between 1 and %d", HTTPScannerMaxDistinctPaths)})
	}
	for _, code := range t.HTTPScannerStatusCodes {
		if code < 100 || code > 599 {
			results = append(results, ValidationResult{"error", "thresholds.http_scanner_status_codes", "http_scanner_status_codes entries must be HTTP status codes between 100 and 599"})
			break
		}
	}
	switch cfg.AutoResponse.HTTPScannerAction {
	case "", "challenge", "block":
	default:
		results = append(results, ValidationResult{"error", "auto_response.http_scanner_action", fmt.Sprintf("http_scanner_action must be %q or %q, got %q", "challenge", "block", cfg.AutoResponse.HTTPScannerAction)})
	}
	if t.SMTPBruteForceThreshold != 0 && (t.SMTPBruteForceThreshold < 2 || t.SMTPBruteForceThreshold > 50) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_bruteforce_threshold", "smtp_bruteforce_threshold must be between 2 and 50"})
	}
	if t.SMTPBruteForceWindowMin != 0 && (t.SMTPBruteForceWindowMin < 1 || t.SMTPBruteForceWindowMin > 60) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_bruteforce_window_min", "smtp_bruteforce_window_min must be between 1 and 60"})
	}
	if t.SMTPBruteForceSuppressMin != 0 && (t.SMTPBruteForceSuppressMin < 1 || t.SMTPBruteForceSuppressMin > 1440) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_bruteforce_suppress_min", "smtp_bruteforce_suppress_min must be between 1 and 1440"})
	}
	if t.SMTPBruteForceSubnetThresh != 0 && (t.SMTPBruteForceSubnetThresh < 2 || t.SMTPBruteForceSubnetThresh > 64) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_bruteforce_subnet_threshold", "smtp_bruteforce_subnet_threshold must be between 2 and 64"})
	}
	if t.SMTPAccountSprayThreshold != 0 && (t.SMTPAccountSprayThreshold < 2 || t.SMTPAccountSprayThreshold > 200) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_account_spray_threshold", "smtp_account_spray_threshold must be between 2 and 200"})
	}
	if t.SMTPBruteForceMaxTracked != 0 && (t.SMTPBruteForceMaxTracked < 1000 || t.SMTPBruteForceMaxTracked > 200000) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_bruteforce_max_tracked", "smtp_bruteforce_max_tracked must be between 1000 and 200000"})
	}
	if t.SMTPBruteForceSlowThreshold != 0 && (t.SMTPBruteForceSlowThreshold < SlowBruteMinThreshold || t.SMTPBruteForceSlowThreshold > SlowBruteMaxThreshold) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_bruteforce_slow_threshold", fmt.Sprintf("smtp_bruteforce_slow_threshold must be 0 (disabled) or between %d and %d", SlowBruteMinThreshold, SlowBruteMaxThreshold)})
	}
	if t.SMTPBruteForceSlowWindowMin != 0 && (t.SMTPBruteForceSlowWindowMin < 1 || t.SMTPBruteForceSlowWindowMin > SlowBruteMaxWindowMin) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_bruteforce_slow_window_min", fmt.Sprintf("smtp_bruteforce_slow_window_min must be between 1 and %d", SlowBruteMaxWindowMin)})
	}
	if t.SMTPProbeThreshold != 0 && (t.SMTPProbeThreshold < 10 || t.SMTPProbeThreshold > 10000) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_probe_threshold", "smtp_probe_threshold must be between 10 and 10000"})
	}
	if t.SMTPProbeWindowMin != 0 && (t.SMTPProbeWindowMin < 1 || t.SMTPProbeWindowMin > 60) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_probe_window_min", "smtp_probe_window_min must be between 1 and 60"})
	}
	if t.SMTPProbeSuppressMin != 0 && (t.SMTPProbeSuppressMin < 1 || t.SMTPProbeSuppressMin > 1440) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_probe_suppress_min", "smtp_probe_suppress_min must be between 1 and 1440"})
	}
	if t.SMTPProbeMaxTracked != 0 && (t.SMTPProbeMaxTracked < 1000 || t.SMTPProbeMaxTracked > 200000) {
		results = append(results, ValidationResult{"error", "thresholds.smtp_probe_max_tracked", "smtp_probe_max_tracked must be between 1000 and 200000"})
	}
	if t.MailBruteForceThreshold != 0 && (t.MailBruteForceThreshold < 2 || t.MailBruteForceThreshold > 50) {
		results = append(results, ValidationResult{"error", "thresholds.mail_bruteforce_threshold", "mail_bruteforce_threshold must be between 2 and 50"})
	}
	if t.MailBruteForceWindowMin != 0 && (t.MailBruteForceWindowMin < 1 || t.MailBruteForceWindowMin > 60) {
		results = append(results, ValidationResult{"error", "thresholds.mail_bruteforce_window_min", "mail_bruteforce_window_min must be between 1 and 60"})
	}
	if t.MailBruteForceSuppressMin != 0 && (t.MailBruteForceSuppressMin < 1 || t.MailBruteForceSuppressMin > 1440) {
		results = append(results, ValidationResult{"error", "thresholds.mail_bruteforce_suppress_min", "mail_bruteforce_suppress_min must be between 1 and 1440"})
	}
	if t.MailBruteForceSubnetThresh != 0 && (t.MailBruteForceSubnetThresh < 2 || t.MailBruteForceSubnetThresh > 64) {
		results = append(results, ValidationResult{"error", "thresholds.mail_bruteforce_subnet_threshold", "mail_bruteforce_subnet_threshold must be between 2 and 64"})
	}
	if t.MailAccountSprayThreshold != 0 && (t.MailAccountSprayThreshold < 2 || t.MailAccountSprayThreshold > 200) {
		results = append(results, ValidationResult{"error", "thresholds.mail_account_spray_threshold", "mail_account_spray_threshold must be between 2 and 200"})
	}
	if t.MailBruteForceMaxTracked != 0 && (t.MailBruteForceMaxTracked < 1000 || t.MailBruteForceMaxTracked > 200000) {
		results = append(results, ValidationResult{"error", "thresholds.mail_bruteforce_max_tracked", "mail_bruteforce_max_tracked must be between 1000 and 200000"})
	}
	if t.MailBruteForceSlowThreshold != 0 && (t.MailBruteForceSlowThreshold < SlowBruteMinThreshold || t.MailBruteForceSlowThreshold > SlowBruteMaxThreshold) {
		results = append(results, ValidationResult{"error", "thresholds.mail_bruteforce_slow_threshold", fmt.Sprintf("mail_bruteforce_slow_threshold must be 0 (disabled) or between %d and %d", SlowBruteMinThreshold, SlowBruteMaxThreshold)})
	}
	if t.MailBruteForceSlowWindowMin != 0 && (t.MailBruteForceSlowWindowMin < 1 || t.MailBruteForceSlowWindowMin > SlowBruteMaxWindowMin) {
		results = append(results, ValidationResult{"error", "thresholds.mail_bruteforce_slow_window_min", fmt.Sprintf("mail_bruteforce_slow_window_min must be between 1 and %d", SlowBruteMaxWindowMin)})
	}
	if field, err := validateMailBruteAccountKeyField(cfg); err != nil {
		results = append(results, ValidationResult{"error", field, err.Error()})
	}

	// --- Mail log source ---
	if field, err := validateMailLogsField(cfg); err != nil {
		results = append(results, ValidationResult{"error", field, err.Error()})
	}

	// --- Reputation.Rspamd ---
	if cfg.Reputation.Rspamd.Enabled {
		secret := cfg.Reputation.Rspamd.Token
		if cfg.Reputation.Rspamd.TokenEnv != "" {
			if v := os.Getenv(cfg.Reputation.Rspamd.TokenEnv); v != "" {
				secret = v
			}
		}
		if secret == "" {
			results = append(results, ValidationResult{"warn", "reputation.rspamd.token", "rspamd enabled but no token configured (rspamd controller history may require auth)"})
		}
	}

	// --- Reputation.Upstream ---
	if cfg.Reputation.Upstream.Enabled {
		secret := cfg.Reputation.Upstream.Token
		if cfg.Reputation.Upstream.TokenEnv != "" {
			if v := os.Getenv(cfg.Reputation.Upstream.TokenEnv); v != "" {
				secret = v
			}
		}
		if secret == "" {
			results = append(results, ValidationResult{"warn", "reputation.upstream.token", "upstream enabled but no token configured (panel endpoint may require auth)"})
		}
	}

	// --- Reputation.VerifiedBots ---
	results = append(results, validateVerifiedBots(cfg)...)

	// --- AutoResponse.VerdictCallback ---
	if field, err := validateVerdictCallbackField(cfg); err != nil {
		results = append(results, ValidationResult{"error", field, err.Error()})
	}

	// --- Debug / pprof ---
	if addr := strings.TrimSpace(cfg.Debug.PprofListen); addr != "" {
		host, _, err := net.SplitHostPort(addr)
		host = strings.TrimSpace(host)
		loopback := err == nil && host != "" &&
			(strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()))
		if loopback {
			results = append(results, ValidationResult{"ok", "debug.pprof_listen", addr})
		} else {
			results = append(results, ValidationResult{"error", "debug.pprof_listen",
				fmt.Sprintf("must be a loopback host:port (127.0.0.1/::1/localhost); %q would expose pprof off-box and is ignored at runtime", addr)})
		}
	}

	// --- Warnings ---
	results = append(results, validateWarnings(cfg)...)

	return results
}

func webUITokenCounts(cfg *Config) (tokens, admins int) {
	if len(cfg.WebUI.Tokens) == 0 && cfg.WebUI.AuthToken != "" {
		tokens++
		admins++
	}
	for _, tok := range cfg.WebUI.Tokens {
		if tok.Token == "" {
			continue
		}
		tokens++
		if tok.Scope == "admin" {
			admins++
		}
	}
	return tokens, admins
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

	// block_ips wants to mutate nftables, but the firewall engine that
	// would apply those rules is disabled or absent. Without this check
	// the daemon happily logs "auto-blocked" actions that never reach
	// the kernel, and operators only notice when attackers keep coming
	// back.
	if cfg.AutoResponse.Enabled && cfg.AutoResponse.BlockIPs {
		if cfg.Firewall == nil || !cfg.Firewall.Enabled {
			results = append(results, ValidationResult{"warn", "auto_response.block_ips", "auto-response wants to block IPs but firewall is disabled; blocks will be no-ops"})
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

// firewallValueResults rejects firewall values the engine would otherwise
// accept and quietly reinterpret: a port outside 1-65535 cannot select the
// intended service, an inverted passive-FTP range opens nothing, and a
// port_flood proto that is not "udp" is treated as TCP no matter what the
// operator typed.
func firewallValueResults(fw *firewall.FirewallConfig) []ValidationResult {
	var results []ValidationResult

	for _, list := range []struct {
		field string
		ports []int
	}{
		{"firewall.tcp_in", fw.TCPIn},
		{"firewall.tcp_out", fw.TCPOut},
		{"firewall.udp_in", fw.UDPIn},
		{"firewall.udp_out", fw.UDPOut},
		{"firewall.tcp6_in", fw.TCP6In},
		{"firewall.tcp6_out", fw.TCP6Out},
		{"firewall.udp6_in", fw.UDP6In},
		{"firewall.udp6_out", fw.UDP6Out},
		{"firewall.restricted_tcp", fw.RestrictedTCP},
		{"firewall.drop_nolog", fw.DropNoLog},
		{"firewall.smtp_ports", fw.SMTPPorts},
	} {
		for _, port := range list.ports {
			if !validPort(port) {
				results = append(results, ValidationResult{"error", list.field,
					fmt.Sprintf("port %d is out of range (1-65535)", port)})
			}
		}
	}

	// The engine only builds the range rule when both ends are set, so a
	// half-configured range is silently inert rather than wrong.
	if fw.PassiveFTPStart != 0 || fw.PassiveFTPEnd != 0 {
		if !validPort(fw.PassiveFTPStart) {
			results = append(results, ValidationResult{"error", "firewall.passive_ftp_start",
				fmt.Sprintf("port %d is out of range (1-65535)", fw.PassiveFTPStart)})
		}
		if !validPort(fw.PassiveFTPEnd) {
			results = append(results, ValidationResult{"error", "firewall.passive_ftp_end",
				fmt.Sprintf("port %d is out of range (1-65535)", fw.PassiveFTPEnd)})
		}
		if validPort(fw.PassiveFTPStart) && validPort(fw.PassiveFTPEnd) && fw.PassiveFTPStart > fw.PassiveFTPEnd {
			results = append(results, ValidationResult{"error", "firewall.passive_ftp_start",
				fmt.Sprintf("passive FTP range starts at %d but ends at %d", fw.PassiveFTPStart, fw.PassiveFTPEnd)})
		}
	}

	for _, code := range fw.CountryBlock {
		if !validCountryCode(code) {
			results = append(results, ValidationResult{"error", "firewall.country_block",
				fmt.Sprintf("%q is not a two-letter ISO country code", code)})
		}
	}

	for i, pf := range fw.PortFlood {
		switch {
		case !validPort(pf.Port):
			results = append(results, ValidationResult{"error", "firewall.port_flood",
				fmt.Sprintf("entry %d: port %d is out of range (1-65535)", i, pf.Port)})
		// The case handling is deliberately asymmetric. The engine selects UDP
		// with an exact `Proto == "udp"` match and treats every other value as
		// TCP, so "TCP" resolves to the protocol the operator meant and is
		// safe to accept, while "UDP" would silently become TCP and must be
		// rejected. Do not "tidy" this into a single case-insensitive compare.
		case pf.Proto != "" && !strings.EqualFold(pf.Proto, "tcp") && pf.Proto != "udp":
			results = append(results, ValidationResult{"error", "firewall.port_flood",
				fmt.Sprintf("entry %d: proto %q must be \"tcp\" or lowercase \"udp\"", i, pf.Proto)})
		case pf.Hits <= 0:
			results = append(results, ValidationResult{"error", "firewall.port_flood",
				fmt.Sprintf("entry %d: hits must be > 0, got %d", i, pf.Hits)})
		case pf.Seconds <= 0:
			results = append(results, ValidationResult{"error", "firewall.port_flood",
				fmt.Sprintf("entry %d: seconds must be > 0, got %d", i, pf.Seconds)})
		}
	}

	return results
}

// centralActions mirrors the action constants in internal/reporting, which
// this package cannot import: reporting depends on alert, and alert depends
// on config. TestCentralActionsMatchReportingConstants (external test package,
// so it may import both) fails if the two lists ever drift.
var centralActions = [...]string{"off", "challenge", "block_if_local_corroborated"}

// ValidCentralActions returns every central-intelligence action accepted by
// config validation.
func ValidCentralActions() []string {
	return append([]string(nil), centralActions[:]...)
}

// centralActionResults rejects an unrecognised central action. The consumer
// parses it with a default branch that resolves to "challenge", so a typo
// silently turns a corroborated-block policy into a challenge policy and the
// only trace is one daemon log line at startup.
func centralActionResults(cfg *Config) []ValidationResult {
	action := cfg.Reputation.Central.Action
	if action == "" {
		return nil
	}
	for _, valid := range centralActions {
		if action == valid {
			return nil
		}
	}
	return []ValidationResult{{"error", "reputation.central.action",
		fmt.Sprintf("invalid action %q: must be one of %s", action, strings.Join(centralActions[:], ", "))}}
}

// blockAtSeverityResults rejects an unrecognised incident block threshold.
// The correlator matches "high" and "critical" and ignores anything else, so
// a typo leaves the operator believing incident blocking is armed when the
// hand-off can never fire.
func blockAtSeverityResults(cfg *Config) []ValidationResult {
	var results []ValidationResult
	for _, entry := range []struct {
		field string
		value string
	}{
		{"incidents.spray_suppression.block_at_severity", cfg.Incidents.SpraySuppression.BlockAtSeverity},
		{"incidents.auto_block.block_at_severity", cfg.Incidents.AutoBlock.BlockAtSeverity},
	} {
		if entry.value == "" {
			continue
		}
		switch strings.ToLower(entry.value) {
		case "high", "critical":
		default:
			results = append(results, ValidationResult{"error", entry.field,
				fmt.Sprintf("invalid severity %q: must be \"high\" or \"critical\" (empty disables blocking)", entry.value)})
		}
	}
	return results
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func validCountryCode(code string) bool {
	if len(code) != 2 {
		return false
	}
	region, err := language.ParseRegion(code)
	return err == nil && region.IsCountry()
}

// limitSummary renders a firewall limit for operator-facing output so a
// disabled protection reads as "disabled" instead of as a bare 0 that looks
// like a missing value.
func limitSummary(v int) string {
	if v == 0 {
		return "disabled"
	}
	return strconv.Itoa(v)
}

// firewallLockoutResults reports the ways an enabled firewall can cut the
// operator off from the host. The web UI runs the same checks before a save;
// running them here covers hand-edited csm.yaml, `csm doctor`, and daemon
// startup, which previously got no warning at all.
//
// These are warnings, never errors. Fronting the web UI with a reverse proxy
// or reaching it over a VPN are legitimate reasons to leave the port out of
// tcp_in, and validation must not refuse a deliberate configuration.
func firewallLockoutResults(cfg *Config) []ValidationResult {
	fw := cfg.Firewall
	if fw == nil || !fw.Enabled {
		return nil
	}

	var results []ValidationResult
	hasInfra := len(cfg.InfraIPs) > 0 || len(fw.InfraIPs) > 0
	port, portKnown := webUIListenPort(cfg.WebUI.Listen)

	// Naming the port in restricted_tcp is how an operator asks for an
	// infra-only service, and the infra accept rule matches before any port
	// rule, so such a port stays reachable without appearing in tcp_in. The
	// shipped defaults ship exactly this pair; warning about it would make
	// every stock install report WARN. Without infra_ips there is nothing left
	// to reach it from, so the warning still stands.
	infraOnly := portKnown && hasInfra && containsPort(fw.RestrictedTCP, port)

	if cfg.WebUI.Enabled && portKnown && !infraOnly && !containsPort(fw.TCPIn, port) {
		results = append(results, ValidationResult{"warn", "firewall.tcp_in",
			fmt.Sprintf("web UI listens on %d but tcp_in does not allow it; the next firewall apply drops new web UI connections", port)})
	}
	// A non-empty tcp6_in overrides tcp_in. When empty, IPv6 inherits tcp_in,
	// so the IPv4 check above already covers the effective port policy.
	if cfg.WebUI.Enabled && portKnown && !infraOnly && fw.IPv6 && len(fw.TCP6In) > 0 && !containsPort(fw.TCP6In, port) {
		results = append(results, ValidationResult{"warn", "firewall.tcp6_in",
			fmt.Sprintf("IPv6 is managed and tcp6_in does not allow web UI port %d", port)})
	}

	// restricted_tcp filters matching ports out of the public allow lists; it
	// does not add reachability. Without infra_ips, only an overlap with an
	// effective allow list changes a port from public to unreachable.
	tcp6In := fw.TCP6In
	if len(tcp6In) == 0 {
		tcp6In = fw.TCPIn
	}
	restrictedAllowed := portsOverlap(fw.RestrictedTCP, fw.TCPIn) ||
		(fw.IPv6 && portsOverlap(fw.RestrictedTCP, tcp6In))
	if restrictedAllowed && !hasInfra {
		msg := "restricted_tcp filters ports out of the public allow list, but no infra_ips are configured, so those ports are reachable from nowhere"
		webUIAllowed := containsPort(fw.TCPIn, port) || (fw.IPv6 && containsPort(tcp6In, port))
		if cfg.WebUI.Enabled && portKnown && webUIAllowed && containsPort(fw.RestrictedTCP, port) {
			msg = fmt.Sprintf("web UI port %d is in restricted_tcp but no infra_ips are configured, so the web UI is reachable from nowhere", port)
		}
		results = append(results, ValidationResult{"warn", "firewall.restricted_tcp", msg})
	}

	return results
}

// sshdConfigPath is where the SSH lockout guard reads the listen ports from.
// It is a test hook, not an operator setting: sshd's own path is fixed.
var sshdConfigPath = sshdconf.DefaultPath

// SetSSHDConfigPath points the SSH lockout guard at another sshd config and
// returns a func restoring the previous path. Tests use it to stay hermetic;
// production always reads sshd's own path.
func SetSSHDConfigPath(path string) func() {
	previous := sshdConfigPath
	sshdConfigPath = path
	return func() { sshdConfigPath = previous }
}

// probeSSHLockout warns when an enabled firewall would not accept the ports
// sshd actually listens on. The shipped tcp_in leaves 22 out, so a host that
// never moved sshd loses SSH on the next apply.
//
// It reads the host, which is why it is a deep probe rather than part of
// Validate: the same csm.yaml must validate identically on any machine.
func probeSSHLockout(cfg *Config) []ValidationResult {
	fw := cfg.Firewall
	if fw == nil || !fw.Enabled {
		return nil
	}

	// No sshd config means no evidence of a listener. Falling back to the
	// compiled default here would warn on every host that does not run sshd.
	sshd := sshdconf.Parse(sshdconf.OSFS{}, sshdConfigPath)
	if !sshd.Present() {
		return nil
	}

	hasInfra := len(cfg.InfraIPs) > 0 || len(fw.InfraIPs) > 0
	var missingV4, missingV6 []int
	for _, port := range sshd.ListenPorts() {
		// Naming the port in restricted_tcp is how an operator asks for an
		// infra-only listener. The infra accept rule matches before any port
		// rule, so such a port stays reachable without appearing in tcp_in.
		if hasInfra && containsPort(fw.RestrictedTCP, port) {
			continue
		}
		if !containsPort(fw.TCPIn, port) {
			missingV4 = append(missingV4, port)
		}
		// An empty tcp6_in inherits tcp_in, so only a non-empty list can
		// diverge from the IPv4 verdict above.
		if fw.IPv6 && len(fw.TCP6In) > 0 && !containsPort(fw.TCP6In, port) {
			missingV6 = append(missingV6, port)
		}
	}

	var results []ValidationResult
	if len(missingV4) > 0 {
		subject, pronoun := portPhrase(missingV4)
		results = append(results, ValidationResult{"warn", "firewall.tcp_in",
			fmt.Sprintf("sshd listens on %s but tcp_in does not allow %s; the next firewall apply drops new SSH connections", subject, pronoun)})
	}
	if len(missingV6) > 0 {
		subject, _ := portPhrase(missingV6)
		results = append(results, ValidationResult{"warn", "firewall.tcp6_in",
			fmt.Sprintf("IPv6 is managed and tcp6_in does not allow sshd %s", subject)})
	}
	return results
}

// portPhrase renders a port list plus the pronoun that agrees with it.
func portPhrase(ports []int) (subject, pronoun string) {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	if len(parts) == 1 {
		return "port " + parts[0], "it"
	}
	return "ports " + strings.Join(parts, ", "), "them"
}

// webUIListenPort extracts the port from a host:port listen string, falling
// back to the shipped default when the field is unset.
func webUIListenPort(listen string) (int, bool) {
	if listen == "" {
		listen = "0.0.0.0:9443"
	}
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, false
	}
	return port, true
}

func containsPort(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

func portsOverlap(a, b []int) bool {
	for _, port := range a {
		if containsPort(b, port) {
			return true
		}
	}
	return false
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

	// SSH reachability under the configured firewall policy
	results = append(results, probeSSHLockout(cfg)...)

	return results
}

// ValidateDeepSection runs only the deep probes relevant to the named
// section, so a save to section X does not fail on an unrelated probe
// for section Y. Section names match the webui settings schema IDs.
//
// For any section without deep probes, returns nil.
func ValidateDeepSection(cfg *Config, section string) []ValidationResult {
	switch section {
	case "alerts":
		var results []ValidationResult
		if cfg.Alerts.Email.Enabled && cfg.Alerts.Email.SMTP != "" {
			results = append(results, probeSMTP(cfg.Alerts.Email.SMTP)...)
		}
		if cfg.Alerts.Webhook.Enabled && cfg.Alerts.Webhook.URL != "" {
			results = append(results, probeWebhook(cfg.Alerts.Webhook.URL)...)
		}
		return results
	case "email_av":
		if cfg.EmailAV.Enabled && cfg.EmailAV.ClamdSocket != "" {
			return probeClamd(cfg.EmailAV.ClamdSocket)
		}
	case "geoip":
		if cfg.GeoIP.AccountID != "" && cfg.GeoIP.LicenseKey != "" && len(cfg.GeoIP.Editions) > 0 {
			return probeGeoIPDBs(cfg.StatePath, cfg.GeoIP.Editions)
		}
	case "firewall":
		return probeSSHLockout(cfg)
	case "challenge":
		// probeListenPortAvailable is not yet implemented in this codebase.
		// When added, invoke it here: return probeListenPortAvailable(cfg.Challenge.ListenPort).
		return nil
	}
	return nil
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
	// #nosec G304 -- filepath.Join under operator-configured statePath.
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

func validateSignatureURL(raw string, allowTemplates bool) error {
	candidate := strings.TrimSpace(raw)
	if allowTemplates {
		candidate = sampleSignatureURLTemplate(candidate)
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("signatures URL must be an http or https URL")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host in %q", raw)
	}
	return validateSignaturesHost(host)
}

func sampleSignatureURLTemplate(raw string) string {
	raw = strings.ReplaceAll(raw, "{tier}", "core")
	raw = strings.ReplaceAll(raw, "{version}", "v1.0.0")
	return raw
}

// validateSignaturesHost rejects URL hosts that point at loopback,
// link-local, or RFC1918 / ULA ranges. Scoped IPv6 literals are valid URL
// hosts, so use netip instead of net.ParseIP to keep the zone intact.
func validateSignaturesHost(host string) error {
	lower := strings.TrimSuffix(strings.ToLower(host), ".")
	if lower == "localhost" || lower == "localhost.localdomain" {
		return fmt.Errorf("signatures URL host %q is loopback; refuse for production downloads", host)
	}
	if addr, err := netip.ParseAddr(lower); err == nil {
		addr = addr.Unmap()
		if addr.IsLoopback() {
			return fmt.Errorf("signatures URL host %s is loopback", host)
		}
		if addr.IsPrivate() {
			return fmt.Errorf("signatures URL host %s is RFC1918 / ULA private", host)
		}
		if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
			return fmt.Errorf("signatures URL host %s is link-local", host)
		}
		if addr.IsUnspecified() {
			return fmt.Errorf("signatures URL host %s is unspecified", host)
		}
	}
	return nil
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

// validateDOSExemptRanges checks each entry in the dos_exempt_ranges list.
// Per entry: whitespace is trimmed; empty entries are rejected; CIDR notation
// is parsed via net.ParseCIDR and default routes (/0) are rejected; bare IP
// addresses are accepted as /32 or /128 equivalents; anything else is an error.
// Each error string is prefixed with "firewall.dos_exempt_ranges[<i>]:".
func validateDOSExemptRanges(entries []string) []string {
	var errs []string
	for i, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			errs = append(errs, fmt.Sprintf("firewall.dos_exempt_ranges[%d]: empty entry", i))
			continue
		}
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			ones, _ := ipnet.Mask.Size()
			if ones == 0 {
				errs = append(errs, fmt.Sprintf("firewall.dos_exempt_ranges[%d]: %s is a default route and cannot be used as an exempt range", i, entry))
			}
			continue
		}
		if net.ParseIP(entry) != nil {
			continue
		}
		errs = append(errs, fmt.Sprintf("firewall.dos_exempt_ranges[%d]: %q is not a valid CIDR or IP address", i, entry))
	}
	return errs
}

// validateFirewallConfig validates firewall fields that are checked at load
// time to prevent invalid configuration from reaching the daemon. It returns
// the first multi-error joined string so LoadBytes can return a single error.
func validateFirewallConfig(cfg *Config) error {
	if cfg.Firewall == nil {
		return nil
	}
	errs := validateDOSExemptRanges(cfg.Firewall.DOSExemptRanges)
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}
