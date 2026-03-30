package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/firewall"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ConfigFile string `yaml:"-"`

	Hostname string `yaml:"hostname"`

	Alerts struct {
		Email struct {
			Enabled bool     `yaml:"enabled"`
			To      []string `yaml:"to"`
			From    string   `yaml:"from"`
			SMTP    string   `yaml:"smtp"`
		} `yaml:"email"`
		Webhook struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
			Type    string `yaml:"type"` // slack, discord, generic
		} `yaml:"webhook"`
		Heartbeat struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
		} `yaml:"heartbeat"`
		MaxPerHour int `yaml:"max_per_hour"`
	} `yaml:"alerts"`

	Integrity struct {
		BinaryHash string `yaml:"binary_hash"`
		ConfigHash string `yaml:"config_hash"`
		Immutable  bool   `yaml:"immutable"`
	} `yaml:"integrity"`

	Thresholds struct {
		MailQueueWarn             int `yaml:"mail_queue_warn"`
		MailQueueCrit             int `yaml:"mail_queue_crit"`
		StateExpiryHours          int `yaml:"state_expiry_hours"`
		DeepScanIntervalMin       int `yaml:"deep_scan_interval_min"`
		WPCoreCheckIntervalMin    int `yaml:"wp_core_check_interval_min"`
		WebshellScanIntervalMin   int `yaml:"webshell_scan_interval_min"`
		FilesystemScanIntervalMin int `yaml:"filesystem_scan_interval_min"`
		MultiIPLoginThreshold     int `yaml:"multi_ip_login_threshold"`
		MultiIPLoginWindowMin     int `yaml:"multi_ip_login_window_min"`
	} `yaml:"thresholds"`

	InfraIPs []string `yaml:"infra_ips"`

	StatePath string `yaml:"state_path"`

	Suppressions struct {
		UPCPWindowStart       string   `yaml:"upcp_window_start"`
		UPCPWindowEnd         string   `yaml:"upcp_window_end"`
		KnownAPITokens        []string `yaml:"known_api_tokens"`
		IgnorePaths           []string `yaml:"ignore_paths"`
		SuppressWebmail       bool     `yaml:"suppress_webmail_alerts"`      // don't alert on webmail logins
		SuppressCpanelLogin   bool     `yaml:"suppress_cpanel_login_alerts"` // don't alert on cPanel direct logins
		SuppressBlockedAlerts bool     `yaml:"suppress_blocked_alerts"`      // don't alert on IPs that were auto-blocked
		TrustedCountries      []string `yaml:"trusted_countries"`            // ISO 3166-1 alpha-2 codes — suppress cPanel login alerts from these countries
	} `yaml:"suppressions"`

	AutoResponse struct {
		Enabled            bool   `yaml:"enabled"`
		KillProcesses      bool   `yaml:"kill_processes"`
		QuarantineFiles    bool   `yaml:"quarantine_files"`
		BlockIPs           bool   `yaml:"block_ips"`
		BlockExpiry        string `yaml:"block_expiry"`        // e.g. "24h", "12h"
		EnforcePermissions bool   `yaml:"enforce_permissions"` // auto-chmod 644 world/group-writable PHP files (default false)
		BlockCpanelLogins  bool   `yaml:"block_cpanel_logins"` // block IPs on cPanel/webmail login alerts (default false)
		NetBlock           bool   `yaml:"netblock"`            // auto-block /24 when threshold IPs from same subnet
		NetBlockThreshold  int    `yaml:"netblock_threshold"`  // IPs from same /24 before subnet block (default 3)
		PermBlock          bool   `yaml:"permblock"`           // auto-promote to permanent after N temp blocks
		PermBlockCount     int    `yaml:"permblock_count"`     // temp blocks before permanent (default 4)
		PermBlockInterval  string `yaml:"permblock_interval"`  // window for counting temp blocks (default "24h")
	} `yaml:"auto_response"`

	Challenge struct {
		Enabled    bool   `yaml:"enabled"`     // enable challenge pages instead of hard block for some IPs
		ListenPort int    `yaml:"listen_port"` // port for challenge server (default: 8439)
		Secret     string `yaml:"secret"`      // HMAC secret for challenge tokens (auto-generated if empty)
		Difficulty int    `yaml:"difficulty"`  // proof-of-work difficulty 0-5 (default: 2)
	} `yaml:"challenge"`

	PHPShield struct {
		Enabled bool `yaml:"enabled"` // watch php_events.log for PHP Shield alerts (default: false)
	} `yaml:"php_shield"`

	Reputation struct {
		AbuseIPDBKey string   `yaml:"abuseipdb_key"`
		Whitelist    []string `yaml:"whitelist"` // IPs to never flag as malicious
	} `yaml:"reputation"`

	Signatures struct {
		RulesDir       string `yaml:"rules_dir"`
		UpdateURL      string `yaml:"update_url"`
		AutoUpdate     bool   `yaml:"auto_update"`     // auto-download rules daily (default: true if update_url set)
		UpdateInterval string `yaml:"update_interval"` // how often to check (default: "24h")
	} `yaml:"signatures"`

	WebUI struct {
		Enabled   bool   `yaml:"enabled"`
		Listen    string `yaml:"listen"`
		AuthToken string `yaml:"auth_token"`
		TLSCert   string `yaml:"tls_cert"`
		TLSKey    string `yaml:"tls_key"`
		UIDir     string `yaml:"ui_dir"` // path to UI files on disk (default: /opt/csm/ui)
	} `yaml:"webui"`

	EmailAV EmailAVConfig `yaml:"email_av"`

	Firewall *firewall.FirewallConfig `yaml:"firewall"`

	GeoIP struct {
		AccountID      string   `yaml:"account_id"`
		LicenseKey     string   `yaml:"license_key"`
		Editions       []string `yaml:"editions"`
		AutoUpdate     *bool    `yaml:"auto_update"`     // nil = true when credentials set
		UpdateInterval string   `yaml:"update_interval"` // default "24h"
	} `yaml:"geoip"`

	C2Blocklist   []string `yaml:"c2_blocklist"`
	BackdoorPorts []int    `yaml:"backdoor_ports"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg.ConfigFile = path

	// Defaults
	if cfg.StatePath == "" {
		cfg.StatePath = "/opt/csm/state"
	}
	if cfg.Signatures.RulesDir == "" {
		cfg.Signatures.RulesDir = "/opt/csm/rules"
	}
	if cfg.WebUI.Listen == "" {
		cfg.WebUI.Listen = "0.0.0.0:9443"
	}
	if cfg.Thresholds.MailQueueWarn == 0 {
		cfg.Thresholds.MailQueueWarn = 500
	}
	if cfg.Thresholds.MailQueueCrit == 0 {
		cfg.Thresholds.MailQueueCrit = 2000
	}
	if cfg.Thresholds.StateExpiryHours == 0 {
		cfg.Thresholds.StateExpiryHours = 24
	}
	if cfg.Thresholds.DeepScanIntervalMin == 0 {
		cfg.Thresholds.DeepScanIntervalMin = 60
	}
	if cfg.Thresholds.WPCoreCheckIntervalMin == 0 {
		cfg.Thresholds.WPCoreCheckIntervalMin = 60
	}
	if cfg.Thresholds.WebshellScanIntervalMin == 0 {
		cfg.Thresholds.WebshellScanIntervalMin = 30
	}
	if cfg.Thresholds.FilesystemScanIntervalMin == 0 {
		cfg.Thresholds.FilesystemScanIntervalMin = 30
	}
	if cfg.Alerts.MaxPerHour == 0 {
		cfg.Alerts.MaxPerHour = 10
	}
	if cfg.Challenge.ListenPort == 0 {
		cfg.Challenge.ListenPort = 8439
	}
	if cfg.Challenge.Difficulty == 0 {
		cfg.Challenge.Difficulty = 2
	}
	if cfg.Firewall == nil {
		cfg.Firewall = firewall.DefaultConfig()
	}
	if len(cfg.GeoIP.Editions) == 0 {
		cfg.GeoIP.Editions = []string{"GeoLite2-City", "GeoLite2-ASN"}
	}
	if cfg.GeoIP.UpdateInterval == "" {
		cfg.GeoIP.UpdateInterval = "24h"
	}
	EmailAVDefaults(&cfg.EmailAV)

	return cfg, nil
}

func Save(cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(cfg.ConfigFile, data, 0600)
}

// Validate checks the config for common mistakes.
func Validate(cfg *Config) []string {
	var errs []string

	if cfg.Hostname == "" || cfg.Hostname == "SET_HOSTNAME_HERE" {
		errs = append(errs, "hostname is not set")
	}

	if !cfg.Alerts.Email.Enabled && !cfg.Alerts.Webhook.Enabled {
		errs = append(errs, "no alert method enabled (enable email or webhook)")
	}

	if cfg.Alerts.Email.Enabled {
		if len(cfg.Alerts.Email.To) == 0 {
			errs = append(errs, "email alerts enabled but no recipients configured")
		}
		for _, to := range cfg.Alerts.Email.To {
			if to == "SET_EMAIL_HERE" || !strings.Contains(to, "@") {
				errs = append(errs, fmt.Sprintf("invalid email recipient: %s", to))
			}
		}
		if cfg.Alerts.Email.SMTP == "" {
			errs = append(errs, "email alerts enabled but no SMTP server configured")
		}
	}

	if cfg.Alerts.Webhook.Enabled && cfg.Alerts.Webhook.URL == "" {
		errs = append(errs, "webhook alerts enabled but no URL configured")
	}

	if cfg.Alerts.Heartbeat.Enabled && cfg.Alerts.Heartbeat.URL == "" {
		errs = append(errs, "heartbeat enabled but no URL configured")
	}

	if cfg.WebUI.Enabled && cfg.WebUI.AuthToken == "" {
		errs = append(errs, "webui enabled but no auth_token configured")
	}

	for _, cc := range cfg.Suppressions.TrustedCountries {
		if len(cc) != 2 {
			errs = append(errs, fmt.Sprintf("invalid country code in trusted_countries: %q (expected 2-letter ISO code)", cc))
		}
	}

	return errs
}
