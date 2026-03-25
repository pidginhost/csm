package config

import (
	"fmt"
	"os"
	"strings"

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
		UPCPWindowStart string   `yaml:"upcp_window_start"`
		UPCPWindowEnd   string   `yaml:"upcp_window_end"`
		KnownAPITokens  []string `yaml:"known_api_tokens"`
		IgnorePaths     []string `yaml:"ignore_paths"`
	} `yaml:"suppressions"`

	AutoResponse struct {
		Enabled         bool `yaml:"enabled"`
		KillProcesses   bool `yaml:"kill_processes"`
		QuarantineFiles bool `yaml:"quarantine_files"`
	} `yaml:"auto_response"`

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

	return errs
}
