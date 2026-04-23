package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/pidginhost/csm/internal/firewall"
)

type Config struct {
	ConfigFile string `yaml:"-"`

	Hostname string `yaml:"hostname" hotreload:"restart"`

	Alerts struct {
		Email struct {
			Enabled        bool     `yaml:"enabled"`
			To             []string `yaml:"to"`
			From           string   `yaml:"from"`
			SMTP           string   `yaml:"smtp"`
			DisabledChecks []string `yaml:"disabled_checks"`
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
	} `yaml:"alerts" hotreload:"safe"`

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
		PluginCheckIntervalMin    int `yaml:"plugin_check_interval_min"`
		BruteForceWindow          int `yaml:"brute_force_window"`

		SMTPBruteForceThreshold    int `yaml:"smtp_bruteforce_threshold"`
		SMTPBruteForceWindowMin    int `yaml:"smtp_bruteforce_window_min"`
		SMTPBruteForceSuppressMin  int `yaml:"smtp_bruteforce_suppress_min"`
		SMTPBruteForceSubnetThresh int `yaml:"smtp_bruteforce_subnet_threshold"`
		SMTPAccountSprayThreshold  int `yaml:"smtp_account_spray_threshold"`
		SMTPBruteForceMaxTracked   int `yaml:"smtp_bruteforce_max_tracked"`

		MailBruteForceThreshold    int `yaml:"mail_bruteforce_threshold"`
		MailBruteForceWindowMin    int `yaml:"mail_bruteforce_window_min"`
		MailBruteForceSuppressMin  int `yaml:"mail_bruteforce_suppress_min"`
		MailBruteForceSubnetThresh int `yaml:"mail_bruteforce_subnet_threshold"`
		MailAccountSprayThreshold  int `yaml:"mail_account_spray_threshold"`
		MailBruteForceMaxTracked   int `yaml:"mail_bruteforce_max_tracked"`
	} `yaml:"thresholds" hotreload:"safe"`

	InfraIPs []string `yaml:"infra_ips" hotreload:"restart"`

	StatePath string `yaml:"state_path" hotreload:"restart"`

	Suppressions struct {
		UPCPWindowStart       string   `yaml:"upcp_window_start"`
		UPCPWindowEnd         string   `yaml:"upcp_window_end"`
		KnownAPITokens        []string `yaml:"known_api_tokens"`
		IgnorePaths           []string `yaml:"ignore_paths"`
		SuppressWebmail       bool     `yaml:"suppress_webmail_alerts"`      // don't alert on webmail logins
		SuppressCpanelLogin   bool     `yaml:"suppress_cpanel_login_alerts"` // don't alert on cPanel direct logins
		SuppressBlockedAlerts bool     `yaml:"suppress_blocked_alerts"`      // don't alert on IPs that were auto-blocked
		TrustedCountries      []string `yaml:"trusted_countries"`            // ISO 3166-1 alpha-2 codes - suppress cPanel login alerts from these countries
	} `yaml:"suppressions" hotreload:"safe"`

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
		CleanDatabase      bool   `yaml:"clean_database"`      // auto-clean malicious DB injections, revoke sessions, block attacker IPs (default false)
	} `yaml:"auto_response" hotreload:"safe"`

	Challenge struct {
		Enabled        bool     `yaml:"enabled"`         // enable challenge pages instead of hard block for some IPs
		ListenPort     int      `yaml:"listen_port"`     // port for challenge server (default: 8439)
		Secret         string   `yaml:"secret"`          // HMAC secret for challenge tokens (auto-generated if empty)
		Difficulty     int      `yaml:"difficulty"`      // proof-of-work difficulty 0-5 (default: 2)
		TrustedProxies []string `yaml:"trusted_proxies"` // IPs allowed to set X-Forwarded-For (empty = trust RemoteAddr only)
	} `yaml:"challenge" hotreload:"restart"`

	PHPShield struct {
		Enabled bool `yaml:"enabled"` // watch php_events.log for PHP Shield alerts (default: false)
	} `yaml:"php_shield" hotreload:"restart"`

	Reputation struct {
		AbuseIPDBKey string   `yaml:"abuseipdb_key"`
		Whitelist    []string `yaml:"whitelist"` // IPs to never flag as malicious
	} `yaml:"reputation" hotreload:"safe"`

	Signatures struct {
		RulesDir       string `yaml:"rules_dir"`
		UpdateURL      string `yaml:"update_url"`
		AutoUpdate     bool   `yaml:"auto_update"`     // auto-download rules daily (default: true if update_url set)
		UpdateInterval string `yaml:"update_interval"` // how often to check (default: "24h")
		SigningKey     string `yaml:"signing_key"`     // hex-encoded ed25519 public key for verifying rule updates
		YaraForge      struct {
			Enabled        bool   `yaml:"enabled"`
			Tier           string `yaml:"tier"`            // "core", "extended", "full" (default: "core")
			UpdateInterval string `yaml:"update_interval"` // default: "168h" (weekly)
		} `yaml:"yara_forge"`
		DisabledRules []string `yaml:"disabled_rules"` // YARA rule names to exclude from Forge downloads
		// YaraWorkerEnabled is a tri-state: nil means "use system default"
		// (default-on, per ROADMAP item 2 follow-up), *true means explicit on,
		// *false means explicit off. Callers must nil-check before dereferencing;
		// daemon.yaraWorkerOn() is the canonical accessor.
		YaraWorkerEnabled *bool `yaml:"yara_worker_enabled"`
	} `yaml:"signatures" hotreload:"restart"`

	WebUI struct {
		Enabled      bool   `yaml:"enabled"`
		Listen       string `yaml:"listen"`
		AuthToken    string `yaml:"auth_token"`
		MetricsToken string `yaml:"metrics_token" hotreload:"safe"` // optional Bearer token for /metrics; rotate via SIGHUP without restart
		TLSCert      string `yaml:"tls_cert"`
		TLSKey       string `yaml:"tls_key"`
		UIDir        string `yaml:"ui_dir"` // path to UI files on disk (default: /opt/csm/ui)
	} `yaml:"webui" hotreload:"restart"`

	EmailAV EmailAVConfig `yaml:"email_av" hotreload:"restart"`

	EmailProtection struct {
		PasswordCheckIntervalMin int      `yaml:"password_check_interval_min"`
		HighVolumeSenders        []string `yaml:"high_volume_senders"`
		RateWarnThreshold        int      `yaml:"rate_warn_threshold"`
		RateCritThreshold        int      `yaml:"rate_crit_threshold"`
		RateWindowMin            int      `yaml:"rate_window_min"`
		KnownForwarders          []string `yaml:"known_forwarders"`
	} `yaml:"email_protection" hotreload:"safe"`

	Firewall *firewall.FirewallConfig `yaml:"firewall" hotreload:"restart"`

	GeoIP struct {
		AccountID      string   `yaml:"account_id"`
		LicenseKey     string   `yaml:"license_key"`
		Editions       []string `yaml:"editions"`
		AutoUpdate     *bool    `yaml:"auto_update"`     // nil = true when credentials set
		UpdateInterval string   `yaml:"update_interval"` // default "24h"
	} `yaml:"geoip" hotreload:"restart"`

	ModSecErrorLog string `yaml:"modsec_error_log" hotreload:"restart"`

	ModSec struct {
		RulesFile     string `yaml:"rules_file"`     // path to modsec2.user.conf
		OverridesFile string `yaml:"overrides_file"` // path to csm-overrides.conf
		ReloadCommand string `yaml:"reload_command"` // e.g. "systemctl restart lsws"
	} `yaml:"modsec" hotreload:"restart"`

	// WebServer overrides the auto-detected web server paths. Every field is
	// optional: anything left blank or empty falls back to what
	// platform.Detect() returned at startup. Intended for hosts with a
	// custom layout (reverse proxy in front of a second daemon, non-standard
	// package locations, chroot, etc.).
	WebServer struct {
		Type         string   `yaml:"type"`              // "apache", "nginx", "litespeed" — overrides auto-detect
		ConfigDir    string   `yaml:"config_dir"`        // e.g. /etc/apache2 or /etc/nginx
		AccessLogs   []string `yaml:"access_logs"`       // candidate access-log paths, tried in order
		ErrorLogs    []string `yaml:"error_logs"`        // candidate error-log paths (used for modsec denies)
		ModSecAudits []string `yaml:"modsec_audit_logs"` // candidate ModSecurity audit-log paths
	} `yaml:"web_server" hotreload:"restart"`

	// AccountRoots lets operators point the account-scan based checks at
	// non-cPanel web root layouts. Each entry is a glob pattern expanded
	// at check time. Examples:
	//
	//   account_roots:
	//     - /var/www/*/public
	//     - /srv/http/*
	//     - /home/*/public_html        # cPanel default (implicit when unset on cPanel)
	//
	// When unset, CSM uses the cPanel default of /home/*/public_html on
	// cPanel hosts and an empty list on non-cPanel hosts (account-scan
	// checks skip entirely). See docs/src/configuration.md for the full
	// list of checks that consume this.
	AccountRoots []string `yaml:"account_roots" hotreload:"restart"`

	Performance struct {
		Enabled                     *bool   `yaml:"enabled"`
		LoadHighMultiplier          float64 `yaml:"load_high_multiplier"`
		LoadCriticalMultiplier      float64 `yaml:"load_critical_multiplier"`
		PHPProcessWarnPerUser       int     `yaml:"php_process_warn_per_user"`
		PHPProcessCriticalTotalMult int     `yaml:"php_process_critical_total_multiplier"`
		ErrorLogWarnSizeMB          int     `yaml:"error_log_warn_size_mb"`
		MySQLJoinBufferMaxMB        int     `yaml:"mysql_join_buffer_max_mb"`
		MySQLWaitTimeoutMax         int     `yaml:"mysql_wait_timeout_max"`
		MySQLMaxConnectionsPerUser  int     `yaml:"mysql_max_connections_per_user"`
		RedisBgsaveMinInterval      int     `yaml:"redis_bgsave_min_interval"`
		RedisLargeDatasetGB         int     `yaml:"redis_large_dataset_gb"`
		WPMemoryLimitMaxMB          int     `yaml:"wp_memory_limit_max_mb"`
		WPTransientWarnMB           int     `yaml:"wp_transient_warn_mb"`
		WPTransientCriticalMB       int     `yaml:"wp_transient_critical_mb"`
	} `yaml:"performance" hotreload:"restart"`

	Cloudflare struct {
		Enabled      bool `yaml:"enabled"`
		RefreshHours int  `yaml:"refresh_hours"`
	} `yaml:"cloudflare" hotreload:"restart"`

	C2Blocklist   []string `yaml:"c2_blocklist" hotreload:"restart"`
	BackdoorPorts []int    `yaml:"backdoor_ports" hotreload:"restart"`

	// Retention bounds bbolt growth. When enabled, a daily sweep prunes
	// per-bucket entries older than the configured TTL and an online
	// compaction pass shrinks the on-disk file once the fill ratio drops
	// below CompactFillRatio (and the file exceeds CompactMinSizeMB).
	// All fields are hot-reload:"restart" because the retention goroutine
	// captures these on daemon start.
	Retention struct {
		Enabled          bool    `yaml:"enabled"`             // opt-in
		FindingsDays     int     `yaml:"findings_days"`       // default 90
		HistoryDays      int     `yaml:"history_days"`        // default 30
		ReputationDays   int     `yaml:"reputation_days"`     // default 180
		SweepInterval    string  `yaml:"sweep_interval"`      // default "24h"
		CompactMinSizeMB int     `yaml:"compact_min_size_mb"` // default 128
		CompactFillRatio float64 `yaml:"compact_fill_ratio"`  // default 0.5
	} `yaml:"retention" hotreload:"restart"`

	// Sentry ships panics and selected errors to a Sentry server for
	// aggregation across hosts. Disabled by default; set enabled=true and
	// provide a DSN from the Sentry project. Init is one-shot: changes
	// require a daemon restart.
	Sentry struct {
		Enabled     bool    `yaml:"enabled"`
		DSN         string  `yaml:"dsn"`
		Environment string  `yaml:"environment"` // e.g. "production", "staging"
		SampleRate  float64 `yaml:"sample_rate"` // 0 -> 1.0 (capture all errors)
		Debug       bool    `yaml:"debug"`       // SDK debug logs to stderr
	} `yaml:"sentry" hotreload:"restart"`
}

func applyDefaults(cfg *Config) {
	// Defaults
	if cfg.StatePath == "" {
		cfg.StatePath = "/opt/csm/state"
	}
	if cfg.Signatures.RulesDir == "" {
		cfg.Signatures.RulesDir = "/opt/csm/rules"
	}
	if cfg.Signatures.YaraForge.Tier == "" {
		cfg.Signatures.YaraForge.Tier = "core"
	}
	if cfg.Signatures.YaraForge.UpdateInterval == "" {
		cfg.Signatures.YaraForge.UpdateInterval = "168h"
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
	if cfg.Thresholds.PluginCheckIntervalMin == 0 {
		cfg.Thresholds.PluginCheckIntervalMin = 1440
	}
	if cfg.Thresholds.BruteForceWindow == 0 {
		cfg.Thresholds.BruteForceWindow = 5000
	}
	if cfg.Thresholds.SMTPBruteForceThreshold == 0 {
		cfg.Thresholds.SMTPBruteForceThreshold = 5
	}
	if cfg.Thresholds.SMTPBruteForceWindowMin == 0 {
		cfg.Thresholds.SMTPBruteForceWindowMin = 10
	}
	if cfg.Thresholds.SMTPBruteForceSuppressMin == 0 {
		cfg.Thresholds.SMTPBruteForceSuppressMin = 60
	}
	if cfg.Thresholds.SMTPBruteForceSubnetThresh == 0 {
		cfg.Thresholds.SMTPBruteForceSubnetThresh = 8
	}
	if cfg.Thresholds.SMTPAccountSprayThreshold == 0 {
		cfg.Thresholds.SMTPAccountSprayThreshold = 12
	}
	if cfg.Thresholds.SMTPBruteForceMaxTracked == 0 {
		cfg.Thresholds.SMTPBruteForceMaxTracked = 20000
	}
	if cfg.Thresholds.MailBruteForceThreshold == 0 {
		cfg.Thresholds.MailBruteForceThreshold = 5
	}
	if cfg.Thresholds.MailBruteForceWindowMin == 0 {
		cfg.Thresholds.MailBruteForceWindowMin = 10
	}
	if cfg.Thresholds.MailBruteForceSuppressMin == 0 {
		cfg.Thresholds.MailBruteForceSuppressMin = 60
	}
	if cfg.Thresholds.MailBruteForceSubnetThresh == 0 {
		cfg.Thresholds.MailBruteForceSubnetThresh = 8
	}
	if cfg.Thresholds.MailAccountSprayThreshold == 0 {
		cfg.Thresholds.MailAccountSprayThreshold = 12
	}
	if cfg.Thresholds.MailBruteForceMaxTracked == 0 {
		cfg.Thresholds.MailBruteForceMaxTracked = 20000
	}
	if cfg.Alerts.MaxPerHour == 0 {
		cfg.Alerts.MaxPerHour = 30
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

	if cfg.EmailProtection.PasswordCheckIntervalMin == 0 {
		cfg.EmailProtection.PasswordCheckIntervalMin = 1440
	}
	if cfg.EmailProtection.RateWarnThreshold == 0 {
		cfg.EmailProtection.RateWarnThreshold = 50
	}
	if cfg.EmailProtection.RateCritThreshold == 0 {
		cfg.EmailProtection.RateCritThreshold = 100
	}
	if cfg.EmailProtection.RateWindowMin == 0 {
		cfg.EmailProtection.RateWindowMin = 10
	}

	// Performance defaults.
	// Enabled is a tri-state *bool: nil means "use system default (on)", true means
	// explicitly enabled, false means explicitly disabled. We do NOT apply a default
	// here so that callers can distinguish "operator left it unset" (nil) from
	// "operator set it to true" (&true). All callers must nil-check before dereferencing;
	// perfEnabled() in checks/performance.go treats nil as true.
	if cfg.Performance.LoadHighMultiplier == 0 {
		cfg.Performance.LoadHighMultiplier = 1.0
	}
	if cfg.Performance.LoadCriticalMultiplier == 0 {
		cfg.Performance.LoadCriticalMultiplier = 2.0
	}
	if cfg.Performance.PHPProcessWarnPerUser == 0 {
		cfg.Performance.PHPProcessWarnPerUser = 20
	}
	if cfg.Performance.PHPProcessCriticalTotalMult == 0 {
		cfg.Performance.PHPProcessCriticalTotalMult = 5
	}
	if cfg.Performance.ErrorLogWarnSizeMB == 0 {
		cfg.Performance.ErrorLogWarnSizeMB = 50
	}
	if cfg.Performance.MySQLJoinBufferMaxMB == 0 {
		cfg.Performance.MySQLJoinBufferMaxMB = 64
	}
	if cfg.Performance.MySQLWaitTimeoutMax == 0 {
		cfg.Performance.MySQLWaitTimeoutMax = 3600
	}
	if cfg.Performance.MySQLMaxConnectionsPerUser == 0 {
		cfg.Performance.MySQLMaxConnectionsPerUser = 10
	}
	if cfg.Performance.RedisBgsaveMinInterval == 0 {
		cfg.Performance.RedisBgsaveMinInterval = 900
	}
	if cfg.Performance.RedisLargeDatasetGB == 0 {
		cfg.Performance.RedisLargeDatasetGB = 4
	}
	if cfg.Performance.WPMemoryLimitMaxMB == 0 {
		cfg.Performance.WPMemoryLimitMaxMB = 512
	}
	if cfg.Performance.WPTransientWarnMB == 0 {
		cfg.Performance.WPTransientWarnMB = 1
	}
	if cfg.Performance.WPTransientCriticalMB == 0 {
		cfg.Performance.WPTransientCriticalMB = 10
	}

	if cfg.Cloudflare.RefreshHours == 0 {
		cfg.Cloudflare.RefreshHours = 6
	}

	// Retention: defaults apply whether or not the feature is enabled, so
	// that flipping `enabled: true` without further tuning gives the
	// documented behaviour.
	if cfg.Retention.FindingsDays == 0 {
		cfg.Retention.FindingsDays = 90
	}
	if cfg.Retention.HistoryDays == 0 {
		cfg.Retention.HistoryDays = 30
	}
	if cfg.Retention.ReputationDays == 0 {
		cfg.Retention.ReputationDays = 180
	}
	if cfg.Retention.SweepInterval == "" {
		cfg.Retention.SweepInterval = "24h"
	}
	if cfg.Retention.CompactMinSizeMB == 0 {
		cfg.Retention.CompactMinSizeMB = 128
	}
	if cfg.Retention.CompactFillRatio == 0 {
		cfg.Retention.CompactFillRatio = 0.5
	}
}

// LoadBytes decodes a YAML config body and applies all defaults,
// matching Load. ConfigFile is left empty; the caller sets it.
func LoadBytes(data []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	applyDefaults(cfg)
	return cfg, nil
}

func Load(path string) (*Config, error) {
	// #nosec G304 -- path is operator-supplied config file (CLI flag / env).
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg, err := LoadBytes(data)
	if err != nil {
		return nil, err
	}
	cfg.ConfigFile = path
	return cfg, nil
}

func Save(cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(cfg.ConfigFile, data, 0600)
}
