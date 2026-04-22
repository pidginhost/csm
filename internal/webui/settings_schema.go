package webui

// OptionGroup is an ordered label + values pair used to render grouped
// multi-select options (e.g. "Authentication & Login" → [cpanel_login, ...]).
type OptionGroup struct {
	Label  string   `json:"label"`
	Values []string `json:"values"`
}

// SettingsField describes a single editable leaf within a settings
// section. YAMLPath is the dotted key path relative to the section's
// YAMLPath. For example inside the Alerts section, the field with
// YAMLPath "email.enabled" has full path "alerts.email.enabled".
//
// For Type "[]enum" fields, Options and/or OptionGroups are resolved at
// request time. A field may either declare a static Options list or set
// OptionsSource to have the handler populate Options/OptionGroups from a
// registry ("check_names", "geoip_editions").
type SettingsField struct {
	YAMLPath      string        `json:"yaml_path"`
	Type          string        `json:"type"`
	Label         string        `json:"label"`
	Help          string        `json:"help,omitempty"`
	Secret        bool          `json:"secret,omitempty"`
	Nullable      bool          `json:"nullable,omitempty"`
	Min           *int64        `json:"min,omitempty"`
	Max           *int64        `json:"max,omitempty"`
	Options       []string      `json:"options,omitempty"`
	OptionGroups  []OptionGroup `json:"option_groups,omitempty"`
	OptionsSource string        `json:"options_source,omitempty"`
	Placeholder   string        `json:"placeholder,omitempty"`
}

// SettingsSection groups the fields of one top-level Config sub-tree.
// YAMLPath is the root key in csm.yaml (e.g. "auto_response"). ID is
// the URL-path identifier used by the API. Restart is a UI hint based
// on the current hotreload struct tag; final safe-vs-restart authority
// comes from config.Diff at runtime. Icon is a Tabler icon suffix (e.g.
// "bell" for "ti ti-bell"); Group is the nav category the section lives
// in ("Alerting", "Detection", "Integrations", "Ops").
type SettingsSection struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	YAMLPath string          `json:"yaml_path"`
	Restart  bool            `json:"restart_hint"`
	Icon     string          `json:"icon,omitempty"`
	Group    string          `json:"group,omitempty"`
	Fields   []SettingsField `json:"fields"`
}

// Section groups for the sidebar. Order here defines order in the UI.
const (
	SectionGroupAlerting     = "Alerting"
	SectionGroupDetection    = "Detection"
	SectionGroupIntegrations = "Integrations"
	SectionGroupOps          = "Operations"
)

// SectionGroupOrder is the display order of sidebar group headers.
var SectionGroupOrder = []string{
	SectionGroupAlerting,
	SectionGroupDetection,
	SectionGroupIntegrations,
	SectionGroupOps,
}

func int64p(v int64) *int64 { return &v }

var settingsSections = []SettingsSection{
	{
		ID:       "alerts",
		Title:    "Alerts",
		YAMLPath: "alerts",
		Icon:     "bell",
		Group:    SectionGroupAlerting,
		Restart:  false,
		Fields: []SettingsField{
			{YAMLPath: "email.enabled", Type: "bool", Label: "Email alerts enabled"},
			{YAMLPath: "email.to", Type: "[]string", Label: "Recipients", Help: "One email address per line"},
			{YAMLPath: "email.from", Type: "string", Label: "From address"},
			{YAMLPath: "email.smtp", Type: "string", Label: "SMTP server", Placeholder: "smtp.example.com:587"},
			{YAMLPath: "email.disabled_checks", Type: "[]enum", Label: "Disabled check names", OptionsSource: "check_names", Help: "Findings with these check names never trigger email alerts."},
			{YAMLPath: "webhook.enabled", Type: "bool", Label: "Webhook alerts enabled"},
			{YAMLPath: "webhook.url", Type: "string", Label: "Webhook URL"},
			{YAMLPath: "webhook.type", Type: "enum", Label: "Webhook type", Options: []string{"slack", "discord", "generic"}},
			{YAMLPath: "heartbeat.enabled", Type: "bool", Label: "Heartbeat enabled"},
			{YAMLPath: "heartbeat.url", Type: "string", Label: "Heartbeat URL"},
			{YAMLPath: "max_per_hour", Type: "int", Label: "Max alerts per hour", Min: int64p(0), Max: int64p(10000)},
		},
	},
	{
		ID:       "thresholds",
		Title:    "Thresholds",
		YAMLPath: "thresholds",
		Icon:     "adjustments",
		Group:    SectionGroupAlerting,
		Restart:  false,
		Fields: []SettingsField{
			{YAMLPath: "mail_queue_warn", Type: "int", Label: "Mail queue warn", Min: int64p(0)},
			{YAMLPath: "mail_queue_crit", Type: "int", Label: "Mail queue critical", Min: int64p(0)},
			{YAMLPath: "state_expiry_hours", Type: "int", Label: "State expiry (hours)", Min: int64p(1)},
			{YAMLPath: "deep_scan_interval_min", Type: "int", Label: "Deep scan interval (min)", Min: int64p(1)},
			{YAMLPath: "wp_core_check_interval_min", Type: "int", Label: "WP core check interval (min)", Min: int64p(1)},
			{YAMLPath: "webshell_scan_interval_min", Type: "int", Label: "Webshell scan interval (min)", Min: int64p(1)},
			{YAMLPath: "filesystem_scan_interval_min", Type: "int", Label: "Filesystem scan interval (min)", Min: int64p(1)},
			{YAMLPath: "multi_ip_login_threshold", Type: "int", Label: "Multi-IP login threshold", Min: int64p(1)},
			{YAMLPath: "multi_ip_login_window_min", Type: "int", Label: "Multi-IP login window (min)", Min: int64p(1)},
			{YAMLPath: "plugin_check_interval_min", Type: "int", Label: "Plugin check interval (min)", Min: int64p(1)},
			{YAMLPath: "brute_force_window", Type: "int", Label: "Brute force window", Min: int64p(1)},
			{YAMLPath: "smtp_bruteforce_threshold", Type: "int", Label: "SMTP bruteforce threshold", Min: int64p(1)},
			{YAMLPath: "smtp_bruteforce_window_min", Type: "int", Label: "SMTP bruteforce window (min)", Min: int64p(1)},
			{YAMLPath: "smtp_bruteforce_suppress_min", Type: "int", Label: "SMTP bruteforce suppress (min)", Min: int64p(1)},
			{YAMLPath: "smtp_bruteforce_subnet_threshold", Type: "int", Label: "SMTP bruteforce /24 threshold", Min: int64p(1)},
			{YAMLPath: "smtp_account_spray_threshold", Type: "int", Label: "SMTP account spray threshold", Min: int64p(1)},
			{YAMLPath: "smtp_bruteforce_max_tracked", Type: "int", Label: "SMTP bruteforce max tracked", Min: int64p(100)},
			{YAMLPath: "mail_bruteforce_threshold", Type: "int", Label: "Mail bruteforce threshold", Min: int64p(1)},
			{YAMLPath: "mail_bruteforce_window_min", Type: "int", Label: "Mail bruteforce window (min)", Min: int64p(1)},
			{YAMLPath: "mail_bruteforce_suppress_min", Type: "int", Label: "Mail bruteforce suppress (min)", Min: int64p(1)},
			{YAMLPath: "mail_bruteforce_subnet_threshold", Type: "int", Label: "Mail bruteforce /24 threshold", Min: int64p(1)},
			{YAMLPath: "mail_account_spray_threshold", Type: "int", Label: "Mail account spray threshold", Min: int64p(1)},
			{YAMLPath: "mail_bruteforce_max_tracked", Type: "int", Label: "Mail bruteforce max tracked", Min: int64p(100)},
		},
	},
	{
		ID:       "suppressions",
		Title:    "Suppressions",
		YAMLPath: "suppressions",
		Icon:     "volume-off",
		Group:    SectionGroupAlerting,
		Restart:  false,
		Fields: []SettingsField{
			{YAMLPath: "upcp_window_start", Type: "string", Label: "UPCP window start (HH:MM)"},
			{YAMLPath: "upcp_window_end", Type: "string", Label: "UPCP window end (HH:MM)"},
			{YAMLPath: "known_api_tokens", Type: "[]string", Label: "Known API tokens (hashed)"},
			{YAMLPath: "ignore_paths", Type: "[]string", Label: "Ignore paths"},
			{YAMLPath: "suppress_webmail_alerts", Type: "bool", Label: "Suppress webmail login alerts"},
			{YAMLPath: "suppress_cpanel_login_alerts", Type: "bool", Label: "Suppress cPanel login alerts"},
			{YAMLPath: "suppress_blocked_alerts", Type: "bool", Label: "Suppress alerts on auto-blocked IPs"},
			{YAMLPath: "trusted_countries", Type: "[]string", Label: "Trusted countries (ISO 3166-1 alpha-2)"},
		},
	},
	{
		ID:       "auto_response",
		Title:    "Auto-Response",
		YAMLPath: "auto_response",
		Icon:     "bolt",
		Group:    SectionGroupDetection,
		Restart:  false,
		Fields: []SettingsField{
			{YAMLPath: "enabled", Type: "bool", Label: "Auto-response enabled"},
			{YAMLPath: "kill_processes", Type: "bool", Label: "Kill malicious processes"},
			{YAMLPath: "quarantine_files", Type: "bool", Label: "Quarantine malicious files"},
			{YAMLPath: "block_ips", Type: "bool", Label: "Block attacker IPs"},
			{YAMLPath: "block_expiry", Type: "string", Label: "Block expiry", Placeholder: "24h"},
			{YAMLPath: "enforce_permissions", Type: "bool", Label: "Auto-chmod 644 world/group-writable PHP"},
			{YAMLPath: "block_cpanel_logins", Type: "bool", Label: "Block on cPanel/webmail login alerts"},
			{YAMLPath: "netblock", Type: "bool", Label: "Auto-block /24 on threshold"},
			{YAMLPath: "netblock_threshold", Type: "int", Label: "Netblock threshold", Min: int64p(1)},
			{YAMLPath: "permblock", Type: "bool", Label: "Auto-promote to permanent"},
			{YAMLPath: "permblock_count", Type: "int", Label: "Temp blocks before permanent", Min: int64p(1)},
			{YAMLPath: "permblock_interval", Type: "string", Label: "Permblock window", Placeholder: "24h"},
			{YAMLPath: "clean_database", Type: "bool", Label: "Auto-clean DB injections"},
		},
	},
	{
		ID:       "reputation",
		Title:    "Reputation",
		YAMLPath: "reputation",
		Icon:     "shield-check",
		Group:    SectionGroupIntegrations,
		Restart:  false,
		Fields: []SettingsField{
			{YAMLPath: "abuseipdb_key", Type: "string", Label: "AbuseIPDB API key", Secret: true},
			{YAMLPath: "whitelist", Type: "[]string", Label: "Whitelisted IPs", Help: "Never flagged as malicious"},
		},
	},
	{
		ID:       "email_protection",
		Title:    "Email Protection",
		YAMLPath: "email_protection",
		Icon:     "mail-shield",
		Group:    SectionGroupDetection,
		Restart:  false,
		Fields: []SettingsField{
			{YAMLPath: "password_check_interval_min", Type: "int", Label: "Password check interval (min)", Min: int64p(1)},
			{YAMLPath: "high_volume_senders", Type: "[]string", Label: "High-volume senders"},
			{YAMLPath: "rate_warn_threshold", Type: "int", Label: "Rate warn threshold", Min: int64p(1)},
			{YAMLPath: "rate_crit_threshold", Type: "int", Label: "Rate critical threshold", Min: int64p(1)},
			{YAMLPath: "rate_window_min", Type: "int", Label: "Rate window (min)", Min: int64p(1)},
			{YAMLPath: "known_forwarders", Type: "[]string", Label: "Known forwarders"},
		},
	},
	{
		ID:       "challenge",
		Title:    "Challenge",
		YAMLPath: "challenge",
		Icon:     "user-question",
		Group:    SectionGroupDetection,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "enabled", Type: "bool", Label: "Challenge pages enabled"},
			{YAMLPath: "listen_port", Type: "int", Label: "Listen port", Min: int64p(1), Max: int64p(65535)},
			{YAMLPath: "difficulty", Type: "int", Label: "PoW difficulty (0-5)", Min: int64p(0), Max: int64p(5)},
			{YAMLPath: "trusted_proxies", Type: "[]string", Label: "Trusted proxy IPs"},
			// challenge.secret is auto-generated at daemon startup; intentionally
			// omitted so the UI cannot overwrite or leak the HMAC key.
		},
	},
	{
		ID:       "php_shield",
		Title:    "PHP Shield",
		YAMLPath: "php_shield",
		Icon:     "brand-php",
		Group:    SectionGroupDetection,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "enabled", Type: "bool", Label: "PHP Shield enabled"},
		},
	},
	{
		ID:       "signatures",
		Title:    "Signatures",
		YAMLPath: "signatures",
		Icon:     "scan",
		Group:    SectionGroupDetection,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "auto_update", Type: "bool", Label: "Auto-update rules"},
			{YAMLPath: "update_interval", Type: "string", Label: "Update interval", Placeholder: "24h"},
			{YAMLPath: "yara_forge.enabled", Type: "bool", Label: "YARA-Forge enabled"},
			{YAMLPath: "yara_forge.tier", Type: "enum", Label: "YARA-Forge tier", Options: []string{"core", "extended", "full"}},
			{YAMLPath: "yara_forge.update_interval", Type: "string", Label: "YARA-Forge interval", Placeholder: "168h"},
			{YAMLPath: "disabled_rules", Type: "[]string", Label: "Disabled rule names"},
			{YAMLPath: "yara_worker_enabled", Type: "bool", Label: "Run YARA-X in supervised worker"},
		},
	},
	{
		ID:       "email_av",
		Title:    "Email AV",
		YAMLPath: "email_av",
		Icon:     "virus",
		Group:    SectionGroupDetection,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "enabled", Type: "bool", Label: "Email AV enabled"},
			{YAMLPath: "clamd_socket", Type: "string", Label: "clamd socket"},
			{YAMLPath: "scan_timeout", Type: "string", Label: "Scan timeout", Placeholder: "30s"},
			{YAMLPath: "max_attachment_size", Type: "int", Label: "Max attachment bytes", Min: int64p(1024)},
			{YAMLPath: "max_archive_depth", Type: "int", Label: "Max archive depth", Min: int64p(0)},
			{YAMLPath: "max_archive_files", Type: "int", Label: "Max archive files", Min: int64p(1)},
			{YAMLPath: "max_extraction_size", Type: "int", Label: "Max extraction bytes", Min: int64p(1024)},
			{YAMLPath: "quarantine_infected", Type: "bool", Label: "Quarantine infected"},
			{YAMLPath: "scan_concurrency", Type: "int", Label: "Scan concurrency", Min: int64p(1), Max: int64p(64)},
		},
	},
	{
		ID:       "modsec",
		Title:    "ModSecurity",
		YAMLPath: "modsec",
		Icon:     "shield-lock",
		Group:    SectionGroupDetection,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "rules_file", Type: "string", Label: "Rules file path"},
			{YAMLPath: "overrides_file", Type: "string", Label: "Overrides file path"},
			{YAMLPath: "reload_command", Type: "string", Label: "Reload command"},
		},
	},
	{
		ID:       "performance",
		Title:    "Performance",
		YAMLPath: "performance",
		Icon:     "activity",
		Group:    SectionGroupOps,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "enabled", Type: "bool", Label: "Performance checks", Nullable: true, Help: "Leave unset to inherit default (on)"},
			{YAMLPath: "load_high_multiplier", Type: "float", Label: "Load high multiplier"},
			{YAMLPath: "load_critical_multiplier", Type: "float", Label: "Load critical multiplier"},
			{YAMLPath: "php_process_warn_per_user", Type: "int", Label: "PHP process warn per user", Min: int64p(1)},
			{YAMLPath: "php_process_critical_total_multiplier", Type: "int", Label: "PHP process crit multiplier", Min: int64p(1)},
			{YAMLPath: "error_log_warn_size_mb", Type: "int", Label: "Error log warn size (MB)", Min: int64p(1)},
			{YAMLPath: "mysql_join_buffer_max_mb", Type: "int", Label: "MySQL join buffer max (MB)", Min: int64p(1)},
			{YAMLPath: "mysql_wait_timeout_max", Type: "int", Label: "MySQL wait timeout max (s)", Min: int64p(1)},
			{YAMLPath: "mysql_max_connections_per_user", Type: "int", Label: "MySQL max connections per user", Min: int64p(1)},
			{YAMLPath: "redis_bgsave_min_interval", Type: "int", Label: "Redis bgsave min interval (s)", Min: int64p(1)},
			{YAMLPath: "redis_large_dataset_gb", Type: "int", Label: "Redis large dataset (GB)", Min: int64p(1)},
			{YAMLPath: "wp_memory_limit_max_mb", Type: "int", Label: "WP memory limit max (MB)", Min: int64p(32)},
			{YAMLPath: "wp_transient_warn_mb", Type: "int", Label: "WP transient warn (MB)", Min: int64p(1)},
			{YAMLPath: "wp_transient_critical_mb", Type: "int", Label: "WP transient critical (MB)", Min: int64p(1)},
		},
	},
	{
		ID:       "cloudflare",
		Title:    "Cloudflare",
		YAMLPath: "cloudflare",
		Icon:     "cloud",
		Group:    SectionGroupIntegrations,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "enabled", Type: "bool", Label: "Cloudflare integration"},
			{YAMLPath: "refresh_hours", Type: "int", Label: "Refresh interval (hours)", Min: int64p(1), Max: int64p(168)},
		},
	},
	{
		ID:       "geoip",
		Title:    "GeoIP",
		YAMLPath: "geoip",
		Icon:     "world",
		Group:    SectionGroupIntegrations,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "account_id", Type: "string", Label: "MaxMind account ID"},
			{YAMLPath: "license_key", Type: "string", Label: "MaxMind license key", Secret: true},
			{YAMLPath: "editions", Type: "[]enum", Label: "Database editions", OptionsSource: "geoip_editions", Help: "Which MaxMind databases to download. GeoLite2-* are free; GeoIP2-* require a paid subscription."},
			{YAMLPath: "auto_update", Type: "bool", Label: "Auto-update databases", Nullable: true},
			{YAMLPath: "update_interval", Type: "string", Label: "Update interval", Placeholder: "24h"},
		},
	},
	{
		ID:       "infra_ips",
		Title:    "Infra IPs",
		YAMLPath: "infra_ips",
		Icon:     "server",
		Group:    SectionGroupOps,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "", Type: "[]string", Label: "Trusted infra IPs and CIDRs"},
		},
	},
	{
		ID:       "sentry",
		Title:    "Sentry",
		YAMLPath: "sentry",
		Icon:     "bug",
		Group:    SectionGroupIntegrations,
		Restart:  true,
		Fields: []SettingsField{
			{YAMLPath: "enabled", Type: "bool", Label: "Sentry enabled"},
			{YAMLPath: "dsn", Type: "string", Label: "Sentry DSN", Secret: true},
			{YAMLPath: "environment", Type: "string", Label: "Environment", Placeholder: "production"},
			{YAMLPath: "sample_rate", Type: "float", Label: "Sample rate (0 to 1.0)"},
			{YAMLPath: "debug", Type: "bool", Label: "Debug logging"},
		},
	},
}

// SettingsSectionIDs returns the ordered list of section IDs.
func SettingsSectionIDs() []string {
	out := make([]string, 0, len(settingsSections))
	for _, s := range settingsSections {
		out = append(out, s.ID)
	}
	return out
}

// LookupSettingsSection returns the section with the given ID.
func LookupSettingsSection(id string) (SettingsSection, bool) {
	for _, s := range settingsSections {
		if s.ID == id {
			return s, true
		}
	}
	return SettingsSection{}, false
}

// AllSettingsSections returns the list of sections. Intended for
// read-only consumers such as the dashboard navigation.
func AllSettingsSections() []SettingsSection {
	out := make([]SettingsSection, len(settingsSections))
	copy(out, settingsSections)
	return out
}
