package checks

import "sort"

// CheckInfo describes a single named check emitted as an alert.Finding.Check.
// Category groups related checks for display in the settings UI. Internal is
// true for checks that exist for plumbing (self-tests, plumbing findings) and
// should not appear in user-facing dropdowns like alerts.email.disabled_checks.
type CheckInfo struct {
	Name     string
	Category string
	Internal bool
}

// Category labels are the groupings shown in the multi-select UI. Keep the
// order below in sync with checkCategoryOrder so categories render in a sane
// order rather than alphabetically (Auth first, Internal last).
const (
	CategoryAuth        = "Authentication & Login"
	CategoryBruteForce  = "Brute Force"
	CategoryMalware     = "Malware & Webshells"
	CategoryWeb         = "Web & Application"
	CategoryDatabase    = "Database Content"
	CategoryEmail       = "Email & Phishing"
	CategoryPerformance = "Performance"
	CategoryNetwork     = "Network & Firewall"
	CategorySystem      = "System Integrity"
	CategoryWAF         = "WAF & ModSecurity"
	CategoryCorrelation = "Correlation & Health"
	CategoryInternal    = "Internal"
)

var checkCategoryOrder = []string{
	CategoryAuth,
	CategoryBruteForce,
	CategoryMalware,
	CategoryWeb,
	CategoryDatabase,
	CategoryEmail,
	CategoryPerformance,
	CategoryNetwork,
	CategorySystem,
	CategoryWAF,
	CategoryCorrelation,
	CategoryInternal,
}

// checkRegistry is the authoritative list of every Check string the daemon
// may emit. Adding a new alert.Finding Check name anywhere in internal/checks,
// internal/daemon, or internal/webui without also adding it here will fail
// TestCheckRegistryCoversProductionCode.
var checkRegistry = []CheckInfo{
	// --- Authentication & Login ------------------------------------------
	{Name: "admin_panel_bruteforce", Category: CategoryAuth},
	{Name: "api_auth_failure", Category: CategoryAuth},
	{Name: "api_auth_failure_realtime", Category: CategoryAuth},
	{Name: "api_tokens", Category: CategoryAuth},
	{Name: "bulk_password_change", Category: CategoryAuth},
	{Name: "cpanel_file_upload", Category: CategoryAuth},
	{Name: "cpanel_file_upload_realtime", Category: CategoryAuth},
	{Name: "cpanel_login", Category: CategoryAuth},
	{Name: "cpanel_login_realtime", Category: CategoryAuth},
	{Name: "cpanel_multi_ip_login", Category: CategoryAuth},
	{Name: "cpanel_password_purge", Category: CategoryAuth},
	{Name: "cpanel_password_purge_realtime", Category: CategoryAuth},
	{Name: "ftp_auth_failure_realtime", Category: CategoryAuth},
	{Name: "ftp_bruteforce", Category: CategoryAuth},
	{Name: "ftp_login", Category: CategoryAuth},
	{Name: "ftp_login_realtime", Category: CategoryAuth},
	{Name: "pam_bruteforce", Category: CategoryAuth},
	{Name: "pam_login", Category: CategoryAuth},
	{Name: "password_hijack_confirmed", Category: CategoryAuth},
	{Name: "root_password_change", Category: CategoryAuth},
	{Name: "shadow_change", Category: CategoryAuth},
	{Name: "ssh_keys", Category: CategoryAuth},
	{Name: "ssh_login_realtime", Category: CategoryAuth},
	{Name: "ssh_login_unknown_ip", Category: CategoryAuth},
	{Name: "sshd_config_change", Category: CategoryAuth},
	{Name: "uid0_account", Category: CategoryAuth},
	{Name: "webmail_bruteforce", Category: CategoryAuth},
	{Name: "webmail_login_realtime", Category: CategoryAuth},
	{Name: "whm_account_action", Category: CategoryAuth},
	{Name: "whm_password_change", Category: CategoryAuth},
	{Name: "whm_password_change_noninfra", Category: CategoryAuth},

	// --- Brute Force -----------------------------------------------------
	{Name: "mail_account_compromised", Category: CategoryBruteForce},
	{Name: "mail_account_spray", Category: CategoryBruteForce},
	{Name: "mail_bruteforce", Category: CategoryBruteForce},
	{Name: "mail_subnet_spray", Category: CategoryBruteForce},
	{Name: "smtp_account_spray", Category: CategoryBruteForce},
	{Name: "smtp_bruteforce", Category: CategoryBruteForce},
	{Name: "smtp_subnet_spray", Category: CategoryBruteForce},
	{Name: "wp_login_bruteforce", Category: CategoryBruteForce},
	{Name: "wp_user_enumeration", Category: CategoryBruteForce},
	{Name: "xmlrpc_abuse", Category: CategoryBruteForce},

	// --- Malware & Webshells --------------------------------------------
	{Name: "backdoor_binary", Category: CategoryMalware},
	{Name: "cgi_backdoor_realtime", Category: CategoryMalware},
	{Name: "cgi_suspicious_location_realtime", Category: CategoryMalware},
	{Name: "cross_account_malware", Category: CategoryMalware},
	{Name: "executable_in_config_realtime", Category: CategoryMalware},
	{Name: "executable_in_tmp_realtime", Category: CategoryMalware},
	{Name: "fake_kernel_thread", Category: CategoryMalware},
	{Name: "group_writable_php", Category: CategoryMalware},
	{Name: "new_executable_in_config", Category: CategoryMalware},
	{Name: "new_php_in_uploads", Category: CategoryMalware},
	{Name: "new_suspicious_php", Category: CategoryMalware},
	{Name: "new_webshell_file", Category: CategoryMalware},
	{Name: "nulled_plugin", Category: CategoryMalware},
	{Name: "obfuscated_php", Category: CategoryMalware},
	{Name: "obfuscated_php_realtime", Category: CategoryMalware},
	{Name: "php_dropper_realtime", Category: CategoryMalware},
	{Name: "php_in_sensitive_dir_realtime", Category: CategoryMalware},
	{Name: "php_in_uploads_realtime", Category: CategoryMalware},
	{Name: "php_shield_block", Category: CategoryMalware},
	{Name: "php_shield_eval", Category: CategoryMalware},
	{Name: "php_shield_webshell", Category: CategoryMalware},
	{Name: "php_suspicious_execution", Category: CategoryMalware},
	{Name: "signature_match_realtime", Category: CategoryMalware},
	{Name: "suid_binary", Category: CategoryMalware},
	{Name: "suspicious_file", Category: CategoryMalware},
	{Name: "suspicious_php_content", Category: CategoryMalware},
	{Name: "suspicious_process", Category: CategoryMalware},
	{Name: "webshell", Category: CategoryMalware},
	{Name: "webshell_content_realtime", Category: CategoryMalware},
	{Name: "webshell_realtime", Category: CategoryMalware},
	{Name: "world_writable_php", Category: CategoryMalware},
	{Name: "yara_match_realtime", Category: CategoryMalware},
	{Name: "yara_worker_crashed", Category: CategoryMalware},

	// --- Web & Application ----------------------------------------------
	{Name: "htaccess_auto_prepend", Category: CategoryWeb},
	{Name: "htaccess_errordocument_hijack", Category: CategoryWeb},
	{Name: "htaccess_filesmatch_shield", Category: CategoryWeb},
	{Name: "htaccess_handler_abuse", Category: CategoryWeb},
	{Name: "htaccess_header_injection", Category: CategoryWeb},
	{Name: "htaccess_injection", Category: CategoryWeb},
	{Name: "htaccess_injection_realtime", Category: CategoryWeb},
	{Name: "htaccess_php_in_uploads", Category: CategoryWeb},
	{Name: "htaccess_spam_redirect", Category: CategoryWeb},
	{Name: "htaccess_user_agent_cloak", Category: CategoryWeb},
	{Name: "open_basedir", Category: CategoryWeb},
	{Name: "outdated_plugins", Category: CategoryWeb},
	{Name: "php_config_change", Category: CategoryWeb},
	{Name: "php_config_realtime", Category: CategoryWeb},
	{Name: "symlink_attack", Category: CategoryWeb},
	{Name: "wp_core_integrity", Category: CategoryWeb},

	// --- Database Content -----------------------------------------------
	{Name: "database_dump", Category: CategoryDatabase},
	{Name: "db_malicious_event", Category: CategoryDatabase},
	{Name: "db_malicious_function", Category: CategoryDatabase},
	{Name: "db_malicious_procedure", Category: CategoryDatabase},
	{Name: "db_malicious_trigger", Category: CategoryDatabase},
	{Name: "db_options_injection", Category: CategoryDatabase},
	{Name: "db_post_injection", Category: CategoryDatabase},
	{Name: "db_unexpected_event", Category: CategoryDatabase},
	{Name: "db_unexpected_function", Category: CategoryDatabase},
	{Name: "db_unexpected_procedure", Category: CategoryDatabase},
	{Name: "db_unexpected_trigger", Category: CategoryDatabase},
	{Name: "db_rogue_admin", Category: CategoryDatabase},
	{Name: "db_siteurl_hijack", Category: CategoryDatabase},
	{Name: "db_spam_cleaned", Category: CategoryDatabase},
	{Name: "db_spam_found", Category: CategoryDatabase},
	{Name: "db_spam_injection", Category: CategoryDatabase},
	{Name: "db_suspicious_admin_email", Category: CategoryDatabase},

	// --- Email & Phishing -----------------------------------------------
	{Name: "credential_log_realtime", Category: CategoryEmail},
	{Name: "email_auth_failure_realtime", Category: CategoryEmail},
	{Name: "email_cloud_relay_abuse", Category: CategoryEmail},
	{Name: "email_av_degraded", Category: CategoryEmail},
	{Name: "email_av_parse_error", Category: CategoryEmail},
	{Name: "email_av_quarantine_error", Category: CategoryEmail},
	{Name: "email_av_timeout", Category: CategoryEmail},
	{Name: "email_compromised_account", Category: CategoryEmail},
	{Name: "email_credential_leak", Category: CategoryEmail},
	{Name: "email_dkim_failure", Category: CategoryEmail},
	{Name: "email_malware", Category: CategoryEmail},
	{Name: "email_phishing_content", Category: CategoryEmail},
	{Name: "email_pipe_forwarder", Category: CategoryEmail},
	{Name: "email_rate_critical", Category: CategoryEmail},
	{Name: "email_rate_warning", Category: CategoryEmail},
	{Name: "email_spam_outbreak", Category: CategoryEmail},
	{Name: "email_spf_rejection", Category: CategoryEmail},
	{Name: "email_suspicious_forwarder", Category: CategoryEmail},
	{Name: "email_suspicious_geo", Category: CategoryEmail},
	{Name: "email_weak_password", Category: CategoryEmail},
	{Name: "exim_frozen_realtime", Category: CategoryEmail},
	{Name: "mail_per_account", Category: CategoryEmail},
	{Name: "mail_queue", Category: CategoryEmail},
	{Name: "phishing_credential_log", Category: CategoryEmail},
	{Name: "phishing_directory", Category: CategoryEmail},
	{Name: "phishing_iframe", Category: CategoryEmail},
	{Name: "phishing_kit_archive", Category: CategoryEmail},
	{Name: "phishing_kit_realtime", Category: CategoryEmail},
	{Name: "phishing_page", Category: CategoryEmail},
	{Name: "phishing_php", Category: CategoryEmail},
	{Name: "phishing_realtime", Category: CategoryEmail},
	{Name: "phishing_redirector", Category: CategoryEmail},

	// --- Performance -----------------------------------------------------
	{Name: "perf_error_logs", Category: CategoryPerformance},
	{Name: "perf_load", Category: CategoryPerformance},
	{Name: "perf_memory", Category: CategoryPerformance},
	{Name: "perf_mysql_config", Category: CategoryPerformance},
	{Name: "perf_php_handler", Category: CategoryPerformance},
	{Name: "perf_php_processes", Category: CategoryPerformance},
	{Name: "perf_redis_config", Category: CategoryPerformance},
	{Name: "perf_wp_config", Category: CategoryPerformance},
	{Name: "perf_wp_cron", Category: CategoryPerformance},
	{Name: "perf_wp_transients", Category: CategoryPerformance},

	// --- Network & Firewall ---------------------------------------------
	{Name: "backdoor_port", Category: CategoryNetwork},
	{Name: "backdoor_port_outbound", Category: CategoryNetwork},
	{Name: "c2_connection", Category: CategoryNetwork},
	{Name: "dns_connection", Category: CategoryNetwork},
	{Name: "dns_zone_change", Category: CategoryNetwork},
	{Name: "exfiltration_paste_site", Category: CategoryNetwork},
	{Name: "firewall", Category: CategoryNetwork},
	{Name: "firewall_ports", Category: CategoryNetwork},
	{Name: "ip_reputation", Category: CategoryNetwork},
	{Name: "ssl_cert_issued", Category: CategoryNetwork},
	{Name: "user_outbound_connection", Category: CategoryNetwork},

	// --- System Integrity ------------------------------------------------
	{Name: "crond_change", Category: CategorySystem},
	{Name: "crontab_change", Category: CategorySystem},
	{Name: "dpkg_integrity", Category: CategorySystem},
	{Name: "kernel_module", Category: CategorySystem},
	{Name: "mysql_superuser", Category: CategorySystem},
	{Name: "rpm_integrity", Category: CategorySystem},
	{Name: "suspicious_crontab", Category: CategorySystem},

	// --- WAF & ModSecurity ----------------------------------------------
	{Name: "modsec_block_realtime", Category: CategoryWAF},
	{Name: "modsec_csm_block_escalation", Category: CategoryWAF},
	{Name: "modsec_warning_realtime", Category: CategoryWAF},
	{Name: "waf_attack_blocked", Category: CategoryWAF},
	{Name: "waf_bypass", Category: CategoryWAF},
	{Name: "waf_detection_only", Category: CategoryWAF},
	{Name: "waf_rules", Category: CategoryWAF},
	{Name: "waf_rules_stale", Category: CategoryWAF},
	{Name: "waf_status", Category: CategoryWAF},

	// --- Correlation & Health -------------------------------------------
	{Name: "account_scan", Category: CategoryCorrelation},
	{Name: "auto_block", Category: CategoryCorrelation},
	{Name: "auto_response", Category: CategoryCorrelation},
	{Name: "challenge_route", Category: CategoryCorrelation},
	{Name: "check_timeout", Category: CategoryCorrelation},
	{Name: "config_reload_error", Category: CategoryCorrelation},
	{Name: "config_reload_restart_required", Category: CategoryCorrelation},
	{Name: "coordinated_attack", Category: CategoryCorrelation},
	{Name: "csm_health", Category: CategoryCorrelation},
	{Name: "fanotify_overflow", Category: CategoryCorrelation},
	{Name: "integrity", Category: CategoryCorrelation},
	{Name: "local_threat_score", Category: CategoryCorrelation},

	// --- Internal (not shown in user-facing dropdowns) -------------------
	{Name: "test_alert", Category: CategoryInternal, Internal: true},
}

// AllCheckNames returns every registered Check name, sorted alphabetically.
// Includes internal names; callers that render user-facing UI should use
// PublicCheckInfos instead.
func AllCheckNames() []string {
	out := make([]string, 0, len(checkRegistry))
	for _, c := range checkRegistry {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}

// PublicCheckInfos returns all non-Internal checks grouped by category in
// the canonical category order (see checkCategoryOrder). Within a category
// names are sorted alphabetically. This is the list the settings UI shows
// for alerts.email.disabled_checks.
func PublicCheckInfos() []CheckInfo {
	byCategory := make(map[string][]CheckInfo, len(checkCategoryOrder))
	for _, c := range checkRegistry {
		if c.Internal {
			continue
		}
		byCategory[c.Category] = append(byCategory[c.Category], c)
	}
	var out []CheckInfo
	for _, cat := range checkCategoryOrder {
		items := byCategory[cat]
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		out = append(out, items...)
	}
	return out
}

// LookupCheck returns the registry entry for name, if any.
func LookupCheck(name string) (CheckInfo, bool) {
	for _, c := range checkRegistry {
		if c.Name == name {
			return c, true
		}
	}
	return CheckInfo{}, false
}
