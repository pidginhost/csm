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
	// Correlation says how cross-account correlation treats this check.
	// Every entry must set it; the zero value fails TestEveryCheckIsClassified.
	Correlation CorrelationClass
	// CorrelationReason names the policy that excludes an Ignored check. One
	// of the reason constants in correlation_policy.go.
	CorrelationReason string
	// CorrelationGap documents a known missing producer identity path for an
	// eligible check. It never changes eligibility.
	CorrelationGap string
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
	{Name: "admin_panel_bruteforce", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "api_auth_failure", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "api_auth_failure_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "api_tokens", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "bulk_password_change", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAccountAggregate},
	{Name: "cpanel_file_upload", Category: CategoryAuth, Correlation: CorrelationSecurityEvent},
	{Name: "cpanel_file_upload_realtime", Category: CategoryAuth, Correlation: CorrelationSecurityEvent},
	{Name: "cpanel_login", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "cpanel_login_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "cpanel_multi_ip_login", Category: CategoryAuth, Correlation: CorrelationSecurityEvent},
	{Name: "cpanel_password_purge", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "cpanel_password_purge_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "ftp_auth_failure_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "ftp_bruteforce", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "ftp_login", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "ftp_login_after_bruteforce", Category: CategoryAuth, Correlation: CorrelationSecurityEvent},
	{Name: "ftp_login_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "credential_stuffing", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "pam_bruteforce", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "pam_login", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "password_hijack_confirmed", Category: CategoryAuth, Correlation: CorrelationSecurityEvent},
	{Name: "root_password_change", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "shadow_change", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "ssh_keys", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "ssh_login_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "ssh_login_unknown_ip", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "sshd_config_change", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "uid0_account", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "webmail_bruteforce", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "webmail_login_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "whm_account_action", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "whm_login_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "whm_password_change", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "whm_password_change_noninfra", Category: CategoryAuth, Correlation: CorrelationSecurityEvent},
	{Name: "whm_unauth_scripts_realtime", Category: CategoryAuth, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},

	// --- Brute Force -----------------------------------------------------
	{Name: "http_request_flood", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "http_scanner_profile", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "http_claimed_bot_unverified", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "http_ua_spoof", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "http_distributed_flood", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "http_asn_crawl", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "mail_account_compromised", Category: CategoryBruteForce, Correlation: CorrelationSecurityEvent},
	{Name: "mail_account_spray", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "mail_bruteforce", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "mail_bruteforce_suspected", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "mail_subnet_spray", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "smtp_account_spray", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "smtp_bruteforce", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "smtp_probe_abuse", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "smtp_subnet_spray", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "wp_login_bruteforce", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "wp_user_enumeration", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "xmlrpc_abuse", Category: CategoryBruteForce, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},

	// --- Malware & Webshells --------------------------------------------
	{Name: "backdoor_binary", Category: CategoryMalware, Correlation: CorrelationMalwareArtifact},
	{Name: "cgi_backdoor_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "cgi_suspicious_location_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "cross_account_malware", Category: CategoryMalware, Correlation: CorrelationDerived},
	{Name: "executable_in_config_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "executable_in_tmp_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "fake_kernel_thread", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "group_writable_php", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "js_keylogger_dataflow", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "js_taint_scan_incomplete", Category: CategoryMalware, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "php_remote_taint", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "php_taint_scan_incomplete", Category: CategoryMalware, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "new_executable_in_config", Category: CategoryMalware, Correlation: CorrelationMalwareArtifact},
	{Name: "new_php_in_sensitive_dir", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "new_php_in_sensitive_dir_clean", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "new_php_in_uploads", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "new_php_in_uploads_clean", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	// Retired: emitted by the file index until a20c6f76 and never registered
	// afterwards. Kept registered so the file_index runner can purge findings
	// written by older versions; nothing emits them today.
	{Name: "new_php_in_languages", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "new_php_in_upgrade", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "new_suspicious_php", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "new_webshell_file", Category: CategoryMalware, Correlation: CorrelationMalwareArtifact},
	{Name: "nulled_plugin", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "obfuscated_php", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "obfuscated_php_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "php_dropper_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "php_in_sensitive_dir_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "php_in_uploads_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "self_deleting_dropper_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "self_deleting_dropper_overflow", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "php_shield_block", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "php_shield_eval", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "php_shield_webshell", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "php_suspicious_execution", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "signature_match_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "suid_binary", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "suspicious_file", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "suspicious_php_content", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "suspicious_process", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "webshell", Category: CategoryMalware, Correlation: CorrelationMalwareArtifact},
	{Name: "webshell_content_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "webshell_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "world_writable_php", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "yara_match_realtime", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "yara_match_scheduled", Category: CategoryMalware, Correlation: CorrelationSecurityEvent},
	{Name: "yara_scan_incomplete", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "yara_realtime_scan_error", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "yara_worker_crashed", Category: CategoryMalware, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},

	// --- Web & Application ----------------------------------------------
	{Name: "htaccess_auto_prepend", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_cgi_handler_abuse", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_errordocument_hijack", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_filesmatch_shield", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_handler_abuse", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_header_injection", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_injection", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_injection_realtime", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_php_in_uploads", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_security_disabled", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "web_exposed_backup_archive", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "web_exposed_config_leak", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "web_exposed_repo_metadata", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "web_exposed_db_dump", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "web_exposed_phpinfo", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "web_exposed_sample_sql", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "web_exposed_source_backup", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "htaccess_spam_redirect", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "htaccess_user_agent_cloak", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "open_basedir", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "outdated_plugins", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "vulnerable_plugins", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "vulnerable_timthumb", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "php_config_change", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "php_config_scan_incomplete", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "php_config_realtime", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "symlink_attack", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "wp_core_integrity", Category: CategoryWeb, Correlation: CorrelationSecurityEvent},
	{Name: "wp_core_unverified", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "wp_plugin_inventory_unverified", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},

	// --- Database Content -----------------------------------------------
	{Name: "database_dump", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "db_malicious_event", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_malicious_function", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_malicious_procedure", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "admin_cross_account_overlap", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonAccountAggregate},
	{Name: "credential_reuse", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "supply_chain_vuln", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "db_magic_token_user", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_malicious_trigger", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_options_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_options_new_external_script", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_options_plugin_notice_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_post_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_content_scan_incomplete", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "db_unexpected_event", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "db_unexpected_function", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "db_unexpected_procedure", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "db_unexpected_trigger", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "drupal_admin_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "drupal_content_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "drupal_settings_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "joomla_admin_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "joomla_content_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "joomla_extensions_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "magento_admin_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "magento_content_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "magento_settings_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "opencart_admin_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "opencart_content_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "opencart_settings_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_phantom_post_author", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_post_volume_burst", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_hidden_link_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_hostname_keyed_option", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_doorway_sitemap_routes", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_spam_taxonomy", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_stored_code_execution", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_stored_cloak_logic", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_rogue_admin", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_siteurl_hijack", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_siteurl_foreign_host", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_siteurl_invalid", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "db_spam_cleaned", Category: CategoryDatabase, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "db_spam_found", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_spam_injection", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},
	{Name: "db_suspicious_admin_email", Category: CategoryDatabase, Correlation: CorrelationSecurityEvent},

	// --- Email & Phishing -----------------------------------------------
	{Name: "credential_log_realtime", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_auth_failure_realtime", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "email_cloud_relay_abuse", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_av_degraded", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_encrypted_archive", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_scanner_panic", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "realtime_scanner_panic", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_hold_bypass", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_late_verdict", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_parse_error", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_queue_overflow", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_quarantine_error", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_scan_error", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_av_timeout", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_compromised_account", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_credential_leak", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_dkim_failure", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "email_filter_blackhole", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_filter_exfil", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_filter_forwarder", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_filter_pipe", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_mail_filters", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_malware", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "email_phishing_content", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "email_php_relay_abuse", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_php_relay_account_volume_capped", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_action_dry_run", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "email_php_relay_action_failed", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "email_php_relay_action_skipped", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "email_php_relay_cpanel_limit_unreadable", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_disabled", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_inotify_overflow", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_inotify_overflow_recovered", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_msgindex_persist_failed", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_no_exim", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_overflow_scan_truncated", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_path2b_disabled", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_policies_reload", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_rate_limit_hit", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "email_php_relay_sweep_failed", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_php_relay_watcher_failed", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "email_defer_fail_governor", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "email_pipe_forwarder", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_rate_critical", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_rate_warning", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_spam_outbreak", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_spf_rejection", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "email_suspicious_forwarder", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_suspicious_geo", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "email_weak_password", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "email_password_audit_incomplete", Category: CategoryEmail, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "exim_frozen_realtime", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "mail_per_account", Category: CategoryEmail, Correlation: CorrelationSecurityEvent, CorrelationGap: gapEnvelopeSender},
	{Name: "mail_queue", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "mail_queue_unavailable", Category: CategoryEmail, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "phishing_credential_log", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "phishing_directory", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "phishing_iframe", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "phishing_kit_archive", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "phishing_kit_realtime", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "phishing_page", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "phishing_php", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "phishing_realtime", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},
	{Name: "phishing_redirector", Category: CategoryEmail, Correlation: CorrelationSecurityEvent},

	// --- Performance -----------------------------------------------------
	{Name: "perf_error_logs", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_load", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_memory", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_mysql_config", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_php_handler", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_php_processes", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_redis_config", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_wp_config", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_wp_cron", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},
	{Name: "perf_wp_transients", Category: CategoryPerformance, Correlation: CorrelationIgnored, CorrelationReason: reasonPerformance},

	// --- Network & Firewall ---------------------------------------------
	{Name: "backdoor_port", Category: CategoryNetwork, Correlation: CorrelationSecurityEvent},
	{Name: "backdoor_port_outbound", Category: CategoryNetwork, Correlation: CorrelationSecurityEvent},
	{Name: "c2_connection", Category: CategoryNetwork, Correlation: CorrelationSecurityEvent},
	{Name: "direct_smtp_egress", Category: CategoryNetwork, Correlation: CorrelationSecurityEvent},
	{Name: "dns_connection", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "dns_zone_change", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "exfiltration_paste_site", Category: CategoryNetwork, Correlation: CorrelationSecurityEvent},
	{Name: "firewall", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "firewall_ports", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "firewall_ipv6_unmanaged", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "bad_asn_outbound", Category: CategoryNetwork, Correlation: CorrelationSecurityEvent},
	{Name: "infra_ips_unresolvable", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "ip_reputation", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "reputation_quota_exhausted", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "threat_feed_stale", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "ssl_cert_issued", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "user_outbound_connection", Category: CategoryNetwork, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},

	// --- System Integrity ------------------------------------------------
	{Name: "af_alg_enforcement_corrected", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "af_alg_socket_use", Category: CategorySystem, Correlation: CorrelationSecurityEvent},
	{Name: "account_scan_error", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "account_scan_truncated", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "bpf_unavailable", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "bpf_ringbuf_error", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "check_panic", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "full_scan_file_too_large", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "crond_change", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "crontab_change", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
	{Name: "dpkg_integrity", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "kernel_module", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "mysql_superuser", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "rpm_integrity", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "sensitive_file_modified", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "signature_update_rollback", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "signature_update_rescan_queued", Category: CategorySystem, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "suspicious_crontab", Category: CategorySystem, Correlation: CorrelationSecurityEvent},

	// --- WAF & ModSecurity ----------------------------------------------
	{Name: "modsec_block_escalation", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "modsec_block_realtime", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "modsec_classifier_gap", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "modsec_csm_block_escalation", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "modsec_low_confidence_burst", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "modsec_warning_realtime", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "waf_attack_blocked", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "modsec_disabled_vhost", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	// Retired in favour of modsec_disabled_vhost. Kept registered so the
	// waf_status runner can still purge findings written by older versions.
	{Name: "waf_bypass", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "waf_detection_only", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "waf_rules", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "waf_rules_stale", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
	{Name: "waf_status", Category: CategoryWAF, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},

	// --- Correlation & Health -------------------------------------------
	{Name: "account_scan", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "auto_block", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "auto_response", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "auto_response_paused", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "challenge_route", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonResponse},
	{Name: "check_timeout", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "config_reload_error", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "config_reload_restart_required", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "yara_forge_rollback", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "coordinated_attack", Category: CategoryCorrelation, Correlation: CorrelationDerived},
	{Name: "csm_health", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "fanotify_kernel_overflow", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "fanotify_overflow", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "integrity", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonHostScope},
	{Name: "local_threat_score", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonAttackerSide},
	{Name: "mail_auth_backend_degraded", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "mail_log_source_unavailable", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "protection_queue_degraded", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},
	{Name: "protection_queue_recovered", Category: CategoryCorrelation, Correlation: CorrelationIgnored, CorrelationReason: reasonSelfHealth},

	// --- Internal (not shown in user-facing dropdowns) -------------------
	{Name: "test_alert", Category: CategoryInternal, Internal: true, Correlation: CorrelationIgnored, CorrelationReason: reasonInformational},
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
