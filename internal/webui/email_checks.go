package webui

import "net/http"

// emailCheck is one check the Email page shows. Kind is its group on the
// workbench; "" lists the check in Findings but never groups it.
type emailCheck struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// emailChecks is the one list of email checks: every Email & Phishing check
// except emailCheckExclusions, plus the mail_ and smtp_ brute-force checks.
// TestEmailCheckListCoversRegistry fails when a registered check is in
// neither list.
var emailChecks = []emailCheck{
	{"email_compromised_account", "compromised_account"},
	{"email_credential_leak", "compromised_account"},
	{"email_weak_password", "compromised_account"},
	{"mail_account_compromised", "compromised_account"},
	{"email_pipe_forwarder", "compromised_account"},
	{"email_suspicious_forwarder", "compromised_account"},

	{"email_spam_outbreak", "spam_outbreak"},
	{"email_rate_critical", "spam_outbreak"},
	{"email_rate_warning", "spam_outbreak"},
	{"email_php_relay_abuse", "spam_outbreak"},
	{"email_php_relay_action_failed", "spam_outbreak"},
	{"email_php_relay_rate_limit_hit", "spam_outbreak"},
	{"email_cloud_relay_abuse", "spam_outbreak"},

	{"email_auth_failure_realtime", "auth_failure"},
	{"email_suspicious_geo", "auth_failure"},
	{"mail_bruteforce", "auth_failure"},
	{"mail_bruteforce_suspected", "auth_failure"},
	{"mail_subnet_spray", "auth_failure"},
	{"mail_account_spray", "auth_failure"},
	{"smtp_bruteforce", "auth_failure"},
	{"smtp_subnet_spray", "auth_failure"},
	{"smtp_account_spray", "auth_failure"},
	{"smtp_probe_abuse", "auth_failure"},

	{"email_malware", "malware"},
	{"email_phishing_content", "malware"},
	{"email_av_degraded", "malware"},
	{"email_av_encrypted_archive", "malware"},
	{"email_av_timeout", "malware"},
	{"email_av_parse_error", "malware"},
	{"email_av_quarantine_error", "malware"},

	{"mail_per_account", "queue_alert"},
	{"mail_queue", "queue_alert"},
	{"mail_queue_unavailable", "queue_alert"},
	{"email_defer_fail_governor", "queue_alert"},
	{"exim_frozen_realtime", "queue_alert"},

	{"email_dkim_failure", ""},
	{"email_spf_rejection", ""},
	{"email_filter_blackhole", ""},
	{"email_filter_exfil", ""},
	{"email_filter_forwarder", ""},
	{"email_filter_pipe", ""},
	{"email_mail_filters", ""},
	{"email_password_audit_incomplete", ""},
	{"antispam_apply_failed", ""},
	{"antispam_controller_open", ""},
	{"antispam_feed", ""},
	{"antispam_ip_map", ""},
	{"antispam_learning", ""},
	{"antispam_precondition", ""},
	{"antispam_rspamd_down", ""},
	{"antispam_rspamd_recovered", ""},
	{"antispam_scan_error", ""},
	{"email_av_hold_bypass", ""},
	{"email_av_late_verdict", ""},
	{"email_av_queue_overflow", ""},
	{"email_av_scan_error", ""},
	{"email_av_scanner_panic", ""},
	{"email_php_relay_account_volume_capped", ""},
	{"email_php_relay_action_dry_run", ""},
	{"email_php_relay_action_skipped", ""},
	{"email_php_relay_cpanel_limit_unreadable", ""},
	{"email_php_relay_disabled", ""},
	{"email_php_relay_inotify_overflow", ""},
	{"email_php_relay_inotify_overflow_recovered", ""},
	{"email_php_relay_msgindex_persist_failed", ""},
	{"email_php_relay_no_exim", ""},
	{"email_php_relay_overflow_scan_truncated", ""},
	{"email_php_relay_path2b_disabled", ""},
	{"email_php_relay_policies_reload", ""},
	{"email_php_relay_sweep_failed", ""},
	{"email_php_relay_watcher_failed", ""},
}

// emailCheckExclusions are Email & Phishing checks that find phishing kits,
// pages and harvested credential logs on websites, not mail. The Email page
// leaves them out.
var emailCheckExclusions = []string{
	"credential_log_realtime",
	"phishing_credential_log",
	"phishing_directory",
	"phishing_iframe",
	"phishing_kit_archive",
	"phishing_kit_realtime",
	"phishing_page",
	"phishing_php",
	"phishing_realtime",
	"phishing_redirector",
}

var emailCheckKinds = func() map[string]string {
	kinds := make(map[string]string, len(emailChecks))
	for _, c := range emailChecks {
		kinds[c.Name] = c.Kind
	}
	return kinds
}()

// emailCheckSet returns a new set of the listed check names, for a history
// filter.
func emailCheckSet() map[string]bool {
	set := make(map[string]bool, len(emailChecks))
	for _, c := range emailChecks {
		set[c.Name] = true
	}
	return set
}

// apiEmailChecks answers the email check list with each check's group kind.
func (s *Server) apiEmailChecks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string][]emailCheck{"checks": emailChecks})
}
