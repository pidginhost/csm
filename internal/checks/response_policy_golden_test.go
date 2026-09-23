package checks

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The IP response policy as it stood before it moved into the check
// registry. These tables are the behaviour the registry must reproduce.
// Change them only together with a deliberate, documented policy change.
var (
	goldenAlwaysBlock = setOf(
		"admin_panel_bruteforce", "c2_connection", "credential_stuffing",
		"email_cloud_relay_abuse", "email_compromised_account", "ftp_bruteforce",
		"http_claimed_bot_unverified", "http_request_flood", "http_scanner_profile",
		"http_ua_spoof", "ip_reputation", "local_threat_score",
		"mail_account_compromised", "mail_bruteforce", "modsec_block_escalation",
		"modsec_csm_block_escalation", "pam_bruteforce", "smtp_bruteforce",
		"smtp_probe_abuse", "ssh_login_unknown_ip", "waf_attack_blocked",
		"wp_login_bruteforce", "xmlrpc_abuse",
	)
	goldenCpanelFailure = setOf(
		"api_auth_failure", "api_auth_failure_realtime", "cpanel_multi_ip_login",
		"ftp_auth_failure_realtime", "webmail_bruteforce",
	)
	goldenChallengeable = setOf(
		"http_claimed_bot_unverified", "http_scanner_profile", "ip_reputation",
		"local_threat_score", "webmail_bruteforce", "wp_login_bruteforce",
		"wp_user_enumeration", "xmlrpc_abuse",
	)
	goldenNeverChallenge = setOf(
		"admin_panel_bruteforce", "api_auth_failure_realtime", "backdoor_binary",
		"backdoor_port", "backdoor_port_outbound", "c2_connection",
		"coordinated_attack", "credential_stuffing", "cross_account_malware",
		"database_dump", "db_options_injection", "db_post_injection",
		"db_rogue_admin", "db_siteurl_hijack", "db_spam_injection",
		"email_spam_outbreak", "exfiltration_paste_site", "fake_kernel_thread",
		"ftp_auth_failure_realtime", "htaccess_handler_abuse", "htaccess_injection",
		"js_keylogger_dataflow", "kernel_module", "mail_account_compromised",
		"mail_bruteforce", "mail_subnet_spray", "modsec_csm_block_escalation",
		"pam_bruteforce", "password_hijack_confirmed", "phishing_credential_log",
		"phishing_directory", "phishing_iframe", "phishing_kit_archive",
		"phishing_page", "phishing_php", "phishing_redirector",
		"php_shield_block", "php_shield_eval", "php_shield_webshell",
		"php_suspicious_execution", "root_password_change", "rpm_integrity",
		"shadow_change", "signature_match_realtime", "smtp_bruteforce",
		"smtp_probe_abuse", "smtp_subnet_spray", "suid_binary",
		"suspicious_crontab", "suspicious_file", "suspicious_process",
		"symlink_attack", "uid0_account", "waf_attack_blocked", "webshell",
		"yara_match_realtime", "yara_match_scheduled",
	)
	goldenNeverChallengePrefixes = []string{"outgoing_mail_", "spam_", "modsec_", "email_auth_failure", "email_compromised", "email_credential"}
)

func setOf(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func goldenBlockable(check string, blockCpanelLogins bool) bool {
	switch check {
	case "ftp_login_realtime":
		check = "ftp_login"
	case "ssh_login_realtime":
		check = "ssh_login_unknown_ip"
	}
	return goldenAlwaysBlock[check] || (blockCpanelLogins && goldenCpanelFailure[check])
}

func goldenBlockableFinding(f alert.Finding, blockCpanelLogins bool) bool {
	return goldenBlockable(f.Check, blockCpanelLogins) &&
		(f.Check != "mail_account_compromised" || f.Severity == alert.Critical)
}

func goldenHardBlock(check string) bool {
	if goldenNeverChallenge[check] {
		return true
	}
	for _, p := range goldenNeverChallengePrefixes {
		if strings.HasPrefix(check, p) {
			return true
		}
	}
	return false
}

func goldenChallengeRoutesCheck(cfg *config.Config, check string) bool {
	return goldenChallengeable[check] &&
		(check != "http_scanner_profile" || cfg.AutoResponse.HTTPScannerAction != responseBlock)
}

func goldenResponseActionForCheck(cfg *config.Config, check string) string {
	if !cfg.Challenge.Enabled || !goldenChallengeRoutesCheck(cfg, check) {
		return responseBlock
	}
	return responseChallenge
}

func goldenResponseActionForFinding(cfg *config.Config, f alert.Finding) string {
	if f.Check == "ip_reputation" && f.Severity == alert.Critical {
		return responseBlock
	}
	return goldenResponseActionForCheck(cfg, f.Check)
}

// goldenNames is every registered check, both renamed-producer aliases,
// dynamic names only the prefix contract covers, and junk.
func goldenNames() []string {
	names := []string{
		"ftp_login_realtime", "ssh_login_realtime",
		"modsec_attack_detected", "spam_outbreak", "outgoing_mail_hold", "email_auth_failure_smtp",
		"brute_force", "", "not_a_check",
	}
	for _, c := range checkRegistry {
		names = append(names, c.Name)
	}
	for _, table := range []map[string]bool{goldenAlwaysBlock, goldenCpanelFailure, goldenChallengeable, goldenNeverChallenge} {
		for name := range table {
			names = append(names, name)
		}
	}
	for _, prefix := range goldenNeverChallengePrefixes {
		names = append(names, prefix, prefix+"synthetic", "x"+prefix, strings.ToUpper(prefix), prefix[:len(prefix)-1], strings.TrimSuffix(prefix, "_")+"near_miss")
	}
	sort.Strings(names)
	return slices.Compact(names)
}

var goldenSeverities = []alert.Severity{alert.Critical, alert.High, alert.Warning}

func TestGoldenPolicyNamesAreRegistered(t *testing.T) {
	for _, table := range []map[string]bool{goldenAlwaysBlock, goldenCpanelFailure, goldenChallengeable, goldenNeverChallenge} {
		for name := range table {
			if _, ok := LookupCheck(name); !ok {
				t.Errorf("golden policy check %q is not registered", name)
			}
		}
	}
}

func TestResponsePolicyMatchesGoldenHelpers(t *testing.T) {
	for _, name := range goldenNames() {
		if got, want := isChallengeableCheck(name), goldenChallengeable[name]; got != want {
			t.Errorf("isChallengeableCheck(%q) = %v, golden %v", name, got, want)
		}
		if got, want := isHardBlockCheck(name), goldenHardBlock(name); got != want {
			t.Errorf("isHardBlockCheck(%q) = %v, golden %v", name, got, want)
		}
		for _, cpanel := range []bool{false, true} {
			if got, want := blockableCheck(name, cpanel), goldenBlockable(name, cpanel); got != want {
				t.Errorf("blockableCheck(%q, block_cpanel_logins=%v) = %v, golden %v", name, cpanel, got, want)
			}
			for _, sev := range goldenSeverities {
				f := alert.Finding{Check: name, Severity: sev}
				if got, want := blockableFinding(f, cpanel), goldenBlockableFinding(f, cpanel); got != want {
					t.Errorf("blockableFinding(%q, %v, block_cpanel_logins=%v) = %v, golden %v", name, sev, cpanel, got, want)
				}
			}
		}
		for _, enabled := range []bool{false, true} {
			for _, action := range []string{"", responseChallenge, responseBlock} {
				cfg := &config.Config{}
				cfg.Challenge.Enabled = enabled
				cfg.AutoResponse.HTTPScannerAction = action
				if got, want := responseActionForCheck(cfg, name), goldenResponseActionForCheck(cfg, name); got != want {
					t.Errorf("responseActionForCheck(%q, challenge=%v, scanner=%q) = %q, golden %q", name, enabled, action, got, want)
				}
				for _, sev := range goldenSeverities {
					f := alert.Finding{Check: name, Severity: sev}
					if got, want := responseActionForFinding(cfg, f), goldenResponseActionForFinding(cfg, f); got != want {
						t.Errorf("responseActionForFinding(%q, %v, challenge=%v, scanner=%q) = %q, golden %q", name, sev, enabled, action, got, want)
					}
				}
			}
		}
	}
}

// ChallengeRouteIPs adds the block_cpanel_logins gate and the hard-block
// filter to the helpers above. Route one finding per name and compare the
// routed set with the golden decision.
func TestChallengeRouteIPsMatchesGoldenPolicy(t *testing.T) {
	old := challengeIPList
	t.Cleanup(func() { SetChallengeIPList(old) })
	for _, cpanel := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			for _, action := range []string{"", responseChallenge, responseBlock} {
				for _, sev := range goldenSeverities {
					for _, name := range goldenNames() {
						mock := &mockIPList{ips: make(map[string]bool)}
						SetChallengeIPList(mock)
						cfg := &config.Config{}
						cfg.Challenge.Enabled = enabled
						cfg.AutoResponse.BlockCpanelLogins = cpanel
						cfg.AutoResponse.HTTPScannerAction = action
						f := alert.Finding{Check: name, Severity: sev, SourceIP: "203.0.113.10", Message: "probe"}
						actions := ChallengeRouteIPs(cfg, []alert.Finding{f})
						want := enabled && (!goldenCpanelFailure[name] || cpanel) &&
							!goldenHardBlock(name) && goldenChallengeable[name] &&
							goldenResponseActionForFinding(cfg, f) == responseChallenge
						wantCount := 0
						if want {
							wantCount = 1
						}
						if mock.ips[f.SourceIP] != want || len(mock.ips) != wantCount || len(actions) != wantCount {
							t.Fatalf("name=%q severity=%v enabled=%v cpanel=%v scanner=%q: ips=%v actions=%v want count=%d", name, sev, enabled, cpanel, action, mock.ips, actions, wantCount)
						}
						if got, expected := mock.nonEscalating[f.SourceIP], want && name == "http_claimed_bot_unverified"; got != expected {
							t.Errorf("%q non-escalating=%v want %v", name, got, expected)
						}
						if want && (actions[0].Check != "challenge_route" || actions[0].Severity != alert.Warning) {
							t.Errorf("unexpected response record: %+v", actions[0])
						}
					}
				}
			}
		}
	}
}
