package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestIsHardBlockCheck(t *testing.T) {
	hardChecks := []string{
		"signature_match_realtime",
		"yara_match_realtime",
		"webshell",
		"backdoor_binary",
		"c2_connection",
		"backdoor_port",
		"htaccess_injection",
		"phishing_page",
		"spam_outbreak",
		"outgoing_mail_hold",
		"waf_attack_blocked",
	}
	for _, check := range hardChecks {
		if !isHardBlockCheck(check) {
			t.Errorf("isHardBlockCheck(%q) = false, want true", check)
		}
	}

	// modsec checks are now hard-blocked (modsec already handles the request)
	modsecChecks := []string{
		"modsec_block_escalation",
		"modsec_csm_block_escalation",
		"modsec_attack_detected",
	}
	for _, check := range modsecChecks {
		if !isHardBlockCheck(check) {
			t.Errorf("isHardBlockCheck(%q) = false, want true (modsec should be hard-blocked)", check)
		}
	}

	challengeChecks := []string{
		"wp_login_bruteforce",
		"xmlrpc_abuse",
		"ftp_bruteforce",
		"cpanel_login_realtime",
		"ip_reputation",
		"webmail_bruteforce",
	}
	for _, check := range challengeChecks {
		if isHardBlockCheck(check) {
			t.Errorf("isHardBlockCheck(%q) = true, want false (should be challenge-eligible)", check)
		}
	}
}

type mockIPList struct {
	ips map[string]bool
}

func (m *mockIPList) Add(ip, reason string, dur time.Duration) {
	m.ips[ip] = true
}

func (m *mockIPList) Contains(ip string) bool {
	return m.ips[ip]
}

func TestChallengeRouteIPsDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = false

	findings := []alert.Finding{{Check: "wp_login_bruteforce", Message: "brute force from 1.2.3.4"}}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 0 {
		t.Error("should return nil when challenge disabled")
	}
}

func TestChallengeRouteIPsSkipsHardBlock(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	findings := []alert.Finding{
		{Check: "webshell", Message: "webshell detected from 1.2.3.4"},
		{Check: "signature_match_realtime", Message: "malware from 5.6.7.8"},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 0 {
		t.Error("hard-block checks should not produce challenge actions")
	}
	if len(mock.ips) != 0 {
		t.Error("no IPs should be added to challenge list for hard-block checks")
	}
}

func TestChallengeRouteIPsRoutesEligible(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "brute force from 1.2.3.4"},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 1 {
		t.Fatalf("expected 1 challenge action, got %d", len(actions))
	}
	if !mock.ips["1.2.3.4"] {
		t.Error("1.2.3.4 should be on challenge list")
	}
}

func TestChallengeRoute_DoesNotRouteSMTPChecks(t *testing.T) {
	for _, check := range []string{"smtp_bruteforce", "smtp_subnet_spray"} {
		if isChallengeableCheck(check) {
			t.Errorf("check %q must be hard-blocked, not challenge-routed", check)
		}
		if !isHardBlockCheck(check) {
			t.Errorf("check %q must be in hardBlockChecks (defense-in-depth)", check)
		}
	}
}

func TestChallengeRoute_DoesNotRouteMailChecks(t *testing.T) {
	for _, check := range []string{"mail_bruteforce", "mail_subnet_spray", "mail_account_compromised"} {
		if isChallengeableCheck(check) {
			t.Errorf("check %q must be hard-blocked, not challenge-routed", check)
		}
		if !isHardBlockCheck(check) {
			t.Errorf("check %q must be in hardBlockChecks (defense-in-depth)", check)
		}
	}
}

func TestChallengeRoute_DoesNotRoutePAMChecks(t *testing.T) {
	for _, check := range []string{"pam_bruteforce", "credential_stuffing"} {
		if isChallengeableCheck(check) {
			t.Errorf("check %q must be hard-blocked, not challenge-routed", check)
		}
		if !isHardBlockCheck(check) {
			t.Errorf("check %q must be in hardBlockChecks (defense-in-depth)", check)
		}
	}
}

func TestChallengeRoute_AdminPanelIsHardBlocked(t *testing.T) {
	if isChallengeableCheck("admin_panel_bruteforce") {
		t.Error("admin_panel_bruteforce must not be challenge-routed (hard-block only)")
	}
	if !isHardBlockCheck("admin_panel_bruteforce") {
		t.Error("admin_panel_bruteforce must be in hardBlockChecks")
	}
}

// http_scanner_profile carries a client IP probing public URLs over
// HTTP, so a browser can answer the challenge. Default action routes it
// to the challenge; the operator can demand a hard block instead.
func TestChallengeRoute_ScannerProfileRoutedByDefault(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	findings := []alert.Finding{
		{Check: "http_scanner_profile", SourceIP: "192.0.2.10", Message: "URL scanner profile from 192.0.2.10"},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 1 {
		t.Fatalf("expected 1 challenge action, got %d", len(actions))
	}
	if !mock.ips["192.0.2.10"] {
		t.Error("192.0.2.10 should be on challenge list")
	}
}

func TestChallengeRoute_ScannerProfileBlockActionSkipsChallenge(t *testing.T) {
	mock := &mockIPList{ips: make(map[string]bool)}
	old := challengeIPList
	SetChallengeIPList(mock)
	defer SetChallengeIPList(old)

	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.AutoResponse.HTTPScannerAction = "block"

	findings := []alert.Finding{
		{Check: "http_scanner_profile", SourceIP: "192.0.2.10", Message: "URL scanner profile from 192.0.2.10"},
	}
	actions := ChallengeRouteIPs(cfg, findings)
	if len(actions) != 0 {
		t.Fatalf("block action must skip challenge routing, got %d actions", len(actions))
	}
	if mock.ips["192.0.2.10"] {
		t.Error("192.0.2.10 must not be on challenge list when action is block")
	}
}

func TestChallengeRoute_ScannerProfileNotHardBlocked(t *testing.T) {
	if isHardBlockCheck("http_scanner_profile") {
		t.Error("http_scanner_profile must not be in hardBlockChecks")
	}
	if !isChallengeableCheck("http_scanner_profile") {
		t.Error("http_scanner_profile must be challenge-eligible")
	}
}

// Regression guard: routing post-auth audit events or non-browser
// protocols to the PoW challenge produces guaranteed timeout
// hard-blocks because the IP has no browser session for the gate to
// catch. Real-world fallout observed in production: legitimate
// customer cPanel logins from non-local IPs and recursive DNS resolver
// IPs both ended up in 24h temporary blocks.
func TestChallengeRoute_AuditAndNonBrowserChecksAreNotChallengeable(t *testing.T) {
	for _, check := range []string{
		"cpanel_login",
		"cpanel_login_realtime",
		"cpanel_multi_ip_login",
		"cpanel_file_upload",
		"cpanel_file_upload_realtime",
		"ftp_login",
		"ftp_login_realtime",
		"ssh_login_realtime",
		"ssh_login_unknown_ip",
		"webmail_login_realtime",
		"whm_password_change",
		"dns_connection",
		"user_outbound_connection",
		"api_auth_failure",
		"brute_force",
	} {
		if isChallengeableCheck(check) {
			t.Errorf("check %q must NOT be challenge-routed: no browser at the other end", check)
		}
	}
}

func TestResponseActionForCheck(t *testing.T) {
	cases := []struct {
		name          string
		check         string
		scannerAction string
		want          string
	}{
		{"challengeable defaults to challenge", "wp_login_bruteforce", "", "challenge"},
		{"scanner profile challenges by default", "http_scanner_profile", "", "challenge"},
		{"scanner profile blocks when configured", "http_scanner_profile", "block", "block"},
		{"scanner action only overrides scanner check", "wp_login_bruteforce", "block", "challenge"},
		{"non-challengeable hard-blocks", "webshell", "", "block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.AutoResponse.HTTPScannerAction = tc.scannerAction
			if got := responseActionForCheck(cfg, tc.check); got != tc.want {
				t.Errorf("responseActionForCheck(%q, action=%q) = %q, want %q",
					tc.check, tc.scannerAction, got, tc.want)
			}
		})
	}
}

// shouldSkipAutoBlockForChallenge must stay the exact inverse of a resolved
// block action: an IP is left for the challenge gate only while the check
// resolves to "challenge".
func TestShouldSkipAutoBlockForChallengeMatchesResponseAction(t *testing.T) {
	for _, check := range []string{"wp_login_bruteforce", "http_scanner_profile", "webshell", "ip_reputation"} {
		for _, action := range []string{"", "block"} {
			cfg := &config.Config{}
			cfg.AutoResponse.HTTPScannerAction = action
			wantSkip := responseActionForCheck(cfg, check) == "challenge"
			if got := shouldSkipAutoBlockForChallenge(cfg, check); got != wantSkip {
				t.Errorf("shouldSkipAutoBlockForChallenge(%q, action=%q) = %v, want %v",
					check, action, got, wantSkip)
			}
		}
	}
}
