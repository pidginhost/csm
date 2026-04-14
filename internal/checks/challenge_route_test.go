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
	}
	for _, check := range hardChecks {
		if !isHardBlockCheck(check) {
			t.Errorf("isHardBlockCheck(%q) = false, want true", check)
		}
	}

	// modsec checks are now hard-blocked (modsec already handles the request)
	modsecChecks := []string{
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
	}
}
