package checks

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestIPResponseAnswersFinding(t *testing.T) {
	cfg := &config.Config{}
	scannerBlocks := &config.Config{}
	scannerBlocks.AutoResponse.HTTPScannerAction = "block"

	tests := []struct {
		name    string
		cfg     *config.Config
		finding alert.Finding
		blocked bool
		want    bool
	}{
		{"blocked ftp auth failure", cfg, alert.Finding{Check: "ftp_auth_failure_realtime", Severity: alert.High}, true, true},
		{"challenged ftp auth failure", cfg, alert.Finding{Check: "ftp_auth_failure_realtime", Severity: alert.High}, false, false},
		{"challenged scanner", cfg, alert.Finding{Check: "http_scanner_profile", Severity: alert.High}, false, true},
		{"challenged scanner under block action", scannerBlocks, alert.Finding{Check: "http_scanner_profile", Severity: alert.High}, false, false},
		{"blocked ua spoof", cfg, alert.Finding{Check: "http_ua_spoof", Severity: alert.Critical}, true, true},
		{"challenged ua spoof", cfg, alert.Finding{Check: "http_ua_spoof", Severity: alert.Critical}, false, false},
		{"challenged wp brute force", cfg, alert.Finding{Check: "wp_login_bruteforce", Severity: alert.Critical}, false, true},
		{"challenged high reputation", cfg, alert.Finding{Check: "ip_reputation", Severity: alert.High}, false, true},
		{"challenged critical reputation", cfg, alert.Finding{Check: "ip_reputation", Severity: alert.Critical}, false, false},
		{"blocked critical reputation", cfg, alert.Finding{Check: "ip_reputation", Severity: alert.Critical}, true, true},
		{"blocked waf attacker", cfg, alert.Finding{Check: "waf_attack_blocked", Severity: alert.High}, true, true},
		// Compromise evidence and audit events still need a human even
		// when their source address is already blocked.
		{"blocked webshell observation", cfg, alert.Finding{Check: "php_shield_webshell", Severity: alert.Critical}, true, false},
		{"blocked cpanel login", cfg, alert.Finding{Check: "cpanel_login", Severity: alert.Warning}, true, false},
		{"blocked ftp login", cfg, alert.Finding{Check: "ftp_login_realtime", Severity: alert.Warning}, true, false},
		{"blocked unknown check", cfg, alert.Finding{Check: "not_a_registered_check", Severity: alert.High}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPResponseAnswersFinding(tt.cfg, tt.finding, tt.blocked); got != tt.want {
				t.Fatalf("IPResponseAnswersFinding(%s, blocked=%v) = %v, want %v", tt.finding.Check, tt.blocked, got, tt.want)
			}
		})
	}
}

func TestIPResponsePolicyKeepsMailAndDistributedEvidence(t *testing.T) {
	previous := alert.SetIPResponsePolicy(IPResponseAnswersFinding)
	t.Cleanup(func() { alert.SetIPResponsePolicy(previous) })

	// These messages follow their producers: a mail subject or message ID
	// can contain an IP, and account-spray SourceIP is only the latest sender
	// among many. None describes an attack answered by blocking that one IP.
	findings := []alert.Finding{
		{Check: "email_phishing_content", Severity: alert.Critical, Message: "Suspicious outbound email from sender@example.test (message: 203.0.113.40)"},
		{Check: "email_malware", Severity: alert.Critical, Message: "Malware detected in outbound email from sender@example.test to recipient@example.test: test-signature [subject: update 203.0.113.40 notice]"},
		{Check: "mail_account_spray", Severity: alert.High, SourceIP: "203.0.113.40", Message: "Mail password spray targeting mailbox@example.test: 10 unique IPs in 5m0s"},
		{Check: "smtp_account_spray", Severity: alert.High, SourceIP: "203.0.113.40", Message: "SMTP password spray targeting mailbox@example.test: 10 unique IPs in 5m0s"},
		{Check: "mail_subnet_spray", Severity: alert.Critical, SourceIP: "203.0.113.0/24", Message: "Mail password spray from 203.0.113.0/24: 10 unique IPs in 5m0s"},
		{Check: "smtp_subnet_spray", Severity: alert.Critical, SourceIP: "203.0.113.0/24", Message: "SMTP password spray from 203.0.113.0/24: 10 unique IPs in 5m0s"},
		{Check: "http_distributed_flood", Severity: alert.High, Message: "Distributed HTTP attack on 203.0.113.40: 10 distinct abusive source IPs"},
		{Check: "http_asn_crawl", Severity: alert.High, Message: "Distributed crawl from AS64500 (test network) against 203.0.113.40"},
	}
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	for _, finding := range findings {
		t.Run(finding.Check, func(t *testing.T) {
			for _, blocked := range []bool{true, false} {
				if IPResponseAnswersFinding(cfg, finding, blocked) {
					t.Errorf("finding incorrectly answered by IP disposition (blocked=%v)", blocked)
				}
			}
			batch := []alert.Finding{finding, {
				Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.40 (expires in 24h0m0s)",
			}}
			if got := alert.FilterBlockedAlerts(cfg, batch); !reflect.DeepEqual(got, []alert.Finding{finding}) {
				t.Fatalf("got %+v, want evidence preserved", got)
			}
		})
	}
}

func TestIPResponsePolicyFiltersLiveDispositions(t *testing.T) {
	previousBlocked, previousChallenged := alert.BlockedIPsFunc, alert.ChallengedIPFunc
	alert.BlockedIPsFunc = func() map[string]bool {
		return map[string]bool{"203.0.113.40": true, "2001:db8::40": true}
	}
	alert.ChallengedIPFunc = func(ip string) bool { return ip == "203.0.113.41" }
	t.Cleanup(func() {
		alert.BlockedIPsFunc, alert.ChallengedIPFunc = previousBlocked, previousChallenged
	})
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	kept := []alert.Finding{
		{Check: "ftp_auth_failure_realtime", Severity: alert.High, SourceIP: "203.0.113.41"},
		{Check: "http_ua_spoof", Severity: alert.Critical, SourceIP: "203.0.113.41"},
		{Check: "ip_reputation", Severity: alert.Critical, SourceIP: "203.0.113.41"},
		{Check: "http_scanner_profile", Severity: alert.High, SourceIP: "203.0.113.42"},
		{Check: "php_shield_webshell", Severity: alert.Critical, SourceIP: "203.0.113.40"},
		{Check: "cpanel_login", Severity: alert.Warning, SourceIP: "203.0.113.40"},
		{Check: "shadow_change", Severity: alert.Critical, SourceIP: "203.0.113.40"},
		{Check: "email_phishing_content", Severity: alert.Critical, SourceIP: "203.0.113.40"},
		{Check: "smtp_account_spray", Severity: alert.High, SourceIP: "203.0.113.40"},
	}
	findings := append([]alert.Finding{
		{Check: "ftp_auth_failure_realtime", Severity: alert.High, SourceIP: "203.0.113.40"},
		{Check: "http_ua_spoof", Severity: alert.Critical, SourceIP: "203.0.113.40"},
		{Check: "waf_attack_blocked", Severity: alert.High, SourceIP: "203.0.113.40"},
		{Check: "http_scanner_profile", Severity: alert.High, SourceIP: "203.0.113.41"},
		{Check: "wp_login_bruteforce", Severity: alert.Critical, Message: "WordPress login brute force from 203.0.113.41: 100 attempts"},
		{Check: "ftp_bruteforce", Severity: alert.High, SourceIP: "[2001:db8:0:0::40]:21"},
	}, kept...)
	if got := alert.FilterBlockedAlerts(cfg, findings); !reflect.DeepEqual(got, kept) {
		t.Fatalf("got %+v, want only handled single-source attacks suppressed", got)
	}
	cfg.Suppressions.SuppressBlockedAlerts = false
	if got := alert.FilterBlockedAlerts(cfg, findings); !reflect.DeepEqual(got, findings) {
		t.Fatal("suppression disabled but findings were removed")
	}
}

func TestAlertDispatchUsesIPResponsePolicyWithoutDaemon(t *testing.T) {
	// This package never constructs a daemon. CLI scans and the web UI must
	// get the same policy just by linking the checks package.
	var calls atomic.Int32
	webhook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(webhook.Close)
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = webhook.URL
	block := alert.Finding{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.40 (expires in 24h0m0s)"}
	for _, check := range []string{"test_alert", "cpanel_login"} {
		if err := alert.Dispatch(cfg, []alert.Finding{{Check: check, Severity: alert.Warning, SourceIP: "203.0.113.40"}, block}); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("control dispatches = %d, want test alert and successful login delivered", got)
	}
	if err := alert.Dispatch(cfg, []alert.Finding{{
		Check: "ftp_auth_failure_realtime", Severity: alert.High, SourceIP: "203.0.113.40",
	}, block}); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("webhook calls = %d, want blocked attack suppressed without daemon startup", got)
	}
}
