package alert

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// fakeIPResponsePolicy stands in for the checks package policy: attacker-side
// checks are answered by a block, and the browser-facing ones by a challenge.
func fakeIPResponsePolicy(_ *config.Config, f Finding, blocked bool) bool {
	switch f.Check {
	case "http_scanner_profile", "wp_login_bruteforce":
		return true
	case "ftp_auth_failure_realtime", "http_ua_spoof":
		return blocked
	default:
		return false
	}
}

func withIPResponsePolicy(t *testing.T, p IPResponsePolicy) {
	t.Helper()
	orig := SetIPResponsePolicy(p)
	t.Cleanup(func() { SetIPResponsePolicy(orig) })
}

func suppressingConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	return cfg
}

func TestFilterBlockedAlertsPolicySuppressesSameBatchChallengedScanner(t *testing.T) {
	withIPResponsePolicy(t, fakeIPResponsePolicy)
	findings := []Finding{
		{Check: "http_scanner_profile", Message: "URL scanner profile from 203.0.113.7: 498 of 500 requests", Severity: High, SourceIP: "203.0.113.7"},
		{Check: "challenge_route", Message: "CHALLENGE: 203.0.113.7 sent to PoW challenge (expires in 30m0s)", Severity: Warning},
	}
	if got := FilterBlockedAlerts(suppressingConfig(t), findings); len(got) != 0 {
		t.Fatalf("got %+v, want scanner finding answered by same-batch challenge", got)
	}
}

func TestFilterBlockedAlertsPolicySuppressesSameBatchBlockedAuthFailure(t *testing.T) {
	withIPResponsePolicy(t, fakeIPResponsePolicy)
	findings := []Finding{
		{Check: "ftp_auth_failure_realtime", Message: "FTP authentication failed from 203.0.113.8", Severity: High, SourceIP: "203.0.113.8"},
		{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.8 (expires in 24h0m0s)", Severity: Critical},
	}
	if got := FilterBlockedAlerts(suppressingConfig(t), findings); len(got) != 0 {
		t.Fatalf("got %+v, want auth failure answered by same-batch block", got)
	}
}

func TestFilterBlockedAlertsPolicySuppressesAlreadyBlockedCritical(t *testing.T) {
	withIPResponsePolicy(t, fakeIPResponsePolicy)
	orig := BlockedIPsFunc
	BlockedIPsFunc = func() map[string]bool { return map[string]bool{"203.0.113.9": true} }
	t.Cleanup(func() { BlockedIPsFunc = orig })

	findings := []Finding{
		{Check: "http_ua_spoof", Message: "User-Agent spoof from 203.0.113.9: claimed bot", Severity: Critical, SourceIP: "203.0.113.9"},
		{Check: "http_ua_spoof", Message: "User-Agent spoof from 203.0.113.10: claimed bot", Severity: Critical, SourceIP: "203.0.113.10"},
	}
	got := FilterBlockedAlerts(suppressingConfig(t), findings)
	if len(got) != 1 || got[0].SourceIP != "203.0.113.10" {
		t.Fatalf("got %+v, want only the unblocked source kept", got)
	}
}

func TestFilterBlockedAlertsPolicyChallengeDoesNotAnswerBlockOnlyFinding(t *testing.T) {
	withIPResponsePolicy(t, fakeIPResponsePolicy)
	orig := ChallengedIPFunc
	ChallengedIPFunc = func(ip string) bool { return ip == "203.0.113.11" }
	t.Cleanup(func() { ChallengedIPFunc = orig })

	findings := []Finding{
		{Check: "ftp_auth_failure_realtime", Message: "FTP authentication failed from 203.0.113.11", Severity: High, SourceIP: "203.0.113.11"},
	}
	if got := FilterBlockedAlerts(suppressingConfig(t), findings); len(got) != 1 {
		t.Fatalf("got %+v, want FTP failure kept while its source is only challenged", got)
	}
}

func TestFilterBlockedAlertsPolicyKeepsFindingsItDoesNotAnswer(t *testing.T) {
	withIPResponsePolicy(t, fakeIPResponsePolicy)
	findings := []Finding{
		{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.12 (expires in 24h0m0s)", Severity: Critical},
		{Check: "cpanel_login", Message: "cPanel direct login from 203.0.113.12", Severity: Warning, SourceIP: "203.0.113.12"},
	}
	got := FilterBlockedAlerts(suppressingConfig(t), findings)
	if len(got) != 1 || got[0].Check != "cpanel_login" {
		t.Fatalf("got %+v, want a blocked source's login kept for the operator", got)
	}
}

func TestFilterBlockedAlertsPolicyIgnoredWhenSuppressionDisabled(t *testing.T) {
	withIPResponsePolicy(t, fakeIPResponsePolicy)
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := []Finding{
		{Check: "ftp_auth_failure_realtime", Message: "FTP authentication failed from 203.0.113.13", Severity: High, SourceIP: "203.0.113.13"},
		{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.13 (expires in 24h0m0s)", Severity: Critical},
	}
	if got := FilterBlockedAlerts(cfg, findings); len(got) != 2 {
		t.Fatalf("got %+v, want everything kept with suppression off", got)
	}
}
