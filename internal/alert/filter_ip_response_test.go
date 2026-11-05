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

func policyConfig(t *testing.T) *config.Config {
	t.Helper()
	withIPResponsePolicy(t, fakeIPResponsePolicy)
	withSummaryNoticePolicy(t, summaryNoticeForTest)
	return &config.Config{StatePath: t.TempDir()}
}

func TestSplitByClassPolicyMovesSameBatchChallengedScanner(t *testing.T) {
	cfg := policyConfig(t)
	findings := []Finding{
		{Check: "http_scanner_profile", Message: "URL scanner profile from 203.0.113.7: 498 of 500 requests", Severity: High, SourceIP: "203.0.113.7"},
		{Check: "challenge_route", Message: "CHALLENGE: 203.0.113.7 sent to PoW challenge (expires in 30m0s)", Severity: Warning},
	}
	assertSplit(t, cfg, findings, nil, findings)
}

func TestSplitByClassPolicyMovesSameBatchBlockedAuthFailure(t *testing.T) {
	cfg := policyConfig(t)
	findings := []Finding{
		{Check: "ftp_auth_failure_realtime", Message: "FTP authentication failed from 203.0.113.8", Severity: High, SourceIP: "203.0.113.8"},
		{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.8 (expires in 24h0m0s)", Severity: Critical},
	}
	assertSplit(t, cfg, findings, nil, findings)
}

func TestSplitByClassPolicyMovesAlreadyBlockedCritical(t *testing.T) {
	cfg := policyConfig(t)
	orig := BlockedIPsFunc
	BlockedIPsFunc = func() map[string]bool { return map[string]bool{"203.0.113.9": true} }
	t.Cleanup(func() { BlockedIPsFunc = orig })

	blocked := Finding{Check: "http_ua_spoof", Message: "User-Agent spoof from 203.0.113.9: claimed bot", Severity: Critical, SourceIP: "203.0.113.9"}
	unblocked := Finding{Check: "http_ua_spoof", Message: "User-Agent spoof from 203.0.113.10: claimed bot", Severity: Critical, SourceIP: "203.0.113.10"}
	assertSplit(t, cfg, []Finding{blocked, unblocked}, []Finding{unblocked}, []Finding{blocked})
}

func TestSplitByClassPolicyChallengeDoesNotAnswerBlockOnlyFinding(t *testing.T) {
	cfg := policyConfig(t)
	orig := ChallengedIPFunc
	ChallengedIPFunc = func(ip string) bool { return ip == "203.0.113.11" }
	t.Cleanup(func() { ChallengedIPFunc = orig })

	findings := []Finding{
		{Check: "ftp_auth_failure_realtime", Message: "FTP authentication failed from 203.0.113.11", Severity: High, SourceIP: "203.0.113.11"},
	}
	assertSplit(t, cfg, findings, findings, nil)
}

func TestSplitByClassPolicyKeepsFindingsItDoesNotAnswer(t *testing.T) {
	cfg := policyConfig(t)
	block := Finding{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.12 (expires in 24h0m0s)", Severity: Critical}
	login := Finding{Check: "cpanel_login", Message: "cPanel direct login from 203.0.113.12", Severity: Warning, SourceIP: "203.0.113.12"}
	// A blocked source's successful login still needs the operator.
	assertSplit(t, cfg, []Finding{block, login}, []Finding{login}, []Finding{block})
}

// No setting keeps a handled attack in alert email any more: the outcome
// decides, so a blocked source's attack goes to the summary.
func TestSplitByClassPolicyHandledGoesToSummaryWithNoSetting(t *testing.T) {
	cfg := policyConfig(t)
	findings := []Finding{
		{Check: "ftp_auth_failure_realtime", Message: "FTP authentication failed from 203.0.113.13", Severity: High, SourceIP: "203.0.113.13"},
		{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.13 (expires in 24h0m0s)", Severity: Critical},
	}
	assertSplit(t, cfg, findings, nil, findings)
}
