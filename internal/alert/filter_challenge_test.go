package alert

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestFilterBlockedAlertsSuppressesSameBatchChallenge(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	findings := []Finding{
		{Check: "challenge_route", Message: "CHALLENGE: 7.7.7.7 sent to PoW challenge (expires in 30m0s)", Severity: Warning},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 7.7.7.7 (source: cins-army)", Severity: High},
	}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 0 {
		t.Errorf("got %+v, want both suppressed (challenge_route dropped, reputation covered by same-batch challenge)", got)
	}
}

func TestFilterBlockedAlertsSameBatchChallengeLeavesOtherIPs(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	findings := []Finding{
		{Check: "challenge_route", Message: "CHALLENGE: 7.7.7.7 sent to PoW challenge (expires in 30m0s)", Severity: Warning},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 8.8.4.4 (source: cins-army)", Severity: High},
	}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 1 || got[0].Check != "ip_reputation" || !strings.Contains(got[0].Message, "8.8.4.4") {
		t.Errorf("got %+v, want only the unchallenged reputation finding kept", got)
	}
}

func TestFilterBlockedAlertsSuppressesActiveChallengeListIP(t *testing.T) {
	orig := ChallengedIPFunc
	defer func() { ChallengedIPFunc = orig }()
	ChallengedIPFunc = func(ip string) bool { return ip == "5.5.5.5" }

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	findings := []Finding{
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 5.5.5.5 (source: blocklist-de)", Severity: High, SourceIP: "5.5.5.5"},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 6.6.6.6 (source: blocklist-de)", Severity: High, SourceIP: "6.6.6.6"},
	}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 1 || !strings.Contains(got[0].Message, "6.6.6.6") {
		t.Errorf("got %+v, want challenged 5.5.5.5 suppressed and 6.6.6.6 kept", got)
	}
}

func TestFilterBlockedAlertsChallengeKeepsCriticalReputationUntilBlocked(t *testing.T) {
	orig := ChallengedIPFunc
	defer func() { ChallengedIPFunc = orig }()
	ChallengedIPFunc = func(ip string) bool { return ip == "5.5.5.5" }

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	finding := Finding{
		Check:    "ip_reputation",
		Message:  "Known malicious IP accessing server: 5.5.5.5 (source: blocklist-de)",
		Severity: Critical,
		SourceIP: "5.5.5.5",
	}

	got := FilterBlockedAlerts(cfg, []Finding{finding})
	if len(got) != 1 || got[0].Check != "ip_reputation" {
		t.Fatalf("got %+v, want hard-block-only reputation finding kept while merely challenged", got)
	}

	got = FilterBlockedAlerts(cfg, []Finding{
		{Check: "challenge_route", Message: "CHALLENGE: 5.5.5.5 sent to PoW challenge", Severity: Warning},
		finding,
	})
	if len(got) != 1 || got[0].Check != "ip_reputation" {
		t.Fatalf("got %+v, want same-batch challenge action not to hide hard-block-only reputation", got)
	}
}

func TestFilterBlockedAlertsBlockSuppressesCriticalReputation(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	findings := []Finding{
		{Check: "auto_block", Message: "AUTO-BLOCK: 5.5.5.5 blocked", Severity: Critical},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 5.5.5.5", Severity: Critical, SourceIP: "5.5.5.5"},
	}

	if got := FilterBlockedAlerts(cfg, findings); len(got) != 0 {
		t.Fatalf("got %+v, want critical reputation suppressed after same-batch hard block", got)
	}
}

func TestFilterBlockedAlertsChallengeDoesNotSuppressNonReputationChecks(t *testing.T) {
	orig := ChallengedIPFunc
	defer func() { ChallengedIPFunc = orig }()
	ChallengedIPFunc = func(string) bool { return true }

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	findings := []Finding{
		{Check: "wp_login_bruteforce", Message: "brute force from 5.5.5.5", Severity: Critical, SourceIP: "5.5.5.5"},
	}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 1 {
		t.Errorf("got %+v, want non-reputation finding kept despite challenge membership", got)
	}
}

func TestFilterBlockedAlertsDisabledKeepsChallengeRouteFindings(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = false
	findings := []Finding{
		{Check: "challenge_route", Message: "CHALLENGE: 7.7.7.7 sent to PoW challenge (expires in 30m0s)", Severity: Warning},
	}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 1 {
		t.Errorf("got %+v, want challenge_route kept when suppression disabled", got)
	}
}
