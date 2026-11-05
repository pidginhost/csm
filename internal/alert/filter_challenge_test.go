package alert

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSplitByClassSameBatchChallengeMovesReputationToSummary(t *testing.T) {
	withSummaryNoticePolicy(t, summaryNoticeForTest)
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := []Finding{
		{Check: "challenge_route", Message: "CHALLENGE: 203.0.113.77 sent to PoW challenge (expires in 30m0s)", Severity: Warning},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 203.0.113.77 (source: cins-army)", Severity: High},
	}
	// The route notice is summary by its class, the reputation finding by
	// the same-batch challenge.
	assertSplit(t, cfg, findings, nil, findings)
}

func TestSplitByClassSameBatchChallengeLeavesOtherIPs(t *testing.T) {
	withSummaryNoticePolicy(t, summaryNoticeForTest)
	cfg := &config.Config{StatePath: t.TempDir()}
	route := Finding{Check: "challenge_route", Message: "CHALLENGE: 203.0.113.77 sent to PoW challenge (expires in 30m0s)", Severity: Warning}
	other := Finding{Check: "ip_reputation", Message: "Known malicious IP accessing server: 198.51.100.44 (source: cins-army)", Severity: High}
	assertSplit(t, cfg, []Finding{route, other}, []Finding{other}, []Finding{route})
}

func TestSplitByClassActiveChallengeListIPGoesToSummary(t *testing.T) {
	orig := ChallengedIPFunc
	defer func() { ChallengedIPFunc = orig }()
	ChallengedIPFunc = func(ip string) bool { return ip == "203.0.113.55" }

	cfg := &config.Config{StatePath: t.TempDir()}
	challenged := Finding{Check: "ip_reputation", Message: "Known malicious IP accessing server: 203.0.113.55 (source: blocklist-de)", Severity: High, SourceIP: "203.0.113.55"}
	other := Finding{Check: "ip_reputation", Message: "Known malicious IP accessing server: 203.0.113.66 (source: blocklist-de)", Severity: High, SourceIP: "203.0.113.66"}
	assertSplit(t, cfg, []Finding{challenged, other}, []Finding{other}, []Finding{challenged})
}

func TestSplitByClassChallengeKeepsCriticalReputationUntilBlocked(t *testing.T) {
	withSummaryNoticePolicy(t, summaryNoticeForTest)
	orig := ChallengedIPFunc
	defer func() { ChallengedIPFunc = orig }()
	ChallengedIPFunc = func(ip string) bool { return ip == "203.0.113.55" }

	cfg := &config.Config{StatePath: t.TempDir()}
	finding := Finding{
		Check:    "ip_reputation",
		Message:  "Known malicious IP accessing server: 203.0.113.55 (source: blocklist-de)",
		Severity: Critical,
		SourceIP: "203.0.113.55",
	}

	// A hard-block-only reputation finding stays immediate while its
	// source is merely challenged, by list or by a same-batch action.
	assertSplit(t, cfg, []Finding{finding}, []Finding{finding}, nil)
	route := Finding{Check: "challenge_route", Message: "CHALLENGE: 203.0.113.55 sent to PoW challenge", Severity: Warning}
	assertSplit(t, cfg, []Finding{route, finding}, []Finding{finding}, []Finding{route})
}

func TestSplitByClassBlockMovesCriticalReputationToSummary(t *testing.T) {
	withSummaryNoticePolicy(t, summaryNoticeForTest)
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := []Finding{
		{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.55 blocked", Severity: Critical},
		{Check: "ip_reputation", Message: "Known malicious IP accessing server: 203.0.113.55", Severity: Critical, SourceIP: "203.0.113.55"},
	}
	assertSplit(t, cfg, findings, nil, findings)
}

func TestSplitByClassChallengeDoesNotHandleNonReputationChecks(t *testing.T) {
	orig := ChallengedIPFunc
	defer func() { ChallengedIPFunc = orig }()
	ChallengedIPFunc = func(string) bool { return true }

	// With no policy wired only reputation findings are answered by a
	// challenge.
	withIPResponsePolicy(t, nil)
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := []Finding{
		{Check: "wp_login_bruteforce", Message: "brute force from 203.0.113.55", Severity: Critical, SourceIP: "203.0.113.55"},
	}
	assertSplit(t, cfg, findings, findings, nil)
}

// No setting keeps a challenge notice in alert email: an applied challenge
// is handled, so it always goes to the summary.
func TestSplitByClassChallengeRouteGoesToSummaryWithNoSetting(t *testing.T) {
	withSummaryNoticePolicy(t, summaryNoticeForTest)
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := []Finding{
		{Check: "challenge_route", Message: "CHALLENGE: 203.0.113.77 sent to PoW challenge (expires in 30m0s)", Severity: Warning},
	}
	assertSplit(t, cfg, findings, nil, findings)
}
