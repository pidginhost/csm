package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// local_threat_score has no producer left: neither the retired score scan's
// findings nor the database session findings of older builds drive a
// challenge or a block, with or without their cause, nor corroborate
// central intelligence.
func TestRetiredThreatScoreCannotDriveIPResponse(t *testing.T) {
	if AddressEvidence("local_threat_score", alert.Critical) {
		t.Fatal("a retired score is address evidence")
	}
	cause := alert.Cause{Check: "db_siteurl_hijack", FindingID: "0123456789abcdef"}
	for _, challengeEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "block", true: "challenge"}[challengeEnabled], func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.Challenge.Enabled = challengeEnabled
			blocker := &recordingIPBlocker{}
			swapBlocker(t, blocker)
			oldList := GetChallengeIPList()
			list := &mockIPList{ips: map[string]bool{}}
			SetChallengeIPList(list)
			t.Cleanup(func() { SetChallengeIPList(oldList) })
			findings := []alert.Finding{
				{Check: "local_threat_score", Severity: alert.Critical, SourceIP: "192.0.2.9", Message: "legacy score", Timestamp: time.Now()},
				{Check: "local_threat_score", Severity: alert.Critical, SourceIP: "192.0.2.13", Message: "database session", Cause: &cause, Timestamp: time.Now()},
			}
			challenges, blocks := ChallengeThenBlock(cfg, findings)
			if len(challenges) != 0 || len(blocks) != 0 || len(blocker.blocked) != 0 || list.Contains("192.0.2.9") || list.Contains("192.0.2.13") {
				t.Fatalf("a retired score drove a response: challenges=%+v blocks=%+v calls=%v", challenges, blocks, blocker.blocked)
			}
		})
	}
}

// A queued retry of either kind of retired score is dropped, never blocked.
func TestRetiredThreatScorePendingBlockIsDropped(t *testing.T) {
	cfg := pendingTestConfig(t)
	cause := &alert.Cause{Check: "db_siteurl_hijack", FindingID: "0123456789abcdef"}
	saveBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{
		{IP: "192.0.2.10", Check: "local_threat_score", Severity: alert.Critical, Reason: "legacy score", QueuedAt: time.Now()},
		{IP: "192.0.2.12", Check: "local_threat_score", Severity: alert.Critical, Reason: "database session", Cause: cause, QueuedAt: time.Now()},
		{IP: "192.0.2.11", Check: "wp_login_bruteforce", Severity: alert.Critical, Reason: "confirmed attack", QueuedAt: time.Now()},
	}})
	blocker := &recordingIPBlocker{}
	swapBlocker(t, blocker)
	AutoBlockIPs(cfg, nil)
	if len(blocker.blocked) != 1 || blocker.blocked[0] != "192.0.2.11" {
		t.Fatalf("block calls = %v, want only the confirmed attack", blocker.blocked)
	}
	if pending := loadBlockState(cfg.StatePath).Pending; len(pending) != 0 {
		t.Fatalf("pending work remains: %+v", pending)
	}
}
