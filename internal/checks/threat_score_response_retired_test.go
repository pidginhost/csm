package checks

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestRetiredThreatScoreCannotDriveIPResponse(t *testing.T) {
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
			legacy := alert.Finding{Check: "local_threat_score", Severity: alert.Critical, SourceIP: "192.0.2.9", Message: "legacy score", Timestamp: time.Now()}
			challenges, blocks := ChallengeThenBlock(cfg, []alert.Finding{legacy})
			if len(challenges) != 0 || len(blocks) != 0 || len(blocker.blocked) != 0 || list.Contains(legacy.SourceIP) {
				t.Fatalf("legacy score drove a response: challenges=%+v blocks=%+v calls=%v", challenges, blocks, blocker.blocked)
			}
			cause := alert.Cause{Check: "db_siteurl_hijack", FindingID: "0123456789abcdef"}
			sessions := sessionAttackerFindings([]string{"192.0.2.13"}, "example.com", cause)
			challenges, blocks = ChallengeThenBlock(cfg, sessions)
			if challengeEnabled {
				if len(challenges) != 1 || len(blocks) != 0 || len(blocker.blocked) != 0 || !list.Contains("192.0.2.13") {
					t.Fatalf("database-session challenge policy changed: challenges=%+v blocks=%+v calls=%v", challenges, blocks, blocker.blocked)
				}
			} else if len(challenges) != 0 || len(blocks) != 1 || len(blocker.blocked) != 1 || blocker.blocked[0] != "192.0.2.13" {
				t.Fatalf("database-session block policy changed: challenges=%+v blocks=%+v calls=%v", challenges, blocks, blocker.blocked)
			}
		})
	}
}

func TestRetiredThreatScorePendingBlockIsDropped(t *testing.T) {
	cfg := pendingTestConfig(t)
	saveBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{
		{IP: "192.0.2.10", Check: "local_threat_score", Severity: alert.Critical, Reason: "legacy score", QueuedAt: time.Now()},
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

func TestDatabaseSessionPendingBlockKeepsCause(t *testing.T) {
	cfg := pendingTestConfig(t)
	swapBlocker(t, &failingIPBlocker{})
	cause := alert.Cause{Check: "db_siteurl_hijack", FindingID: "0123456789abcdef"}
	blockSessionAttackerIPs(cfg, []string{"192.0.2.12"}, "example.com", cause)
	pending := loadBlockState(cfg.StatePath).Pending
	if len(pending) != 1 {
		t.Fatalf("pending = %+v, want one database-session retry", pending)
	}
	raw, err := json.Marshal(pending[0])
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		Cause *alert.Cause `json:"cause"`
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Cause == nil || *persisted.Cause != cause {
		t.Fatalf("pending cause = %+v, want %+v", persisted.Cause, cause)
	}
	blocker := &recordingIPBlocker{}
	SetIPBlocker(blocker)
	AutoBlockIPs(cfg, nil)
	if len(blocker.blocked) != 1 || blocker.blocked[0] != "192.0.2.12" || len(loadBlockState(cfg.StatePath).Pending) != 0 {
		t.Fatalf("database-session retry failed: block calls=%v", blocker.blocked)
	}
}
