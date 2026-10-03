package attackdb

import (
	"testing"
	"time"
)

func TestComputeScoreEmpty(t *testing.T) {
	r := &IPRecord{AttackCounts: make(map[AttackType]int), Accounts: make(map[string]int)}
	if got := ComputeScore(r); got != 0 {
		t.Errorf("empty record = %d, want 0", got)
	}
}

func TestComputeScoreVolumeOnly(t *testing.T) {
	r := &IPRecord{EventCount: 10, AttackCounts: make(map[AttackType]int), Accounts: make(map[string]int)}
	got := ComputeScore(r)
	if got != 20 { // 10*2 = 20, capped at 30
		t.Errorf("10 events = %d, want 20", got)
	}
}

func TestComputeScoreVolumeCapAt30(t *testing.T) {
	r := &IPRecord{EventCount: 50, AttackCounts: make(map[AttackType]int), Accounts: make(map[string]int)}
	got := ComputeScore(r)
	if got != 30 { // capped at 30
		t.Errorf("50 events = %d, want 30 (capped)", got)
	}
}

func TestComputeScoreAttackTypes(t *testing.T) {
	r := &IPRecord{
		EventCount:   5,
		AttackCounts: map[AttackType]int{AttackBruteForce: 3},
		Accounts:     make(map[string]int),
	}
	got := ComputeScore(r)
	// 5*2=10 + BruteForce(15) = 25
	if got != 25 {
		t.Errorf("got %d, want 25", got)
	}
}

func TestComputeScoreMultiAccount(t *testing.T) {
	r := &IPRecord{
		EventCount:   1,
		AttackCounts: make(map[AttackType]int),
		Accounts:     map[string]int{"alice": 1, "bob": 1},
	}
	got := ComputeScore(r)
	// 1*2=2 + multi-account(10) = 12
	if got != 12 {
		t.Errorf("got %d, want 12", got)
	}
}

func TestComputeScoreAutoBlockedMinimum50(t *testing.T) {
	r := &IPRecord{
		EventCount:   1,
		AutoBlocked:  true,
		AttackCounts: make(map[AttackType]int),
		Accounts:     make(map[string]int),
	}
	got := ComputeScore(r)
	if got != 50 { // floor is 50 when auto-blocked
		t.Errorf("auto-blocked floor = %d, want 50", got)
	}
}

func TestComputeScoreCap100(t *testing.T) {
	// Every bonus at once: volume 30, brute force 15, WAF 10, upload 20 and
	// multiple accounts 10.
	r := &IPRecord{
		EventCount: 60,
		AttackCounts: map[AttackType]int{
			AttackBruteForce: 52,
			AttackWAFBlock:   6,
			AttackFileUpload: 1,
		},
		Accounts: map[string]int{"a": 1, "b": 1},
	}
	got := ComputeScore(r)
	if got != 85 || got > 100 {
		t.Errorf("max score = %d, want 85 and never above 100", got)
	}
}

func TestSortRecordsByScore(t *testing.T) {
	recs := []*IPRecord{
		{IP: "a", ThreatScore: 20, EventCount: 5},
		{IP: "b", ThreatScore: 80, EventCount: 10},
		{IP: "c", ThreatScore: 80, EventCount: 20},
	}
	sortRecords(recs)
	if recs[0].IP != "c" {
		t.Errorf("first = %q, want c (highest score + events)", recs[0].IP)
	}
	if recs[1].IP != "b" {
		t.Errorf("second = %q, want b", recs[1].IP)
	}
	if recs[2].IP != "a" {
		t.Errorf("third = %q, want a", recs[2].IP)
	}
}

// A fast single-IP brute force blocks through its own producer (the mail,
// SMTP, FTP or SSH tracker), whose gates know about successful logins and
// auth backend outages. Its attack record alone never reaches the
// local_threat_score block threshold.
func TestComputeScore_SustainedBruteForceStaysBelowBlockThreshold(t *testing.T) {
	now := time.Now()
	r := &IPRecord{
		EventCount:   1255,
		AttackCounts: map[AttackType]int{AttackBruteForce: 1255},
		Accounts:     map[string]int{"owner": 1255},
		LastSeen:     now,
	}
	got := ComputeScore(r)
	if got >= 70 {
		t.Errorf("sustained single-IP brute force score = %d, want < 70 (the producer blocks, not the score)", got)
	}
}

func TestComputeScore_SlowStalePasswordDoesNotReachBlockThreshold(t *testing.T) {
	now := time.Now()
	r := &IPRecord{
		EventCount:   50,
		AttackCounts: map[AttackType]int{AttackBruteForce: 50},
		Accounts:     map[string]int{"owner": 50},
		LastSeen:     now,
	}
	got := ComputeScore(r)
	if got >= 70 {
		t.Errorf("slow stale-password score = %d, want < 70 (no auto-block)", got)
	}
}

func TestComputeScore_CumulativeBruteWithoutRecentSustainedMarkerStaysBelowBlock(t *testing.T) {
	now := time.Now()
	r := &IPRecord{
		EventCount:   50,
		AttackCounts: map[AttackType]int{AttackBruteForce: 50},
		Accounts:     map[string]int{"owner": 50},
		LastSeen:     now,
	}
	got := ComputeScore(r)
	if got >= 70 {
		t.Errorf("cumulative brute score without recent marker = %d, want < 70", got)
	}
}

func TestComputeScore_BriefAuthFailuresStayBelowBlock(t *testing.T) {
	r := &IPRecord{
		EventCount:   6,
		AttackCounts: map[AttackType]int{AttackBruteForce: 6},
		Accounts:     map[string]int{"owner": 6},
	}
	got := ComputeScore(r)
	if got >= 70 {
		t.Errorf("brief auth failures score = %d, want < 70 (no auto-block)", got)
	}
}
