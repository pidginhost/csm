package attackdb

import "testing"

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
		AttackCounts: map[AttackType]int{AttackC2: 1, AttackBruteForce: 3},
		Accounts:     make(map[string]int),
	}
	got := ComputeScore(r)
	// 5*2=10 + C2(35) + BruteForce(15) = 60
	if got != 60 {
		t.Errorf("got %d, want 60", got)
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
	r := &IPRecord{
		EventCount: 50,
		AttackCounts: map[AttackType]int{
			AttackC2:         1,
			AttackWebshell:   1,
			AttackPhishing:   1,
			AttackBruteForce: 1,
			AttackFileUpload: 1,
		},
		Accounts: map[string]int{"a": 1, "b": 1},
	}
	got := ComputeScore(r)
	if got != 100 {
		t.Errorf("max score = %d, want 100", got)
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

func TestComputeScore_SustainedBruteForceReachesBlockThreshold(t *testing.T) {
	// A persistent single-account mail brute force (e.g. 1255 dovecot
	// SMTP-AUTH failures from one IP over hours) must reach the
	// local_threat_score auto-block threshold (70). Without the sustained
	// brute tier it tops out at volume 30 + brute 15 = 45 and is never
	// auto-blocked, which is exactly how 79.133.42.191 evaded blocking.
	r := &IPRecord{
		EventCount:   1255,
		AttackCounts: map[AttackType]int{AttackBruteForce: 1255},
		Accounts:     map[string]int{"florin": 1255},
	}
	got := ComputeScore(r)
	if got < 70 {
		t.Errorf("sustained single-IP brute force score = %d, want >= 70 (block threshold)", got)
	}
}

func TestComputeScore_BriefAuthFailuresStayBelowBlock(t *testing.T) {
	// A legitimate user with a stale saved password produces a handful of
	// auth failures, not dozens. This must stay well under the block
	// threshold so a brief credential mishap is never a 24h IP block.
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
