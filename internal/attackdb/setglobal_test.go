package attackdb

import "testing"

// SetGlobal is the test-only escape hatch around Init's sync.Once.
// NewForTest builds a bare DB without touching disk or starting a
// background saver. Both are used cross-package by the checks and
// webui tests; this file proves the pair round-trips correctly.
func TestSetGlobalRoundTrip(t *testing.T) {
	t.Cleanup(func() { SetGlobal(nil) })

	if Global() != nil {
		t.Fatal("Global() must start nil under sync.Once for a fresh process")
	}

	db := NewForTest(map[string]*IPRecord{
		"198.51.100.7": {IP: "198.51.100.7", ThreatScore: 55, EventCount: 2},
	})
	SetGlobal(db)
	got := Global()
	if got == nil {
		t.Fatal("Global() nil after SetGlobal")
	}
	if got != db {
		t.Error("Global() must return the exact pointer SetGlobal installed")
	}

	// TopAttackers on the test DB must see the seeded record.
	recs := got.TopAttackers(10)
	if len(recs) != 1 || recs[0].IP != "198.51.100.7" {
		t.Errorf("seeded record missing from TopAttackers: %+v", recs)
	}
}

// NewForTest must deep-copy the attack-counts map so a mutation in
// one test cannot bleed into another through a shared reference.
func TestNewForTestDeepCopiesAttackCounts(t *testing.T) {
	source := map[string]*IPRecord{
		"198.51.100.8": {
			IP:           "198.51.100.8",
			ThreatScore:  40,
			AttackCounts: map[AttackType]int{AttackBruteForce: 5},
		},
	}
	db := NewForTest(source)

	// Mutate the original map's nested map; the DB's copy must not
	// pick up the change.
	source["198.51.100.8"].AttackCounts[AttackWebshell] = 99

	recs := db.TopAttackers(10)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].AttackCounts[AttackWebshell] != 0 {
		t.Errorf("NewForTest did not deep-copy AttackCounts (leaked %d via shared map)",
			recs[0].AttackCounts[AttackWebshell])
	}
}

// A nil-map input must produce a DB with a usable records map — the
// nil-valued nested maps inside an IPRecord are replaced with empty
// ones so callers can write to them without a nil-map panic.
func TestNewForTestNilInnerMapsAreNormalised(t *testing.T) {
	db := NewForTest(map[string]*IPRecord{
		"198.51.100.9": {IP: "198.51.100.9", ThreatScore: 30},
	})
	recs := db.TopAttackers(10)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].AttackCounts == nil {
		t.Error("AttackCounts must be non-nil after NewForTest")
	}
	if recs[0].Accounts == nil {
		t.Error("Accounts must be non-nil after NewForTest")
	}
}
