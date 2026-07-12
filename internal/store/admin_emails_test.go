package store

import (
	"testing"
	"time"
)

func TestRecordAdminEmail_NewEmailCreatesEntry(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.RecordAdminEmail("ops@example.test", "alice", "alice_wp", time.Now()); err != nil {
		t.Fatalf("RecordAdminEmail: %v", err)
	}
	owners, _ := db.AdminEmailOwners("ops@example.test")
	if len(owners) != 1 {
		t.Fatalf("got %d owners, want 1", len(owners))
	}
	if owners[0].Account != "alice" || owners[0].Schema != "alice_wp" {
		t.Errorf("got owner %+v", owners[0])
	}
}

func TestRecordAdminEmail_SameEmailDifferentAccountAppends(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()
	_ = db.RecordAdminEmail("ops@example.test", "alice", "alice_wp", now)
	_ = db.RecordAdminEmail("ops@example.test", "bob", "bob_wp", now)

	owners, _ := db.AdminEmailOwners("ops@example.test")
	if len(owners) != 2 {
		t.Fatalf("got %d owners, want 2", len(owners))
	}
	accounts := map[string]bool{}
	for _, o := range owners {
		accounts[o.Account] = true
	}
	if !accounts["alice"] || !accounts["bob"] {
		t.Errorf("expected both alice and bob, got %v", accounts)
	}
}

func TestRecordAdminEmail_SameAccountUpdatesLastSeenNoDuplicate(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	t1 := time.Now().Add(-1 * time.Hour)
	t2 := time.Now()
	_ = db.RecordAdminEmail("ops@example.test", "alice", "alice_wp", t1)
	_ = db.RecordAdminEmail("ops@example.test", "alice", "alice_wp", t2)

	owners, _ := db.AdminEmailOwners("ops@example.test")
	if len(owners) != 1 {
		t.Fatalf("expected single owner after re-record, got %d", len(owners))
	}
	if !owners[0].LastSeen.Equal(t2) {
		t.Errorf("LastSeen = %v, want %v", owners[0].LastSeen, t2)
	}
}

func TestOverlappingAdminEmails_BelowThresholdReturnsNothing(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()
	_ = db.RecordAdminEmail("solo@example.test", "alice", "alice_wp", now)

	out, _ := db.OverlappingAdminEmails(2, 90*24*time.Hour)
	if len(out) != 0 {
		t.Errorf("expected no overlap below threshold, got %v", out)
	}
}

func TestOverlappingAdminEmails_AtThresholdReturnsResults(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()
	_ = db.RecordAdminEmail("ops@example.test", "alice", "alice_wp", now)
	_ = db.RecordAdminEmail("ops@example.test", "bob", "bob_wp", now)

	out, _ := db.OverlappingAdminEmails(2, 90*24*time.Hour)
	if len(out) != 1 {
		t.Fatalf("expected one overlapping email, got %d (%v)", len(out), out)
	}
	if len(out["ops@example.test"]) != 2 {
		t.Errorf("expected 2 owners for ops@example.test, got %d", len(out["ops@example.test"]))
	}
}

func TestOverlappingAdminEmails_StaleEntriesEvicted(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	stale := time.Now().Add(-180 * 24 * time.Hour)
	fresh := time.Now()
	_ = db.RecordAdminEmail("mix@example.test", "alice", "alice_wp", stale)
	_ = db.RecordAdminEmail("mix@example.test", "bob", "bob_wp", fresh)

	// Retention window of 90d: alice's entry is stale, only bob remains.
	// One owner -- below the threshold, so no overlap finding.
	out, _ := db.OverlappingAdminEmails(2, 90*24*time.Hour)
	if len(out) != 0 {
		t.Errorf("stale entry not evicted, overlap returned %v", out)
	}
	owners, err := db.AdminEmailOwners("mix@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].Account != "bob" {
		t.Fatalf("persisted owners after retention = %+v, want only bob", owners)
	}
}

func TestOverlappingAdminEmails_ThresholdAboveTwoFiltersTwoOwnerCase(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()
	_ = db.RecordAdminEmail("ops@example.test", "alice", "alice_wp", now)
	_ = db.RecordAdminEmail("ops@example.test", "bob", "bob_wp", now)

	out, _ := db.OverlappingAdminEmails(3, 90*24*time.Hour)
	if len(out) != 0 {
		t.Errorf("threshold=3 must filter two-owner case, got %v", out)
	}
}
