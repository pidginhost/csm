package store

import (
	"testing"
	"time"
)

func openThreatTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// A timed operator block records operator evidence that lapses with the
// firewall block. It must not be classified as legacy permanent evidence
// just because its reason matches a legacy operator prefix.
func TestAddOperatorTempBlockExpiresWithBlock(t *testing.T) {
	db := openThreatTestDB(t)
	ip := "192.0.2.40"
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := db.AddOperatorTempBlock(ip, "Manually blocked via CSM Web UI", expiresAt); err != nil {
		t.Fatalf("AddOperatorTempBlock: %v", err)
	}
	entry, found := db.GetPermanentBlock(ip)
	if !found {
		t.Fatal("operator temp row not written")
	}
	if entry.Source != ThreatSourceOperator {
		t.Fatalf("source = %q, want operator", entry.Source)
	}
	if !entry.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expires_at = %v, want %v", entry.ExpiresAt, expiresAt)
	}
	if entry.Expired(time.Now()) {
		t.Fatal("operator temp row expired while the block is live")
	}
	if !entry.Expired(expiresAt.Add(time.Second)) {
		t.Fatal("operator temp row still live after the block lapsed")
	}
	if count := db.getCounter("threats:count"); count != 1 {
		t.Fatalf("threats:count = %d, want 1", count)
	}
}

func TestAddOperatorTempBlockIgnoresZeroExpiry(t *testing.T) {
	db := openThreatTestDB(t)
	if err := db.AddOperatorTempBlock("192.0.2.41", "Manually blocked via CSM Web UI", time.Time{}); err != nil {
		t.Fatalf("AddOperatorTempBlock: %v", err)
	}
	if _, found := db.GetPermanentBlock("192.0.2.41"); found {
		t.Fatal("zero expiry created a never-expiring row through the temp path")
	}
}

func TestAddOperatorTempBlockNeverDowngradesPermanentRows(t *testing.T) {
	db := openThreatTestDB(t)

	// Tagged operator permanent row.
	if err := db.AddPermanentBlock("192.0.2.42", "Permanently blocked via CSM Web UI"); err != nil {
		t.Fatalf("AddPermanentBlock: %v", err)
	}
	// Legacy no-source operator row, still live via its reason prefix.
	if err := seedRawThreatRow(db, "192.0.2.43", "Manually blocked via CSM Web UI [2026-01-02]"); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	for _, ip := range []string{"192.0.2.42", "192.0.2.43"} {
		before, _ := db.GetPermanentBlock(ip)
		if err := db.AddOperatorTempBlock(ip, "Manually blocked via CSM Web UI", expiresAt); err != nil {
			t.Fatalf("AddOperatorTempBlock(%s): %v", ip, err)
		}
		after, found := db.GetPermanentBlock(ip)
		if !found {
			t.Fatalf("%s: permanent row deleted", ip)
		}
		if !after.ExpiresAt.IsZero() || after.Source != before.Source || after.Reason != before.Reason {
			t.Fatalf("%s: permanent row downgraded: before=%+v after=%+v", ip, before, after)
		}
	}
}

func TestAddOperatorTempBlockKeepsLongerLiveExpiry(t *testing.T) {
	db := openThreatTestDB(t)
	ip := "192.0.2.44"
	longer := time.Now().Add(48 * time.Hour)
	if err := db.AddTempBlock(ip, "web_attack", longer); err != nil {
		t.Fatalf("AddTempBlock: %v", err)
	}
	if err := db.AddOperatorTempBlock(ip, "Manually blocked via CSM Web UI", time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("AddOperatorTempBlock: %v", err)
	}
	entry, _ := db.GetPermanentBlock(ip)
	if !entry.ExpiresAt.Equal(longer) {
		t.Fatalf("expiry shortened: got %v, want %v", entry.ExpiresAt, longer)
	}

	// A shorter auto-block row is extended and re-attributed to the operator.
	ip2 := "192.0.2.45"
	if err := db.AddTempBlock(ip2, "web_attack", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("AddTempBlock: %v", err)
	}
	want := time.Now().Add(24 * time.Hour)
	if err := db.AddOperatorTempBlock(ip2, "Manually blocked via CSM Web UI", want); err != nil {
		t.Fatalf("AddOperatorTempBlock: %v", err)
	}
	entry2, _ := db.GetPermanentBlock(ip2)
	if !entry2.ExpiresAt.Equal(want) || entry2.Source != ThreatSourceOperator {
		t.Fatalf("shorter auto-block row not replaced: %+v", entry2)
	}
	if count := db.getCounter("threats:count"); count != 2 {
		t.Fatalf("threats:count = %d, want 2", count)
	}
}

// Firewall-lifetime rows (auto-block, or any row with an expiry) go away
// with the firewall block; never-expiring operator and legacy rows stay.
func TestRemoveTemporaryBlockDropsTimedOperatorRows(t *testing.T) {
	db := openThreatTestDB(t)
	if err := db.AddOperatorTempBlock("192.0.2.46", "Manually blocked via CSM Web UI", time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("AddOperatorTempBlock: %v", err)
	}
	if err := db.AddPermanentBlock("192.0.2.47", "Permanently blocked via CSM Web UI"); err != nil {
		t.Fatalf("AddPermanentBlock: %v", err)
	}

	if removed, err := db.RemoveTemporaryBlock("192.0.2.46"); err != nil || !removed {
		t.Fatalf("RemoveTemporaryBlock(timed operator) = (%v, %v), want (true, nil)", removed, err)
	}
	if _, found := db.GetPermanentBlock("192.0.2.46"); found {
		t.Fatal("timed operator row survived the firewall unblock")
	}
	if removed, err := db.RemoveTemporaryBlock("192.0.2.47"); err != nil || removed {
		t.Fatalf("RemoveTemporaryBlock(permanent operator) = (%v, %v), want (false, nil)", removed, err)
	}
	if count := db.getCounter("threats:count"); count != 1 {
		t.Fatalf("threats:count = %d, want 1", count)
	}
}
