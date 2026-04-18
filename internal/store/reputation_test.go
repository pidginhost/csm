package store

import (
	"fmt"
	"testing"
	"time"
)

func TestReputationGetSet(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now().Truncate(time.Second)

	// Set an entry.
	entry := ReputationEntry{
		Score:     95,
		Category:  "malware",
		CheckedAt: now,
	}
	if err := db.SetReputation("10.0.0.1", entry); err != nil {
		t.Fatalf("SetReputation: %v", err)
	}

	// Get it back and verify fields.
	got, found := db.GetReputation("10.0.0.1")
	if !found {
		t.Fatal("GetReputation(10.0.0.1): not found")
	}
	if got.Score != 95 {
		t.Fatalf("Score = %d, want 95", got.Score)
	}
	if got.Category != "malware" {
		t.Fatalf("Category = %q, want %q", got.Category, "malware")
	}
	if !got.CheckedAt.Equal(now) {
		t.Fatalf("CheckedAt = %v, want %v", got.CheckedAt, now)
	}

	// Get unknown IP - not found.
	_, found = db.GetReputation("10.0.0.99")
	if found {
		t.Fatal("GetReputation(10.0.0.99) should not be found")
	}
}

func TestReputationCleanExpired(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()

	// 1 fresh entry.
	if err := db.SetReputation("10.0.0.1", ReputationEntry{
		Score:     80,
		Category:  "spam",
		CheckedAt: now,
	}); err != nil {
		t.Fatalf("SetReputation(10.0.0.1): %v", err)
	}

	// 1 expired entry (7 hours old).
	if err := db.SetReputation("10.0.0.2", ReputationEntry{
		Score:     60,
		Category:  "botnet",
		CheckedAt: now.Add(-7 * time.Hour),
	}); err != nil {
		t.Fatalf("SetReputation(10.0.0.2): %v", err)
	}

	// 1 fresh entry.
	if err := db.SetReputation("10.0.0.3", ReputationEntry{
		Score:     70,
		Category:  "scanner",
		CheckedAt: now,
	}); err != nil {
		t.Fatalf("SetReputation(10.0.0.3): %v", err)
	}

	// Clean with 6h maxAge - should remove 1 (the 7h-old entry).
	removed := db.CleanExpiredReputation(6 * time.Hour)
	if removed != 1 {
		t.Fatalf("CleanExpiredReputation = %d, want 1", removed)
	}

	// Verify expired entry is gone.
	_, found := db.GetReputation("10.0.0.2")
	if found {
		t.Fatal("expired entry 10.0.0.2 should be gone after clean")
	}

	// Verify fresh entries remain.
	if _, found := db.GetReputation("10.0.0.1"); !found {
		t.Fatal("fresh entry 10.0.0.1 should still exist")
	}
	if _, found := db.GetReputation("10.0.0.3"); !found {
		t.Fatal("fresh entry 10.0.0.3 should still exist")
	}
}

func TestAbuseQuotaExhaustedUntil(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// No value yet - zero time.
	if got := db.AbuseQuotaExhaustedUntil(); !got.IsZero() {
		t.Fatalf("AbuseQuotaExhaustedUntil: want zero, got %v", got)
	}

	// Persist and read back.
	until := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	if err := db.SetAbuseQuotaExhaustedUntil(until); err != nil {
		t.Fatalf("SetAbuseQuotaExhaustedUntil: %v", err)
	}
	got := db.AbuseQuotaExhaustedUntil()
	if !got.Equal(until) {
		t.Fatalf("AbuseQuotaExhaustedUntil = %v, want %v", got, until)
	}
}

func TestAbuseQueryCount(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	day := "2026-04-18"
	if got := db.AbuseQueryCount(day); got != 0 {
		t.Fatalf("initial count = %d, want 0", got)
	}

	for i := 1; i <= 5; i++ {
		if got := db.IncrementAbuseQueryCount(day); got != i {
			t.Fatalf("Increment #%d = %d, want %d", i, got, i)
		}
	}

	if got := db.AbuseQueryCount(day); got != 5 {
		t.Fatalf("AbuseQueryCount = %d, want 5", got)
	}

	// Different day is independent.
	if got := db.AbuseQueryCount("2026-04-19"); got != 0 {
		t.Fatalf("next-day count = %d, want 0", got)
	}
}

func TestReputationMaxCap(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Now().Add(-24 * time.Hour)

	// Insert 20 entries with staggered CheckedAt times.
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if err := db.SetReputation(ip, ReputationEntry{
			Score:     50 + i,
			Category:  "test",
			CheckedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("SetReputation(%s): %v", ip, err)
		}
	}

	// Enforce cap of 10 - should remove 10 oldest.
	removed := db.EnforceReputationCap(10)
	if removed != 10 {
		t.Fatalf("EnforceReputationCap = %d, want 10", removed)
	}

	// Verify 10 remain.
	var remaining int
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if _, found := db.GetReputation(ip); found {
			remaining++
		}
	}
	if remaining != 10 {
		t.Fatalf("remaining entries = %d, want 10", remaining)
	}

	// The oldest 10 (i=0..9) should be gone, newest 10 (i=10..19) should remain.
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if _, found := db.GetReputation(ip); found {
			t.Fatalf("oldest entry %s should have been removed", ip)
		}
	}
	for i := 10; i < 20; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if _, found := db.GetReputation(ip); !found {
			t.Fatalf("newest entry %s should still exist", ip)
		}
	}
}
