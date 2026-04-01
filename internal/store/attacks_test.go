package store

import (
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestRecordAndQueryEvents(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)

	events := []AttackEvent{
		{Timestamp: base, IP: "1.2.3.4", AttackType: 1, CheckName: "brute-force", Severity: 3},
		{Timestamp: base.Add(1 * time.Minute), IP: "1.2.3.4", AttackType: 2, CheckName: "php-shell", Severity: 4},
		{Timestamp: base.Add(2 * time.Minute), IP: "5.6.7.8", AttackType: 1, CheckName: "brute-force", Severity: 3},
		{Timestamp: base.Add(3 * time.Minute), IP: "1.2.3.4", AttackType: 3, CheckName: "htaccess", Severity: 2},
	}

	for i, ev := range events {
		if err := db.RecordAttackEvent(ev, i); err != nil {
			t.Fatalf("RecordAttackEvent[%d]: %v", i, err)
		}
	}

	// Query "1.2.3.4" — expect 3 events, newest-first.
	results := db.QueryAttackEvents("1.2.3.4", 10)
	if len(results) != 3 {
		t.Fatalf("QueryAttackEvents(1.2.3.4) len = %d, want 3", len(results))
	}
	for i := 0; i < len(results)-1; i++ {
		if !results[i].Timestamp.After(results[i+1].Timestamp) {
			t.Errorf("results[%d].Timestamp (%v) should be after results[%d].Timestamp (%v)",
				i, results[i].Timestamp, i+1, results[i+1].Timestamp)
		}
	}

	// Query "5.6.7.8" — expect 1 event.
	results = db.QueryAttackEvents("5.6.7.8", 10)
	if len(results) != 1 {
		t.Errorf("QueryAttackEvents(5.6.7.8) len = %d, want 1", len(results))
	}

	// Query unknown IP — expect 0 events.
	results = db.QueryAttackEvents("9.9.9.9", 10)
	if len(results) != 0 {
		t.Errorf("QueryAttackEvents(9.9.9.9) len = %d, want 0", len(results))
	}

	// Verify counter = 4.
	var count int
	db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		if v := b.Get([]byte("attacks:events:count")); v != nil {
			fmt.Sscanf(string(v), "%d", &count)
		}
		return nil
	})
	if count != 4 {
		t.Errorf("attacks:events:count = %d, want 4", count)
	}
}

func TestSaveLoadIPRecord(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	record := IPRecord{
		IP:         "10.20.30.40",
		FirstSeen:  now.Add(-24 * time.Hour),
		LastSeen:   now,
		EventCount: 42,
		AttackCounts: map[int]int{
			1: 30,
			2: 12,
		},
		Accounts: map[string]int{
			"user1": 25,
			"user2": 17,
		},
		ThreatScore: 85,
		AutoBlocked: true,
	}

	if err := db.SaveIPRecord(record); err != nil {
		t.Fatalf("SaveIPRecord: %v", err)
	}

	loaded, found := db.LoadIPRecord("10.20.30.40")
	if !found {
		t.Fatal("LoadIPRecord: not found")
	}
	if loaded.EventCount != 42 {
		t.Errorf("EventCount = %d, want 42", loaded.EventCount)
	}
	if loaded.ThreatScore != 85 {
		t.Errorf("ThreatScore = %d, want 85", loaded.ThreatScore)
	}
	if !loaded.AutoBlocked {
		t.Error("AutoBlocked = false, want true")
	}
	if loaded.AttackCounts[1] != 30 {
		t.Errorf("AttackCounts[1] = %d, want 30", loaded.AttackCounts[1])
	}
	if loaded.Accounts["user2"] != 17 {
		t.Errorf("Accounts[user2] = %d, want 17", loaded.Accounts["user2"])
	}
	if !loaded.FirstSeen.Equal(now.Add(-24 * time.Hour)) {
		t.Errorf("FirstSeen = %v, want %v", loaded.FirstSeen, now.Add(-24*time.Hour))
	}

	// Load unknown IP — not found.
	_, found = db.LoadIPRecord("99.99.99.99")
	if found {
		t.Error("LoadIPRecord(99.99.99.99) should not be found")
	}
}
