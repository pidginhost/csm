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
	defer func() { _ = db.Close() }()

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)

	events := []AttackEvent{
		{Timestamp: base, IP: "1.2.3.4", AttackType: "brute_force", CheckName: "brute-force", Severity: 3},
		{Timestamp: base.Add(1 * time.Minute), IP: "1.2.3.4", AttackType: "webshell", CheckName: "php-shell", Severity: 4},
		{Timestamp: base.Add(2 * time.Minute), IP: "5.6.7.8", AttackType: "brute_force", CheckName: "brute-force", Severity: 3},
		{Timestamp: base.Add(3 * time.Minute), IP: "1.2.3.4", AttackType: "recon", CheckName: "htaccess", Severity: 2},
	}

	for i, ev := range events {
		if err := db.RecordAttackEvent(ev, i); err != nil {
			t.Fatalf("RecordAttackEvent[%d]: %v", i, err)
		}
	}

	// Query "1.2.3.4" - expect 3 events, newest-first.
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

	// Query "5.6.7.8" - expect 1 event.
	results = db.QueryAttackEvents("5.6.7.8", 10)
	if len(results) != 1 {
		t.Errorf("QueryAttackEvents(5.6.7.8) len = %d, want 1", len(results))
	}

	// Query unknown IP - expect 0 events.
	results = db.QueryAttackEvents("9.9.9.9", 10)
	if len(results) != 0 {
		t.Errorf("QueryAttackEvents(9.9.9.9) len = %d, want 0", len(results))
	}

	// Verify counter = 4.
	var count int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		if v := b.Get([]byte("attacks:events:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
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
	defer func() { _ = db.Close() }()

	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	record := IPRecord{
		IP:         "10.20.30.40",
		FirstSeen:  now.Add(-24 * time.Hour),
		LastSeen:   now,
		EventCount: 42,
		AttackCounts: map[string]int{
			"brute_force": 30,
			"webshell":    12,
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
	if loaded.AttackCounts["brute_force"] != 30 {
		t.Errorf("AttackCounts[brute_force] = %d, want 30", loaded.AttackCounts["brute_force"])
	}
	if loaded.Accounts["user2"] != 17 {
		t.Errorf("Accounts[user2] = %d, want 17", loaded.Accounts["user2"])
	}
	if !loaded.FirstSeen.Equal(now.Add(-24 * time.Hour)) {
		t.Errorf("FirstSeen = %v, want %v", loaded.FirstSeen, now.Add(-24*time.Hour))
	}

	// Load unknown IP - not found.
	_, found = db.LoadIPRecord("99.99.99.99")
	if found {
		t.Error("LoadIPRecord(99.99.99.99) should not be found")
	}
}

func TestRecordAttackEventPrunesExcess(t *testing.T) {
	old := maxAttackEvents
	maxAttackEvents = 5
	t.Cleanup(func() { maxAttackEvents = old })

	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)

	// Insert more than maxAttackEvents
	for i := 0; i < 8; i++ {
		ev := AttackEvent{
			Timestamp:  base.Add(time.Duration(i) * time.Second),
			IP:         fmt.Sprintf("10.0.0.%d", i+1),
			AttackType: "brute_force",
			CheckName:  "wp_login",
			Severity:   3,
		}
		if err := db.RecordAttackEvent(ev, i); err != nil {
			t.Fatalf("RecordAttackEvent[%d]: %v", i, err)
		}
	}

	all := db.ReadAllAttackEvents()
	if len(all) != 5 {
		t.Errorf("expected exactly 5 events after pruning, got %d", len(all))
	}

	// Verify oldest events were pruned: 10.0.0.1, 10.0.0.2, 10.0.0.3 should be gone
	for _, ev := range all {
		if ev.IP == "10.0.0.1" || ev.IP == "10.0.0.2" || ev.IP == "10.0.0.3" {
			t.Errorf("oldest event %s should have been pruned", ev.IP)
		}
	}

	// Verify secondary index was cleaned too
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		events := db.QueryAttackEvents(ip, 10)
		if len(events) != 0 {
			t.Errorf("secondary index for pruned IP %s should be empty, got %d", ip, len(events))
		}
	}
}

func TestLoadAllIPRecordsMultiple(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if err := db.SaveIPRecord(IPRecord{IP: ip, EventCount: 1, ThreatScore: 50}); err != nil {
			t.Fatalf("SaveIPRecord: %v", err)
		}
	}

	all := db.LoadAllIPRecords()
	if len(all) != 3 {
		t.Errorf("expected 3 records, got %d", len(all))
	}
}

func TestLoadAllIPRecordsEmpty(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	all := db.LoadAllIPRecords()
	if len(all) != 0 {
		t.Errorf("expected 0 records, got %d", len(all))
	}
}

func TestQueryLimitNewestFirst(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		ev := AttackEvent{
			Timestamp:  base.Add(time.Duration(i) * time.Minute),
			IP:         "10.0.0.1",
			AttackType: "scan",
			CheckName:  "test",
			Severity:   2,
			Message:    fmt.Sprintf("event-%d", i),
		}
		if err := db.RecordAttackEvent(ev, i); err != nil {
			t.Fatalf("RecordAttackEvent: %v", err)
		}
	}

	events := db.QueryAttackEvents("10.0.0.1", 3)
	if len(events) != 3 {
		t.Fatalf("expected 3, got %d", len(events))
	}
	// Verify newest-first ordering
	if events[0].Message != "event-9" {
		t.Errorf("first event should be newest, got %q", events[0].Message)
	}
	if events[2].Message != "event-7" {
		t.Errorf("last event should be event-7, got %q", events[2].Message)
	}
}
