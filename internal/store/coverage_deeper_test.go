package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// --- RecordAttackEvent: edge cases ----------------------------------------

func TestRecordAttackEventSingleEventNoPrune(t *testing.T) {
	db := openTestDB(t)
	ev := AttackEvent{
		Timestamp:  time.Now(),
		IP:         "10.0.0.1",
		AttackType: "brute_force",
		CheckName:  "test",
		Severity:   3,
	}
	if err := db.RecordAttackEvent(ev, 0); err != nil {
		t.Fatalf("RecordAttackEvent: %v", err)
	}

	var count int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		if v := b.Get([]byte("attacks:events:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
		}
		return nil
	})
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}

func TestRecordAttackEventCounterIncrementsCorrectly(t *testing.T) {
	db := openTestDB(t)
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ev := AttackEvent{
			Timestamp:  base.Add(time.Duration(i) * time.Second),
			IP:         "10.0.0.1",
			AttackType: "scan",
			CheckName:  "test",
			Severity:   2,
		}
		if err := db.RecordAttackEvent(ev, i); err != nil {
			t.Fatalf("RecordAttackEvent[%d]: %v", i, err)
		}
	}

	var count int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		if v := b.Get([]byte("attacks:events:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
		}
		return nil
	})
	if count != 5 {
		t.Errorf("count = %d, want 5", count)
	}
}

// --- QueryAttackEvents: empty result set ---------------------------------

func TestQueryAttackEventsEmptyDB(t *testing.T) {
	db := openTestDB(t)
	results := db.QueryAttackEvents("10.0.0.1", 10)
	if len(results) != 0 {
		t.Errorf("empty DB should return 0 events, got %d", len(results))
	}
}

func TestQueryAttackEventsLimitExact(t *testing.T) {
	db := openTestDB(t)
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ev := AttackEvent{
			Timestamp:  base.Add(time.Duration(i) * time.Minute),
			IP:         "10.0.0.1",
			AttackType: "scan",
			CheckName:  "test",
			Severity:   2,
		}
		if err := db.RecordAttackEvent(ev, i); err != nil {
			t.Fatal(err)
		}
	}

	// Request exactly as many as exist.
	results := db.QueryAttackEvents("10.0.0.1", 5)
	if len(results) != 5 {
		t.Errorf("got %d, want 5", len(results))
	}
	// Still newest-first.
	if results[0].Timestamp.Before(results[4].Timestamp) {
		t.Error("should be newest-first")
	}
}

// --- SaveIPRecord / LoadIPRecord: update existing record -----------------

func TestSaveIPRecordUpdate(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	rec := IPRecord{IP: "10.0.0.1", ThreatScore: 50, FirstSeen: now, LastSeen: now, EventCount: 1}
	if err := db.SaveIPRecord(rec); err != nil {
		t.Fatal(err)
	}

	// Update with higher score.
	rec.ThreatScore = 90
	rec.EventCount = 10
	if err := db.SaveIPRecord(rec); err != nil {
		t.Fatal(err)
	}

	loaded, found := db.LoadIPRecord("10.0.0.1")
	if !found {
		t.Fatal("should be found after update")
	}
	if loaded.ThreatScore != 90 {
		t.Errorf("ThreatScore = %d, want 90 after update", loaded.ThreatScore)
	}
	if loaded.EventCount != 10 {
		t.Errorf("EventCount = %d, want 10", loaded.EventCount)
	}
}

// --- ReadAllAttackEvents: empty ------------------------------------------

func TestReadAllAttackEventsEmpty(t *testing.T) {
	db := openTestDB(t)
	events := db.ReadAllAttackEvents()
	if len(events) != 0 {
		t.Errorf("empty DB should yield 0 events, got %d", len(events))
	}
}

// --- AggregateByHour: findings at hour boundaries ------------------------

func TestAggregateByHourBoundaryFinding(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	exactHour := now.Truncate(time.Hour)

	writeFindings(t, db, []alert.Finding{
		{Timestamp: exactHour, Severity: alert.Critical, Check: "exact-hour", Message: "at boundary"},
	})

	buckets := db.AggregateByHour()
	if len(buckets) != 24 {
		t.Fatalf("expected 24 buckets, got %d", len(buckets))
	}

	var total int
	for _, b := range buckets {
		total += b.Total
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
}

func TestAggregateByHourFutureTimestampIgnored(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(2 * time.Hour), Severity: alert.Critical, Check: "future", Message: "ahead"},
		{Timestamp: now.Add(-30 * time.Minute), Severity: alert.High, Check: "recent"},
	})

	buckets := db.AggregateByHour()
	var total int
	for _, b := range buckets {
		total += b.Total
	}
	if total != 1 {
		t.Errorf("future finding should be ignored, got total %d", total)
	}
}

// --- AggregateByDay: findings at day boundaries --------------------------

func TestAggregateByDayBoundaryFinding(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)

	writeFindings(t, db, []alert.Finding{
		{Timestamp: today, Severity: alert.Warning, Check: "day-boundary", Message: "start of day"},
	})

	buckets := db.AggregateByDay()
	if len(buckets) != 30 {
		t.Fatalf("expected 30 buckets, got %d", len(buckets))
	}

	var total int
	for _, b := range buckets {
		total += b.Total
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
}

func TestAggregateByDaySeverityBreakdown(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now, Severity: alert.Critical, Check: "a"},
		{Timestamp: now, Severity: alert.High, Check: "b"},
		{Timestamp: now, Severity: alert.Warning, Check: "c"},
		{Timestamp: now, Severity: alert.Warning, Check: "d"},
	})

	buckets := db.AggregateByDay()
	var crit, high, warn, total int
	for _, b := range buckets {
		crit += b.Critical
		high += b.High
		warn += b.Warning
		total += b.Total
	}
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if crit != 1 {
		t.Errorf("critical = %d, want 1", crit)
	}
	if high != 1 {
		t.Errorf("high = %d, want 1", high)
	}
	if warn != 2 {
		t.Errorf("warning = %d, want 2", warn)
	}
}

// --- AggregateByDay: finding exactly 29 days ago -------------------------

func TestAggregateByDayExactly29DaysAgo(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.Local)
	cutoffDay := today.AddDate(0, 0, -29)

	writeFindings(t, db, []alert.Finding{
		{Timestamp: cutoffDay, Severity: alert.High, Check: "edge"},
	})

	buckets := db.AggregateByDay()
	var total int
	for _, b := range buckets {
		total += b.Total
	}
	if total != 1 {
		t.Errorf("finding at day 29 ago should be included, got total %d", total)
	}
}

// --- ReadHistorySince: empty DB ------------------------------------------

func TestReadHistorySinceEmpty(t *testing.T) {
	db := openTestDB(t)
	results := db.ReadHistorySince(time.Now().Add(-24 * time.Hour))
	if len(results) != 0 {
		t.Errorf("empty DB should return 0, got %d", len(results))
	}
}

// --- DeleteIPRecord: then LoadAllIPRecords is smaller --------------------

func TestDeleteIPRecordDecreasesLoadAll(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if err := db.SaveIPRecord(IPRecord{IP: ip, ThreatScore: 50, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}

	if err := db.DeleteIPRecord("10.0.0.2"); err != nil {
		t.Fatal(err)
	}

	all := db.LoadAllIPRecords()
	if len(all) != 2 {
		t.Errorf("expected 2 after delete, got %d", len(all))
	}
	if _, exists := all["10.0.0.2"]; exists {
		t.Error("10.0.0.2 should be gone")
	}
}

// --- RecordAttackEvent: prune with multiple IPs in secondary index ------

func TestRecordAttackEventPrunesCleansSecondaryIndex(t *testing.T) {
	old := maxAttackEvents
	maxAttackEvents = 3
	t.Cleanup(func() { maxAttackEvents = old })

	db := openTestDB(t)
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)

	// Insert 5 events across 2 IPs.
	ips := []string{"10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.1"}
	for i, ip := range ips {
		ev := AttackEvent{
			Timestamp:  base.Add(time.Duration(i) * time.Second),
			IP:         ip,
			AttackType: "test",
			CheckName:  "test",
			Severity:   2,
		}
		if err := db.RecordAttackEvent(ev, i); err != nil {
			t.Fatalf("RecordAttackEvent[%d]: %v", i, err)
		}
	}

	// After pruning, only 3 newest should remain.
	all := db.ReadAllAttackEvents()
	if len(all) != 3 {
		t.Errorf("expected 3 events after prune, got %d", len(all))
	}

	// The first 2 events (10.0.0.1, 10.0.0.1) should be pruned.
	// Secondary index for 10.0.0.1 should have at most the surviving event.
	events1 := db.QueryAttackEvents("10.0.0.1", 10)
	// Only the 5th event (index 4) for 10.0.0.1 should survive.
	if len(events1) > 1 {
		t.Errorf("10.0.0.1 should have at most 1 surviving event, got %d", len(events1))
	}
}

// --- LoadFirewallState: mixed entries with expired blocks ----------------

func TestLoadFirewallStateFiltersExpiredBlocks(t *testing.T) {
	db := openTestDB(t)
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	_ = db.BlockIP("10.0.0.1", "expired", past)
	_ = db.BlockIP("10.0.0.2", "active", future)
	_ = db.BlockIP("10.0.0.3", "permanent", time.Time{})

	state := db.LoadFirewallState()
	blockedIPs := make(map[string]bool)
	for _, b := range state.Blocked {
		blockedIPs[b.IP] = true
	}

	if blockedIPs["10.0.0.1"] {
		t.Error("expired block should be filtered")
	}
	if !blockedIPs["10.0.0.2"] {
		t.Error("active block should remain")
	}
	if !blockedIPs["10.0.0.3"] {
		t.Error("permanent block should remain")
	}
}

// --- GetBlockedIP: expired entry returns not found -----------------------

func TestGetBlockedIPExpiredReturnsNotFound(t *testing.T) {
	db := openTestDB(t)
	past := time.Now().Add(-1 * time.Hour)
	_ = db.BlockIP("10.0.0.1", "expired", past)

	_, found := db.GetBlockedIP("10.0.0.1")
	if found {
		t.Error("expired block should return not found")
	}
}

func TestGetBlockedIPPermanentReturnsFound(t *testing.T) {
	db := openTestDB(t)
	_ = db.BlockIP("10.0.0.1", "permanent", time.Time{})

	entry, found := db.GetBlockedIP("10.0.0.1")
	if !found {
		t.Fatal("permanent block should return found")
	}
	if entry.Reason != "permanent" {
		t.Errorf("Reason = %q, want permanent", entry.Reason)
	}
}

func TestGetBlockedIPMissing(t *testing.T) {
	db := openTestDB(t)
	_, found := db.GetBlockedIP("99.99.99.99")
	if found {
		t.Error("unknown IP should return not found")
	}
}

// --- AggregateByHour: severity=Info (unknown) not counted in named fields

func TestAggregateByHourUnknownSeverityStillCountsTotal(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	// Severity value that doesn't match Critical/High/Warning.
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-30 * time.Minute), Severity: alert.Severity(99), Check: "unknown-sev"},
	})

	buckets := db.AggregateByHour()
	var total, crit, high, warn int
	for _, b := range buckets {
		total += b.Total
		crit += b.Critical
		high += b.High
		warn += b.Warning
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if crit+high+warn != 0 {
		t.Errorf("unknown severity should not increment named fields: c=%d h=%d w=%d", crit, high, warn)
	}
}

// --- AggregateByDay: unknown severity ------------------------------------

func TestAggregateByDayUnknownSeverityStillCountsTotal(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now, Severity: alert.Severity(99), Check: "unknown-sev"},
	})

	buckets := db.AggregateByDay()
	var total, crit, high, warn int
	for _, b := range buckets {
		total += b.Total
		crit += b.Critical
		high += b.High
		warn += b.Warning
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if crit+high+warn != 0 {
		t.Error("unknown severity should not increment named fields")
	}
}
