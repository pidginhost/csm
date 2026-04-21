package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// readDaily fetches a stats:daily entry by YYYY-MM-DD key.
// Returns the bucket and ok=false if the key is absent.
func readDaily(t *testing.T, db *DB, dateKey string) (SeverityBucket, bool) {
	t.Helper()
	var sb SeverityBucket
	var ok bool
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketStatsDaily))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(dateKey))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &sb); err != nil {
			return err
		}
		ok = true
		return nil
	})
	if err != nil {
		t.Fatalf("readDaily: %v", err)
	}
	return sb, ok
}

// dailyKeys returns all date keys present in stats:daily (sorted ascending).
func dailyKeys(t *testing.T, db *DB) []string {
	t.Helper()
	var keys []string
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketStatsDaily))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			keys = append(keys, string(k))
		}
		return nil
	})
	return keys
}

// --- AppendHistory updates stats:daily ---------------------------------

func TestAppendHistoryIncrementsStatsDaily(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	writeFindings(t, db, []alert.Finding{
		{Timestamp: now, Severity: alert.Critical, Check: "a"},
		{Timestamp: now, Severity: alert.High, Check: "b"},
		{Timestamp: now, Severity: alert.Warning, Check: "c"},
		{Timestamp: now, Severity: alert.Warning, Check: "d"},
	})

	key := now.Format("2006-01-02")
	sb, ok := readDaily(t, db, key)
	if !ok {
		t.Fatalf("stats:daily missing entry for %s", key)
	}
	if sb.Critical != 1 || sb.High != 1 || sb.Warning != 2 || sb.Total != 4 {
		t.Errorf("daily counts = %+v, want {C:1 H:1 W:2 T:4}", sb)
	}
}

func TestAppendHistoryStatsDailyAccumulatesAcrossCalls(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	writeFindings(t, db, []alert.Finding{
		{Timestamp: now, Severity: alert.Critical, Check: "a"},
	})
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now, Severity: alert.Critical, Check: "b"},
		{Timestamp: now, Severity: alert.Warning, Check: "c"},
	})

	key := now.Format("2006-01-02")
	sb, ok := readDaily(t, db, key)
	if !ok {
		t.Fatalf("stats:daily missing entry for %s", key)
	}
	if sb.Critical != 2 || sb.Warning != 1 || sb.Total != 3 {
		t.Errorf("daily counts = %+v, want {C:2 W:1 T:3}", sb)
	}
}

func TestAppendHistoryStatsDailySplitsByDay(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)

	writeFindings(t, db, []alert.Finding{
		{Timestamp: yesterday, Severity: alert.Critical, Check: "y"},
		{Timestamp: now, Severity: alert.High, Check: "t"},
	})

	if sb, ok := readDaily(t, db, yesterday.Format("2006-01-02")); !ok || sb.Critical != 1 || sb.Total != 1 {
		t.Errorf("yesterday: ok=%v %+v", ok, sb)
	}
	if sb, ok := readDaily(t, db, now.Format("2006-01-02")); !ok || sb.High != 1 || sb.Total != 1 {
		t.Errorf("today: ok=%v %+v", ok, sb)
	}
}

// --- AggregateByDay reads from stats:daily, survives history pruning ---

func TestAggregateByDaySurvivesHistoryPruning(t *testing.T) {
	// This is the core regression test for the production bug:
	// when history pruning kicks in, old day buckets must still be
	// reflected in the trend chart because they live in stats:daily.
	orig := maxHistoryEntries
	maxHistoryEntries = 3
	defer func() { maxHistoryEntries = orig }()

	db := openTestDB(t)
	now := time.Now()

	// Five findings spanning five distinct days. With maxHistoryEntries=3,
	// the two oldest get pruned out of `history`, but stats:daily must
	// retain all five.
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-4 * 24 * time.Hour), Severity: alert.Critical, Check: "d-4"},
		{Timestamp: now.Add(-3 * 24 * time.Hour), Severity: alert.Critical, Check: "d-3"},
		{Timestamp: now.Add(-2 * 24 * time.Hour), Severity: alert.Critical, Check: "d-2"},
		{Timestamp: now.Add(-1 * 24 * time.Hour), Severity: alert.Critical, Check: "d-1"},
		{Timestamp: now, Severity: alert.Critical, Check: "d-0"},
	})

	if got := db.HistoryCount(); got != 3 {
		t.Errorf("history count after prune = %d, want 3", got)
	}

	buckets := db.AggregateByDay()
	var total int
	for _, b := range buckets {
		total += b.Total
	}
	if total != 5 {
		t.Errorf("AggregateByDay total = %d, want 5 (pruning of `history` must not affect daily aggregates)", total)
	}
}

func TestAggregateByDayBucketsMatchSeverity(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now, Severity: alert.Critical, Check: "a"},
		{Timestamp: now, Severity: alert.High, Check: "b"},
		{Timestamp: now, Severity: alert.Warning, Check: "c"},
		{Timestamp: now, Severity: alert.Warning, Check: "d"},
	})

	buckets := db.AggregateByDay()
	if len(buckets) != 30 {
		t.Fatalf("buckets len = %d, want 30", len(buckets))
	}

	var crit, high, warn, total int
	for _, b := range buckets {
		crit += b.Critical
		high += b.High
		warn += b.Warning
		total += b.Total
	}
	if crit != 1 || high != 1 || warn != 2 || total != 4 {
		t.Errorf("severity totals = {C:%d H:%d W:%d T:%d}, want {C:1 H:1 W:2 T:4}",
			crit, high, warn, total)
	}
}

// --- stats:daily retention ---------------------------------------------

func TestStatsDailyRetentionPrunesOldEntries(t *testing.T) {
	origHist := maxHistoryEntries
	origRet := dailyRetentionDays
	maxHistoryEntries = 100_000
	dailyRetentionDays = 60
	defer func() {
		maxHistoryEntries = origHist
		dailyRetentionDays = origRet
	}()

	db := openTestDB(t)
	now := time.Now()

	// Seed an ancient (200 days ago) entry directly in stats:daily, then
	// trigger AppendHistory. The retention sweep that runs alongside the
	// insert must drop the ancient row.
	ancientKey := now.Add(-200 * 24 * time.Hour).Format("2006-01-02")
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		val, _ := json.Marshal(SeverityBucket{Critical: 1, Total: 1})
		return tx.Bucket([]byte(bucketStatsDaily)).Put([]byte(ancientKey), val)
	}); err != nil {
		t.Fatalf("seed ancient: %v", err)
	}
	if _, ok := readDaily(t, db, ancientKey); !ok {
		t.Fatalf("ancient daily entry missing before sweep")
	}

	writeFindings(t, db, []alert.Finding{
		{Timestamp: now, Severity: alert.Warning, Check: "recent"},
	})

	if _, ok := readDaily(t, db, ancientKey); ok {
		t.Errorf("ancient daily entry should have been pruned (retention=%d days)", dailyRetentionDays)
	}
	if _, ok := readDaily(t, db, now.Format("2006-01-02")); !ok {
		t.Errorf("recent daily entry must survive retention sweep")
	}
}

func TestStatsDailyRetentionKeepsBoundaryDay(t *testing.T) {
	origHist := maxHistoryEntries
	origRet := dailyRetentionDays
	maxHistoryEntries = 100_000
	dailyRetentionDays = 30
	defer func() {
		maxHistoryEntries = origHist
		dailyRetentionDays = origRet
	}()

	db := openTestDB(t)
	now := time.Now()
	// Day exactly at the retention boundary must be retained.
	boundary := now.Add(-29 * 24 * time.Hour)

	writeFindings(t, db, []alert.Finding{
		{Timestamp: boundary, Severity: alert.High, Check: "edge"},
	})
	// Trigger sweep with a fresh finding.
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now, Severity: alert.Warning, Check: "trigger"},
	})

	if _, ok := readDaily(t, db, boundary.Format("2006-01-02")); !ok {
		t.Errorf("day at retention boundary (-29d, retention=30) must be retained")
	}
}

// --- Backfill from existing history bucket -----------------------------

func TestBackfillStatsDailyFromExistingHistoryRunsOnce(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	// Seed the history bucket directly (simulating an upgrade where
	// history exists but stats:daily is empty). We use AppendHistory
	// then wipe stats:daily and the sentinel to mimic a pre-feature DB.
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-3 * 24 * time.Hour), Severity: alert.Critical, Check: "a"},
		{Timestamp: now.Add(-2 * 24 * time.Hour), Severity: alert.High, Check: "b"},
		{Timestamp: now.Add(-1 * 24 * time.Hour), Severity: alert.Warning, Check: "c"},
		{Timestamp: now, Severity: alert.Warning, Check: "d"},
	})

	// Reset stats:daily and the sentinel to simulate pre-feature state.
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(bucketStatsDaily)); err != nil {
			return err
		}
		if _, err := tx.CreateBucket([]byte(bucketStatsDaily)); err != nil {
			return err
		}
		return tx.Bucket([]byte("meta")).Delete([]byte(metaStatsDailyBackfilled))
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	if got := dailyKeys(t, db); len(got) != 0 {
		t.Fatalf("stats:daily should be empty after reset, got %d keys", len(got))
	}

	// Backfill.
	if err := db.BackfillStatsDaily(); err != nil {
		t.Fatalf("BackfillStatsDaily: %v", err)
	}

	keys := dailyKeys(t, db)
	if len(keys) != 4 {
		t.Errorf("after backfill, stats:daily keys = %d, want 4", len(keys))
	}

	// Each day should have a single finding.
	for _, k := range keys {
		sb, ok := readDaily(t, db, k)
		if !ok {
			t.Fatalf("missing %s", k)
		}
		if sb.Total != 1 {
			t.Errorf("day %s total = %d, want 1", k, sb.Total)
		}
	}

	// Backfill must not double-count if invoked again (sentinel guard).
	if err := db.BackfillStatsDaily(); err != nil {
		t.Fatalf("BackfillStatsDaily second call: %v", err)
	}
	for _, k := range keys {
		sb, _ := readDaily(t, db, k)
		if sb.Total != 1 {
			t.Errorf("after re-running backfill, day %s total = %d, want 1 (must be idempotent)", k, sb.Total)
		}
	}
}

func TestBackfillStatsDailyEmptyHistoryIsNoOp(t *testing.T) {
	db := openTestDB(t)
	if err := db.BackfillStatsDaily(); err != nil {
		t.Fatalf("BackfillStatsDaily on empty DB: %v", err)
	}
	if got := dailyKeys(t, db); len(got) != 0 {
		t.Errorf("expected no daily keys after backfilling empty history, got %d", len(got))
	}
}
