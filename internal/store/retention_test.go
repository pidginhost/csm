package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

func TestSweepHistoryOlderThan_EmptyBucketIsNoop(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	n, err := db.SweepHistoryOlderThan(time.Now())
	if err != nil {
		t.Fatalf("SweepHistoryOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0 on empty bucket", n)
	}
}

func TestSweepHistoryOlderThan_DeletesOnlyOldEntries(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "c1", Message: "old-1", Timestamp: old},
		{Severity: alert.Warning, Check: "c1", Message: "old-2", Timestamp: old.Add(time.Hour)},
		{Severity: alert.Warning, Check: "c1", Message: "fresh-1", Timestamp: fresh},
	}
	if err := db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	n, err := db.SweepHistoryOlderThan(cutoff)
	if err != nil {
		t.Fatalf("SweepHistoryOlderThan: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	// history:count must reflect the delete.
	if got := db.HistoryCount(); got != 1 {
		t.Errorf("HistoryCount = %d, want 1", got)
	}

	// Surviving entry should be the fresh one.
	results, total := db.ReadHistory(10, 0)
	if total != 1 || len(results) != 1 {
		t.Fatalf("ReadHistory: total=%d len=%d want 1/1", total, len(results))
	}
	if results[0].Message != "fresh-1" {
		t.Errorf("survived message = %q, want fresh-1", results[0].Message)
	}
}

func TestSweepHistoryOlderThan_AllOlderWipesBucket(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	var findings []alert.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, alert.Finding{
			Severity: alert.Warning, Check: "c", Message: "m", Timestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}
	if err := db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	n, err := db.SweepHistoryOlderThan(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SweepHistoryOlderThan: %v", err)
	}
	if n != 10 {
		t.Errorf("deleted = %d, want 10", n)
	}
	if got := db.HistoryCount(); got != 0 {
		t.Errorf("HistoryCount = %d, want 0", got)
	}
}

func TestSweepHistoryOlderThan_CutoffInPastKeepsAll(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	if err := db.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "c", Message: "m", Timestamp: base},
	}); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	n, err := db.SweepHistoryOlderThan(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SweepHistoryOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0", n)
	}
	if got := db.HistoryCount(); got != 1 {
		t.Errorf("HistoryCount = %d, want 1", got)
	}
}

func TestSweepAttackEventsOlderThan_DeletesPrimaryAndSecondary(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Record two events at `old` and one at `fresh` for the same IP so
	// the secondary index has a 3-entry prefix to prune.
	for i, ts := range []time.Time{old, old.Add(time.Second), fresh} {
		if err := db.RecordAttackEvent(AttackEvent{
			IP:         "1.2.3.4",
			Timestamp:  ts,
			AttackType: "t",
		}, i); err != nil {
			t.Fatalf("RecordAttackEvent: %v", err)
		}
	}

	n, err := db.SweepAttackEventsOlderThan(cutoff)
	if err != nil {
		t.Fatalf("SweepAttackEventsOlderThan: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	// Primary + secondary index should both retain only the fresh entry.
	if got := db.QueryAttackEvents("1.2.3.4", 10); len(got) != 1 {
		t.Errorf("QueryAttackEvents = %d entries, want 1", len(got))
	}
}

func TestSweepReputationOlderThan_UsesCheckedAt(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := db.SetReputation("1.1.1.1", ReputationEntry{Score: 10, CheckedAt: old}); err != nil {
		t.Fatalf("SetReputation old: %v", err)
	}
	if err := db.SetReputation("2.2.2.2", ReputationEntry{Score: 20, CheckedAt: old.Add(time.Hour)}); err != nil {
		t.Fatalf("SetReputation old2: %v", err)
	}
	if err := db.SetReputation("3.3.3.3", ReputationEntry{Score: 30, CheckedAt: fresh}); err != nil {
		t.Fatalf("SetReputation fresh: %v", err)
	}

	n, err := db.SweepReputationOlderThan(cutoff)
	if err != nil {
		t.Fatalf("SweepReputationOlderThan: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	if _, ok := db.GetReputation("1.1.1.1"); ok {
		t.Error("1.1.1.1 should have been swept")
	}
	if _, ok := db.GetReputation("2.2.2.2"); ok {
		t.Error("2.2.2.2 should have been swept")
	}
	if _, ok := db.GetReputation("3.3.3.3"); !ok {
		t.Error("3.3.3.3 should have been kept")
	}
}

func TestSweepReputationOlderThan_SkipsMalformedEntries(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Valid fresh entry.
	if err := db.SetReputation("9.9.9.9", ReputationEntry{
		Score: 1, CheckedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SetReputation: %v", err)
	}

	// Inject a malformed row directly via bbolt.
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("reputation")).Put([]byte("bogus"), []byte("this is not json"))
	}); err != nil {
		t.Fatalf("direct put: %v", err)
	}

	// Sweep with future cutoff — should attempt to inspect all entries.
	// Malformed entry must not poison the sweep.
	n, err := db.SweepReputationOlderThan(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SweepReputationOlderThan: %v", err)
	}
	// Only the valid fresh entry deletes; malformed is skipped.
	if n != 1 {
		t.Errorf("deleted = %d, want 1 (malformed entry must be skipped)", n)
	}
}
