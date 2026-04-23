package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// retentionCfg returns a Config with the retention block configured
// to the supplied values; unrelated fields stay at defaults.
func retentionCfg(enabled bool, findingsDays, historyDays, reputationDays int) *config.Config {
	cfg := &config.Config{}
	cfg.Retention.Enabled = enabled
	cfg.Retention.FindingsDays = findingsDays
	cfg.Retention.HistoryDays = historyDays
	cfg.Retention.ReputationDays = reputationDays
	cfg.Retention.CompactMinSizeMB = 128
	cfg.Retention.CompactFillRatio = 0.5
	return cfg
}

func TestRunRetentionOnce_DisabledIsNoop(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Put one old history entry in to confirm it's NOT swept.
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := db.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "c", Message: "old", Timestamp: old},
	}); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	cfg := retentionCfg(false /* disabled */, 90, 30, 180)
	result := RunRetentionOnce(db, cfg, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if result.Deleted() != 0 {
		t.Errorf("Deleted = %d, want 0 when retention is disabled", result.Deleted())
	}
	if db.HistoryCount() != 1 {
		t.Errorf("HistoryCount = %d, want 1 (nothing should have been swept)", db.HistoryCount())
	}
}

func TestRunRetentionOnce_NilDBIsNoop(t *testing.T) {
	cfg := retentionCfg(true, 90, 30, 180)
	result := RunRetentionOnce(nil, cfg, time.Now())
	if result.Deleted() != 0 {
		t.Errorf("Deleted = %d, want 0 with nil db", result.Deleted())
	}
}

func TestRunRetentionOnce_NilConfigIsNoop(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	result := RunRetentionOnce(db, nil, time.Now())
	if result.Deleted() != 0 {
		t.Errorf("Deleted = %d, want 0 with nil config", result.Deleted())
	}
}

func TestRunRetentionOnce_SweepsEachBucket(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	// history: one old, one fresh
	if err := db.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "c", Message: "old", Timestamp: old},
		{Severity: alert.Warning, Check: "c", Message: "fresh", Timestamp: fresh},
	}); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}
	// attacks:events: two old, one fresh
	for i, ts := range []time.Time{old, old.Add(time.Hour), fresh} {
		if err := db.RecordAttackEvent(store.AttackEvent{
			IP: "1.2.3.4", Timestamp: ts, AttackType: "t",
		}, i); err != nil {
			t.Fatalf("RecordAttackEvent: %v", err)
		}
	}
	// reputation: one old, one fresh
	if err := db.SetReputation("a", store.ReputationEntry{Score: 1, CheckedAt: old}); err != nil {
		t.Fatalf("SetReputation a: %v", err)
	}
	if err := db.SetReputation("b", store.ReputationEntry{Score: 2, CheckedAt: fresh}); err != nil {
		t.Fatalf("SetReputation b: %v", err)
	}

	// Retention: 30d history -> old-only swept; 30d findings -> both old
	// attack events swept; 30d reputation -> old reputation swept.
	cfg := retentionCfg(true, 30, 30, 30)
	result := RunRetentionOnce(db, cfg, now)

	if result.History != 1 {
		t.Errorf("History = %d, want 1", result.History)
	}
	if result.AttackEvents != 2 {
		t.Errorf("AttackEvents = %d, want 2", result.AttackEvents)
	}
	if result.Reputation != 1 {
		t.Errorf("Reputation = %d, want 1", result.Reputation)
	}
	if result.Deleted() != 4 {
		t.Errorf("Deleted = %d, want 4 (1+2+1)", result.Deleted())
	}

	// Surviving counts.
	if db.HistoryCount() != 1 {
		t.Errorf("HistoryCount = %d, want 1", db.HistoryCount())
	}
	if len(db.QueryAttackEvents("1.2.3.4", 10)) != 1 {
		t.Errorf("attack events survived = %d, want 1", len(db.QueryAttackEvents("1.2.3.4", 10)))
	}
	if _, ok := db.GetReputation("a"); ok {
		t.Error("a should be swept")
	}
	if _, ok := db.GetReputation("b"); !ok {
		t.Error("b should be kept")
	}
}

func TestRunRetentionOnce_ZeroDaysSkipsThatBucket(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	if err := db.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "c", Message: "old", Timestamp: old},
	}); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	// HistoryDays=0 → history sweep is a no-op.
	cfg := retentionCfg(true, 0, 0, 0)
	result := RunRetentionOnce(db, cfg, now)
	if result.Deleted() != 0 {
		t.Errorf("Deleted = %d, want 0 when all *Days are zero", result.Deleted())
	}
	if db.HistoryCount() != 1 {
		t.Errorf("HistoryCount = %d, want 1", db.HistoryCount())
	}
}
