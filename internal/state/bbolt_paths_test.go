package state

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// setupBboltGlobal opens a bbolt store and sets it as the global.
func setupBboltGlobal(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(sdb)
	return func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	}
}

func TestAppendHistoryViaBbolt(t *testing.T) {
	cleanup := setupBboltGlobal(t)
	defer cleanup()

	s := openTestStore(t)
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "test", Message: "msg", Timestamp: time.Now()},
	}
	s.AppendHistory(findings)

	got := s.ReadHistorySince(time.Now().Add(-1 * time.Hour))
	if len(got) != 1 {
		t.Errorf("got %d findings, want 1", len(got))
	}
}

func TestAppendHistoryEmpty(t *testing.T) {
	s := openTestStore(t)
	s.AppendHistory(nil) // should not panic
}

func TestReadHistorySinceViaBbolt(t *testing.T) {
	cleanup := setupBboltGlobal(t)
	defer cleanup()

	s := openTestStore(t)
	// No findings → empty
	got := s.ReadHistorySince(time.Now().Add(-1 * time.Hour))
	if len(got) != 0 {
		t.Errorf("empty store should return 0, got %d", len(got))
	}
}

func TestReadHistorySinceNoBbolt(t *testing.T) {
	// Without bbolt, returns nil
	s := openTestStore(t)
	got := s.ReadHistorySince(time.Now().Add(-1 * time.Hour))
	if got != nil {
		t.Errorf("no bbolt should return nil, got %v", got)
	}
}

func TestSearchHistorySinceNoBboltUsesJSONLNewestFirst(t *testing.T) {
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(nil) })

	s := openTestStore(t)
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	s.appendHistoryFile([]alert.Finding{
		{Severity: alert.Warning, Check: "test", Message: "needle-before-cutoff", Timestamp: base},
		{Severity: alert.High, Check: "test", Message: "needle-oldest", Timestamp: base.Add(time.Minute)},
		{Severity: alert.High, Check: "test", Message: "ordinary", Timestamp: base.Add(2 * time.Minute)},
		{Severity: alert.Critical, Check: "test", Message: "needle-newest", Timestamp: base.Add(3 * time.Minute)},
	})

	got := s.SearchHistorySince(base.Add(30*time.Second), 1, func(f alert.Finding) bool {
		return strings.Contains(f.Message, "needle")
	})
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].Message != "needle-newest" {
		t.Errorf("got[0].Message = %q, want needle-newest", got[0].Message)
	}
}

func TestAggregateByHourViaBbolt(t *testing.T) {
	cleanup := setupBboltGlobal(t)
	defer cleanup()

	s := openTestStore(t)
	got := s.AggregateByHour()
	if got == nil {
		t.Error("with bbolt should return non-nil (even if empty)")
	}
}

func TestAggregateByHourNoBbolt(t *testing.T) {
	s := openTestStore(t)
	if got := s.AggregateByHour(); got != nil {
		t.Errorf("no bbolt should return nil, got %v", got)
	}
}

func TestAggregateByDayViaBbolt(t *testing.T) {
	cleanup := setupBboltGlobal(t)
	defer cleanup()

	s := openTestStore(t)
	got := s.AggregateByDay()
	if got == nil {
		t.Error("with bbolt should return non-nil")
	}
}

func TestAggregateByDayNoBbolt(t *testing.T) {
	s := openTestStore(t)
	if got := s.AggregateByDay(); got != nil {
		t.Errorf("no bbolt should return nil, got %v", got)
	}
}

func TestSaveSuppressionsViaBbolt(t *testing.T) {
	cleanup := setupBboltGlobal(t)
	defer cleanup()

	s := openTestStore(t)
	rules := []SuppressionRule{
		{ID: "r1", Check: "test_check", PathPattern: "*.php", Reason: "testing"},
	}
	if err := s.SaveSuppressions(rules); err != nil {
		t.Fatalf("SaveSuppressions: %v", err)
	}

	loaded := s.LoadSuppressions()
	if len(loaded) != 1 {
		t.Errorf("loaded %d rules, want 1", len(loaded))
	}
}
