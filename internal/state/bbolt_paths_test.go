package state

import (
	"os"
	"path/filepath"
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

// History lives only in the state DB. A history.jsonl left in the state
// directory is never written or served; opening the DB imports it once.
func TestHistoryWithoutStateDBUsesNoFile(t *testing.T) {
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(nil) })

	s := openTestStore(t)
	leftover := filepath.Join(s.path, "history.jsonl")
	old := []byte(`{"check":"leftover","message":"m","timestamp":"2026-04-01T10:00:00Z"}` + "\n")
	if err := os.WriteFile(leftover, old, 0600); err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.AppendHistory([]alert.Finding{{Check: "new", Message: "m", Timestamp: since.AddDate(0, 4, 0)}})

	if data, err := os.ReadFile(leftover); err != nil || string(data) != string(old) {
		t.Errorf("history.jsonl changed: %q, %v", data, err)
	}
	if got, total := s.ReadHistory(10, 0); len(got) != 0 || total != 0 {
		t.Errorf("ReadHistory = %+v, total %d; want none", got, total)
	}
	if got, total := s.ReadHistoryFiltered(10, 0, "", "", -1, ""); len(got) != 0 || total != 0 {
		t.Errorf("ReadHistoryFiltered = %+v, total %d; want none", got, total)
	}
	if got := s.ReadHistorySince(since); len(got) != 0 {
		t.Errorf("ReadHistorySince = %+v; want none", got)
	}
	if got := s.SearchHistorySince(since, 10, nil); len(got) != 0 {
		t.Errorf("SearchHistorySince = %+v; want none", got)
	}
	if got := s.LatestByCheck(); len(got) != 0 {
		t.Errorf("LatestByCheck = %+v; want none", got)
	}
	if got := s.HistoryMark(); got != "" {
		t.Errorf("HistoryMark = %q; want empty", got)
	}
}

func TestSearchHistorySinceViaBboltNewestFirst(t *testing.T) {
	t.Cleanup(setupBboltGlobal(t))

	s := openTestStore(t)
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	s.AppendHistory([]alert.Finding{
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
