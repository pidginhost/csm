package state

import (
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
