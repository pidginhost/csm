package state

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestEnsureBaselinePersistsFirstStart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	if got := s.BaselineAt(); !got.IsZero() {
		t.Fatalf("fresh store should have zero baseline, got %v", got)
	}

	first := time.Now().UTC().Truncate(time.Millisecond)
	s.EnsureBaseline(first)

	got := s.BaselineAt()
	if !got.Equal(first) {
		t.Fatalf("BaselineAt after first EnsureBaseline = %v, want %v", got, first)
	}

	// Second call must be a no-op so reinstalls / restarts do not reset.
	later := first.Add(2 * time.Hour)
	s.EnsureBaseline(later)
	if got := s.BaselineAt(); !got.Equal(first) {
		t.Fatalf("BaselineAt was overwritten by second EnsureBaseline: %v vs %v", got, first)
	}
}

func TestBaselineAtSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first := time.Now().UTC().Truncate(time.Millisecond)
	s.EnsureBaseline(first)
	_ = s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	got := s2.BaselineAt()
	if !got.Equal(first) {
		t.Fatalf("BaselineAt after reopen = %v, want %v", got, first)
	}
}

func TestBaselineAtSurvivesPruneAndBaselineReset(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	first := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)
	s.EnsureBaseline(first)

	s.mu.Lock()
	s.entries[baselineAtMetaKey].LastSeen = time.Now().Add(-48 * time.Hour)
	s.mu.Unlock()
	s.Update([]alert.Finding{{Check: "new", Message: "finding"}})
	if got := s.BaselineAt(); !got.Equal(first) {
		t.Fatalf("BaselineAt after prune = %v, want %v", got, first)
	}

	s.SetBaseline([]alert.Finding{{Check: "baseline", Message: "known"}})
	if got := s.BaselineAt(); !got.Equal(first) {
		t.Fatalf("BaselineAt after SetBaseline = %v, want %v", got, first)
	}
}

func TestBaselineAtHiddenFromEntries(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	s.EnsureBaseline(time.Now())
	if _, ok := s.Entries()[baselineAtMetaKey]; ok {
		t.Fatalf("%s should not appear in public entries", baselineAtMetaKey)
	}
}
