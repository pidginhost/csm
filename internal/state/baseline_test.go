package state

import (
	"testing"
	"time"
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
