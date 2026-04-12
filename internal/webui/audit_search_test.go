package webui

import (
	"testing"
)

func TestSearchAuditEntriesEmpty(t *testing.T) {
	s := newTestServer(t, "tok")
	// Empty search returns nil.
	if got := s.searchAuditEntries("", 10); got != nil {
		t.Errorf("empty search should return nil, got %v", got)
	}
}

func TestSearchAuditEntriesZeroLimit(t *testing.T) {
	s := newTestServer(t, "tok")
	if got := s.searchAuditEntries("test", 0); got != nil {
		t.Errorf("zero limit should return nil, got %v", got)
	}
}

func TestSearchAuditEntriesNoLog(t *testing.T) {
	s := newTestServer(t, "tok")
	// No audit log file → empty results.
	got := s.searchAuditEntries("anything", 10)
	if len(got) != 0 {
		t.Errorf("no log should return empty, got %d", len(got))
	}
}
