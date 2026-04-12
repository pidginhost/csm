package webui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	got := s.searchAuditEntries("anything", 10)
	if len(got) != 0 {
		t.Errorf("no log should return empty, got %d", len(got))
	}
}

// --- readUIAuditLog --------------------------------------------------

func TestReadUIAuditLogWithEntries(t *testing.T) {
	dir := t.TempDir()
	entries := []UIAuditEntry{
		{Timestamp: time.Now(), SourceIP: "10.0.0.1", Action: "block", Target: "203.0.113.5", Details: "test"},
		{Timestamp: time.Now(), SourceIP: "10.0.0.1", Action: "dismiss", Target: "webshell|test", Details: ""},
	}
	f, _ := os.Create(filepath.Join(dir, uiAuditFile))
	enc := json.NewEncoder(f)
	for _, e := range entries {
		_ = enc.Encode(e)
	}
	_ = f.Close()

	got := readUIAuditLog(dir, 10)
	if len(got) != 2 {
		t.Errorf("got %d entries, want 2", len(got))
	}
	// Should be newest first
	if got[0].Action != "dismiss" {
		t.Error("newest entry should be first")
	}
}

func TestReadUIAuditLogMissing(t *testing.T) {
	got := readUIAuditLog(t.TempDir(), 10)
	if got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

func TestReadUIAuditLogLimit(t *testing.T) {
	dir := t.TempDir()
	f, _ := os.Create(filepath.Join(dir, uiAuditFile))
	enc := json.NewEncoder(f)
	for i := 0; i < 10; i++ {
		_ = enc.Encode(UIAuditEntry{Action: "test"})
	}
	_ = f.Close()

	got := readUIAuditLog(dir, 3)
	if len(got) != 3 {
		t.Errorf("limit 3 should return 3, got %d", len(got))
	}
}

// --- searchAuditEntries with data ------------------------------------

func TestSearchAuditEntriesFindsMatch(t *testing.T) {
	dir := t.TempDir()
	s := newTestServer(t, "tok")
	s.cfg.StatePath = dir

	f, _ := os.Create(filepath.Join(dir, uiAuditFile))
	enc := json.NewEncoder(f)
	_ = enc.Encode(UIAuditEntry{Action: "block", Target: "203.0.113.5", Details: "brute-force"})
	_ = enc.Encode(UIAuditEntry{Action: "dismiss", Target: "webshell", Details: "false positive"})
	_ = f.Close()

	got := s.searchAuditEntries("brute", 10)
	if len(got) != 1 {
		t.Errorf("search 'brute' should find 1, got %d", len(got))
	}
}
