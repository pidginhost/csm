package store

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAppendAndReadHistory(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	var findings []alert.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "test-check",
			Message:   "finding message",
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}

	if err := db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	results, total := db.ReadHistory(10, 0)
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(results) != 5 {
		t.Fatalf("len(results) = %d, want 5", len(results))
	}

	// Verify newest-first order.
	for i := 0; i < len(results)-1; i++ {
		if !results[i].Timestamp.After(results[i+1].Timestamp) {
			t.Errorf("results[%d].Timestamp (%v) should be after results[%d].Timestamp (%v)",
				i, results[i].Timestamp, i+1, results[i+1].Timestamp)
		}
	}
}

func TestReadHistoryPagination(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	var findings []alert.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.High,
			Check:     "paginate-check",
			Message:   "paginate message",
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}

	if err := db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	// Page 1: limit=3, offset=0
	page1, total := db.ReadHistory(3, 0)
	if total != 10 {
		t.Errorf("total = %d, want 10", total)
	}
	if len(page1) != 3 {
		t.Fatalf("page1 len = %d, want 3", len(page1))
	}

	// Page 2: limit=3, offset=3
	page2, _ := db.ReadHistory(3, 3)
	if len(page2) != 3 {
		t.Fatalf("page2 len = %d, want 3", len(page2))
	}

	// Pages should not overlap.
	for _, p1 := range page1 {
		for _, p2 := range page2 {
			if p1.Timestamp.Equal(p2.Timestamp) {
				t.Errorf("page1 and page2 overlap at timestamp %v", p1.Timestamp)
			}
		}
	}

	// Last page: offset=9 should return 1 item.
	last, _ := db.ReadHistory(3, 9)
	if len(last) != 1 {
		t.Errorf("last page len = %d, want 1", len(last))
	}
}

func TestSearchHistorySinceLimitsNewestMatches(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "test", Message: "needle-before-cutoff", Timestamp: base},
		{Severity: alert.High, Check: "test", Message: "needle-oldest", Timestamp: base.Add(time.Minute)},
		{Severity: alert.High, Check: "test", Message: "ordinary", Timestamp: base.Add(2 * time.Minute)},
		{Severity: alert.High, Check: "test", Message: "needle-newer", Timestamp: base.Add(3 * time.Minute)},
		{Severity: alert.Critical, Check: "test", Message: "needle-newest", Timestamp: base.Add(4 * time.Minute)},
	}
	if err := db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	got := db.SearchHistorySince(base.Add(30*time.Second), 2, func(f alert.Finding) bool {
		return strings.Contains(f.Message, "needle")
	})
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].Message != "needle-newest" {
		t.Errorf("got[0].Message = %q, want needle-newest", got[0].Message)
	}
	if got[1].Message != "needle-newer" {
		t.Errorf("got[1].Message = %q, want needle-newer", got[1].Message)
	}
}

func TestHistoryCountEmpty(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if got := db.HistoryCount(); got != 0 {
		t.Errorf("HistoryCount() = %d, want 0 on fresh DB", got)
	}
}

func TestHistoryCountAfterAppend(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "test", Message: "msg1", Timestamp: time.Now()},
		{Severity: alert.High, Check: "test", Message: "msg2", Timestamp: time.Now()},
		{Severity: alert.Critical, Check: "test", Message: "msg3", Timestamp: time.Now()},
	}
	if err := db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	if got := db.HistoryCount(); got != 3 {
		t.Errorf("HistoryCount() = %d, want 3 after appending 3 findings", got)
	}
}

func TestAppendHistoryKeepsDuplicateTimestampAcrossCalls(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ts := time.Date(2026, 6, 8, 15, 30, 0, 123, time.UTC)
	first := alert.Finding{Severity: alert.High, Check: "shutdown-a", Message: "first", Timestamp: ts}
	second := alert.Finding{Severity: alert.High, Check: "shutdown-b", Message: "second", Timestamp: ts}

	if err := db.AppendHistory([]alert.Finding{first}); err != nil {
		t.Fatalf("AppendHistory(first): %v", err)
	}
	if err := db.AppendHistory([]alert.Finding{second}); err != nil {
		t.Fatalf("AppendHistory(second): %v", err)
	}

	results, total := db.ReadHistory(10, 0)
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}

	seen := map[string]bool{}
	for _, f := range results {
		seen[f.Check] = true
	}
	if !seen[first.Check] || !seen[second.Check] {
		t.Fatalf("history lost duplicate-timestamp findings, seen=%v", seen)
	}
}

func TestHistoryPruning(t *testing.T) {
	// Override maxHistoryEntries for this test.
	orig := maxHistoryEntries
	maxHistoryEntries = 10
	defer func() { maxHistoryEntries = orig }()

	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	var findings []alert.Finding
	for i := 0; i < 15; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "prune-check",
			Message:   "prune message",
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}

	if err := db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	results, total := db.ReadHistory(100, 0)
	if total != 10 {
		t.Errorf("total = %d, want 10 (pruned)", total)
	}
	if len(results) != 10 {
		t.Errorf("len(results) = %d, want 10", len(results))
	}

	// The 10 remaining should be the newest (indices 5..14 from original).
	// The newest result (index 0) should have timestamp base + 14 minutes.
	expectedNewest := base.Add(14 * time.Minute)
	if !results[0].Timestamp.Equal(expectedNewest) {
		t.Errorf("newest result timestamp = %v, want %v", results[0].Timestamp, expectedNewest)
	}

	// The oldest remaining (index 9) should have timestamp base + 5 minutes.
	expectedOldest := base.Add(5 * time.Minute)
	if !results[9].Timestamp.Equal(expectedOldest) {
		t.Errorf("oldest remaining timestamp = %v, want %v", results[9].Timestamp, expectedOldest)
	}
}
