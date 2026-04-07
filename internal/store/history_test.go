package store

import (
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
