package store

import (
	"testing"
)

// The happy path is in TestAddRemovePermanent. These tests cover the
// remaining branches that kept AddPermanentBlock and RemovePermanentBlock
// below 80% coverage.

func TestAddPermanentBlockUpdateExistingDoesNotIncrementCount(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.AddPermanentBlock("198.51.100.1", "initial reason"); err != nil {
		t.Fatal(err)
	}
	if got := db.getCounter("threats:count"); got != 1 {
		t.Fatalf("count after first add = %d, want 1", got)
	}

	// Second call for the SAME IP: isNew=false, count must stay at 1.
	// (The reason is intentionally updated — new context replaces old.)
	if err := db.AddPermanentBlock("198.51.100.1", "updated reason"); err != nil {
		t.Fatal(err)
	}
	if got := db.getCounter("threats:count"); got != 1 {
		t.Errorf("count after duplicate add = %d, want 1", got)
	}

	entry, found := db.GetPermanentBlock("198.51.100.1")
	if !found {
		t.Fatal("entry missing after update")
	}
	if entry.Reason != "updated reason" {
		t.Errorf("reason not updated: got %q", entry.Reason)
	}
}

func TestRemovePermanentBlockNotFoundIsNoop(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Add one IP so the counter has a stable value.
	if err := db.AddPermanentBlock("198.51.100.5", "reason"); err != nil {
		t.Fatal(err)
	}

	// Remove an IP that was never added. Should be a no-op — no error,
	// and the counter must NOT be decremented (that would corrupt the
	// stored total).
	if err := db.RemovePermanentBlock("203.0.113.99"); err != nil {
		t.Errorf("RemovePermanentBlock on absent IP should not error, got %v", err)
	}
	if got := db.getCounter("threats:count"); got != 1 {
		t.Errorf("count after no-op remove = %d, want 1 (must not decrement)", got)
	}
}

func TestRemovePermanentBlockTwiceDecrementsOnce(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.AddPermanentBlock("198.51.100.9", "reason"); err != nil {
		t.Fatal(err)
	}
	if err := db.RemovePermanentBlock("198.51.100.9"); err != nil {
		t.Fatal(err)
	}
	if got := db.getCounter("threats:count"); got != 0 {
		t.Fatalf("count after first remove = %d, want 0", got)
	}

	// Second remove: the entry is already gone; the function must
	// detect this and not re-decrement into negative territory.
	if err := db.RemovePermanentBlock("198.51.100.9"); err != nil {
		t.Errorf("second remove should not error, got %v", err)
	}
	if got := db.getCounter("threats:count"); got != 0 {
		t.Errorf("count after double remove = %d, want 0 (must not go negative)", got)
	}
}
