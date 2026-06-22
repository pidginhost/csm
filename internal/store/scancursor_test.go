package store

import (
	"testing"
	"time"
)

func TestScanCursorRoundTrip(t *testing.T) {
	db := openTestDB(t)

	wrapped := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	cycle := time.Date(2026, 1, 20, 12, 30, 0, 0, time.UTC)

	rec := ScanCursorRecord{
		Account:         "alice",
		Check:           "fileindex",
		LastPath:        "/home/alice/public_html/wp-content/plugins/foo.php",
		WrappedAt:       wrapped,
		LastFullCycleTS: cycle,
	}

	if err := db.PutScanCursor(rec); err != nil {
		t.Fatalf("PutScanCursor: %v", err)
	}

	got, ok, err := db.GetScanCursor("alice", "fileindex")
	if err != nil {
		t.Fatalf("GetScanCursor: %v", err)
	}
	if !ok {
		t.Fatal("GetScanCursor: expected ok=true, got false")
	}
	if got.Account != rec.Account {
		t.Errorf("Account: got %q, want %q", got.Account, rec.Account)
	}
	if got.Check != rec.Check {
		t.Errorf("Check: got %q, want %q", got.Check, rec.Check)
	}
	if got.LastPath != rec.LastPath {
		t.Errorf("LastPath: got %q, want %q", got.LastPath, rec.LastPath)
	}
	if !got.WrappedAt.Equal(rec.WrappedAt) {
		t.Errorf("WrappedAt: got %v, want %v", got.WrappedAt, rec.WrappedAt)
	}
	if !got.LastFullCycleTS.Equal(rec.LastFullCycleTS) {
		t.Errorf("LastFullCycleTS: got %v, want %v", got.LastFullCycleTS, rec.LastFullCycleTS)
	}
}

func TestScanCursorGetAbsent(t *testing.T) {
	db := openTestDB(t)

	_, ok, err := db.GetScanCursor("bob", "content")
	if err != nil {
		t.Fatalf("GetScanCursor on absent key: %v", err)
	}
	if ok {
		t.Fatal("GetScanCursor: expected ok=false for absent key, got true")
	}
}

func TestScanCursorIndependentKeys(t *testing.T) {
	db := openTestDB(t)

	records := []ScanCursorRecord{
		{Account: "alice", Check: "fileindex", LastPath: "/alice/fileindex"},
		{Account: "alice", Check: "content", LastPath: "/alice/content"},
		{Account: "bob", Check: "fileindex", LastPath: "/bob/fileindex"},
	}

	for _, r := range records {
		if err := db.PutScanCursor(r); err != nil {
			t.Fatalf("PutScanCursor(%s/%s): %v", r.Account, r.Check, err)
		}
	}

	for _, want := range records {
		got, ok, err := db.GetScanCursor(want.Account, want.Check)
		if err != nil {
			t.Fatalf("GetScanCursor(%s/%s): %v", want.Account, want.Check, err)
		}
		if !ok {
			t.Fatalf("GetScanCursor(%s/%s): expected ok=true", want.Account, want.Check)
		}
		if got.LastPath != want.LastPath {
			t.Errorf("(%s/%s) LastPath: got %q, want %q", want.Account, want.Check, got.LastPath, want.LastPath)
		}
	}
}

func TestScanCursorOverwrite(t *testing.T) {
	db := openTestDB(t)

	initial := ScanCursorRecord{
		Account:  "alice",
		Check:    "fileindex",
		LastPath: "/home/alice/old.php",
	}
	if err := db.PutScanCursor(initial); err != nil {
		t.Fatalf("PutScanCursor initial: %v", err)
	}

	updated := ScanCursorRecord{
		Account:  "alice",
		Check:    "fileindex",
		LastPath: "/home/alice/new.php",
	}
	if err := db.PutScanCursor(updated); err != nil {
		t.Fatalf("PutScanCursor update: %v", err)
	}

	got, ok, err := db.GetScanCursor("alice", "fileindex")
	if err != nil {
		t.Fatalf("GetScanCursor: %v", err)
	}
	if !ok {
		t.Fatal("GetScanCursor: expected ok=true after overwrite")
	}
	if got.LastPath != updated.LastPath {
		t.Errorf("LastPath after overwrite: got %q, want %q", got.LastPath, updated.LastPath)
	}
}
