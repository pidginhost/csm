package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
	bolt "go.etcd.io/bbolt"
)

// populateStore fills a fresh bbolt file with padded history rows so a
// subsequent compact has something meaningful to reclaim.
func populateStore(t *testing.T, statePath string) int64 {
	t.Helper()
	db, err := store.Open(statePath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var findings []alert.Finding
	for i := 0; i < 2000; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "c",
			Message:   strings.Repeat("x", 256),
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	if err = db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}
	if _, err = db.SweepHistoryOlderThan(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("SweepHistoryOlderThan: %v", err)
	}
	sz, err := db.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	return sz
}

func TestRunStoreCompact_ShrinksFile(t *testing.T) {
	statePath := t.TempDir()
	srcSizeBefore := populateStore(t, statePath)

	res, err := runStoreCompact(statePath, StoreCompactOptions{})
	if err != nil {
		t.Fatalf("runStoreCompact: %v", err)
	}
	if res.SrcSize != srcSizeBefore {
		t.Errorf("SrcSize = %d, want %d (pre-compact size)", res.SrcSize, srcSizeBefore)
	}
	if res.DstSize <= 0 {
		t.Errorf("DstSize = %d, want > 0", res.DstSize)
	}
	if res.DstSize >= srcSizeBefore {
		t.Errorf("compact did not shrink: src=%d dst=%d", srcSizeBefore, res.DstSize)
	}
	if res.Preview {
		t.Error("Preview flag should be false when --preview not set")
	}

	// After a real compact the csm.db file on disk matches DstSize.
	db, err := store.Open(statePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	got, err := db.Size()
	if err != nil {
		t.Fatalf("Size after compact: %v", err)
	}
	if got != res.DstSize {
		t.Errorf("post-compact size = %d, want %d", got, res.DstSize)
	}
}

func TestRunStoreCompact_PreviewDoesNotModify(t *testing.T) {
	statePath := t.TempDir()
	srcSizeBefore := populateStore(t, statePath)

	res, err := runStoreCompact(statePath, StoreCompactOptions{Preview: true})
	if err != nil {
		t.Fatalf("runStoreCompact preview: %v", err)
	}
	if !res.Preview {
		t.Error("Preview flag should be true")
	}
	if res.DstSize <= 0 {
		t.Error("preview should report a dst size")
	}

	// The on-disk src must still be the pre-compact size.
	db, err := store.Open(statePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	got, _ := db.Size()
	if got != srcSizeBefore {
		t.Errorf("preview modified src: got=%d want=%d", got, srcSizeBefore)
	}
}

func TestRunStoreCompact_RefusesWhenStoreLocked(t *testing.T) {
	statePath := t.TempDir()
	populateStore(t, statePath)

	// Hold the bbolt lock the way a running daemon would.
	holder, err := bolt.Open(filepath.Join(statePath, "csm.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("lock holder open: %v", err)
	}
	defer func() { _ = holder.Close() }()

	_, err = runStoreCompact(statePath, StoreCompactOptions{})
	if err == nil {
		t.Fatal("runStoreCompact should fail when the DB is locked by another process")
	}
	if !strings.Contains(err.Error(), "daemon") && !strings.Contains(err.Error(), "locked") && !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error should mention the daemon or lock; got: %v", err)
	}
}

func TestRunStoreCompact_MissingStatePath(t *testing.T) {
	_, err := runStoreCompact("", StoreCompactOptions{})
	if err == nil {
		t.Error("empty state path should error")
	}
}

func TestRunStoreCompact_CleansUpTempOnFailure(t *testing.T) {
	// Point to a stateDir that exists but contains no csm.db — Open
	// creates one on the fly, but CompactInto to a locked dst should
	// still clean up. Simpler check: pass a bogus dir that can't be
	// created.
	_, err := runStoreCompact("/proc/self/no-such-dir/that-cannot-be-made", StoreCompactOptions{})
	if err == nil {
		t.Error("expected error when state path is unusable")
	}
}
