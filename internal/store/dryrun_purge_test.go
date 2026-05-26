package store

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestPurgeAllDryRunBlocks asserts that the operator-flip-to-live
// reset wipes every dry-run record so /api/v1/status no longer
// reports a stale count from the previous dry-run window.
func TestPurgeAllDryRunBlocks(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		db.RecordDryRunBlock(ip, "test", time.Hour)
	}
	if got := db.DryRunBlocksCount(); got != 3 {
		t.Fatalf("seed count = %d, want 3", got)
	}

	purged := db.PurgeAllDryRunBlocks()
	if purged != 3 {
		t.Errorf("PurgeAllDryRunBlocks returned %d, want 3", purged)
	}
	if got := db.DryRunBlocksCount(); got != 0 {
		t.Errorf("count after purge = %d, want 0", got)
	}
}

// TestPurgeDryRunBlocksOlderThan keeps entries from the recent
// window so operators can still review fresh would-have-been-blocks
// after a long enough dry-run trial, while removing month-old noise.
func TestPurgeDryRunBlocksOlderThan(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Inject one fresh + one stale entry directly through the same
	// bucket so we can control the timestamp prefix without waiting.
	now := time.Now().UTC()
	freshKey := now.Format(time.RFC3339Nano) + ":198.51.100.10"
	staleKey := now.Add(-30*24*time.Hour).Format(time.RFC3339Nano) + ":198.51.100.11"
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("dry_run_blocks"))
		if err != nil {
			return err
		}
		if err := b.Put([]byte(freshKey), []byte(`{}`)); err != nil {
			return err
		}
		return b.Put([]byte(staleKey), []byte(`{}`))
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	purged := db.PurgeDryRunBlocksOlderThan(now.Add(-7 * 24 * time.Hour))
	if purged != 1 {
		t.Errorf("PurgeDryRunBlocksOlderThan removed %d, want 1", purged)
	}
	if got := db.DryRunBlocksCount(); got != 1 {
		t.Errorf("count after age-purge = %d, want 1", got)
	}
}
