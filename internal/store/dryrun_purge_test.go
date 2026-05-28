package store

import (
	"encoding/json"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// X21: RecordDryRunBlock used fmt.Sprintf %q which emits \v / \xHH
// escapes that JSON cannot parse. A reason containing a control char
// (audit forwarding from a noisy log source occasionally carries them)
// wrote an unparseable record; the bucket then failed to unmarshal at
// read time and the dry-run review pane went dark. Marshalling via
// encoding/json applies the proper \u00XX escapes so every stored row
// round-trips.
func TestRecordDryRunBlockEncodesControlChars(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reasons := []string{
		"vertical\vtab",
		"bell\x07control",
		"newline\nin reason",
		"null\x00byte",
		"normal reason",
	}
	for i, reason := range reasons {
		db.RecordDryRunBlock("198.51.100."+itoaSimple(i), reason, time.Hour)
	}

	parsed := 0
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("dry_run_blocks"))
		if b == nil {
			t.Fatal("dry_run_blocks bucket missing")
		}
		return b.ForEach(func(_, v []byte) error {
			var entry map[string]any
			if err := json.Unmarshal(v, &entry); err != nil {
				t.Errorf("row failed to unmarshal: %v -- raw=%q", err, string(v))
				return nil
			}
			parsed++
			return nil
		})
	})
	if parsed != len(reasons) {
		t.Errorf("parsed %d rows, want %d", parsed, len(reasons))
	}
}

func itoaSimple(i int) string {
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}

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
	freshKey := now.Format(time.RFC3339Nano) + ":2001:db8::10"
	staleKey := now.Add(-30*24*time.Hour).Format(time.RFC3339Nano) + ":2001:db8::11"
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
