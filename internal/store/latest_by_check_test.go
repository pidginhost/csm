package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

func TestLatestByCheckMigratesFlatFilesAndSurvivesRetention(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	var lines []byte
	for _, f := range []alert.Finding{
		{Check: "webshell_realtime", Timestamp: now.Add(-time.Minute)},
		{Check: "webshell_realtime", Timestamp: now},
		{Check: "smtp_bruteforce", Timestamp: now.Add(-time.Hour)},
	} {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, append(b, '\n')...)
	}
	if err := os.WriteFile(filepath.Join(dir, "history.jsonl"), lines, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	for _, sweep := range []bool{false, true} {
		if sweep {
			if n, err := db.SweepHistoryOlderThan(now.Add(time.Second)); err != nil || n != 3 {
				t.Fatalf("sweep: deleted=%d err=%v", n, err)
			}
		}
		got := db.LatestByCheck()
		if len(got) != 2 || !got["webshell_realtime"].Equal(now) || !got["smtp_bruteforce"].Equal(now.Add(-time.Hour)) {
			t.Fatalf("after sweep=%v: got %v", sweep, got)
		}
	}
}

// The dashboard asks when each check last fired. The index answers that
// without walking the history bucket, and keeps the newest time even when
// an older finding is appended later.
func TestLatestByCheckKeepsTheNewestTimestamp(t *testing.T) {
	db := openTestDB(t)
	base := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	writeFindings(t, db, []alert.Finding{
		{Timestamp: base, Severity: alert.High, Check: "webshell_realtime"},
		{Timestamp: base.Add(2 * time.Minute), Severity: alert.High, Check: "webshell_realtime"},
		{Timestamp: base.Add(time.Minute), Severity: alert.Warning, Check: "smtp_bruteforce"},
	})
	// A delayed finding with an older timestamp must not move it back.
	writeFindings(t, db, []alert.Finding{
		{Timestamp: base.Add(-time.Hour), Severity: alert.High, Check: "webshell_realtime"},
	})

	got := db.LatestByCheck()
	if want := base.Add(2 * time.Minute); !got["webshell_realtime"].Equal(want) {
		t.Errorf("webshell_realtime = %s, want %s", got["webshell_realtime"], want)
	}
	if want := base.Add(time.Minute); !got["smtp_bruteforce"].Equal(want) {
		t.Errorf("smtp_bruteforce = %s, want %s", got["smtp_bruteforce"], want)
	}
	if len(got) != 2 {
		t.Errorf("index = %v, want two checks", got)
	}
}

// HistoryMark changes whenever history does, so callers can reuse results
// computed from it while it stays the same.
func TestHistoryMarkFollowsHistory(t *testing.T) {
	db := openTestDB(t)
	empty := db.HistoryMark()
	if db.HistoryMark() != empty {
		t.Fatal("mark changed without a write")
	}
	now := time.Now()
	writeFindings(t, db, []alert.Finding{{Timestamp: now, Severity: alert.High, Check: "a"}})
	added := db.HistoryMark()
	if added == empty {
		t.Fatal("mark unchanged after an append")
	}
	if _, err := db.SweepHistoryOlderThan(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if db.HistoryMark() == added {
		t.Fatal("mark unchanged after retention removed entries")
	}
}

func TestHistoryMarkDoesNotReuseDeletedKeys(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	writeFindings(t, db, []alert.Finding{{Timestamp: now, Check: "old"}})
	before := db.HistoryMark()
	if _, err := db.SweepHistoryOlderThan(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	writeFindings(t, db, []alert.Finding{{Timestamp: now, Check: "replacement"}})
	if got := db.HistoryMark(); got == before {
		t.Fatal("different findings with reused time keys kept the same history mark")
	}
}

func TestHistoryMarkTracksMiddleKeyMigration(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-24 * time.Hour), Check: "first"},
		{Timestamp: now, Check: "middle"},
		{Timestamp: now.Add(24 * time.Hour), Check: "last"},
	})
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		key := []byte(TimeKey(now, 1))
		value := append([]byte(nil), b.Get(key)...)
		if err := b.Delete(key); err != nil {
			return err
		}
		if err := b.Put([]byte(TimeKey(now.Add(time.Hour), 1)), value); err != nil {
			return err
		}
		return tx.Bucket([]byte("meta")).Delete([]byte(timeKeyUTCMarker))
	}); err != nil {
		t.Fatal(err)
	}
	before := db.HistoryMark()
	if err := db.migrateTimeKeysToUTC(); err != nil {
		t.Fatal(err)
	}
	if db.HistoryMark() == before {
		t.Fatal("middle-key migration did not change the history mark")
	}
}

// A host upgrading from a build without the index fills it from history once.
func TestBackfillLatestByCheckRunsOnce(t *testing.T) {
	db := openTestDB(t)
	base := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	writeFindings(t, db, []alert.Finding{
		{Timestamp: base, Severity: alert.High, Check: "a"},
		{Timestamp: base.Add(time.Minute), Severity: alert.High, Check: "a"},
		{Timestamp: base, Severity: alert.High, Check: "b"},
	})
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(bucketLatestByCheck)); err != nil {
			return err
		}
		if _, err := tx.CreateBucket([]byte(bucketLatestByCheck)); err != nil {
			return err
		}
		return tx.Bucket([]byte("meta")).Delete([]byte(metaLatestByCheckBackfilled))
	}); err != nil {
		t.Fatal(err)
	}
	if got := db.LatestByCheck(); len(got) != 0 {
		t.Fatalf("index after reset = %v, want empty", got)
	}

	if err := db.BackfillLatestByCheck(); err != nil {
		t.Fatal(err)
	}
	got := db.LatestByCheck()
	if !got["a"].Equal(base.Add(time.Minute)) || !got["b"].Equal(base) {
		t.Fatalf("index after backfill = %v", got)
	}

	// The sentinel stops a second pass from rewriting newer live values.
	writeFindings(t, db, []alert.Finding{{Timestamp: base.Add(time.Hour), Severity: alert.High, Check: "a"}})
	if err := db.BackfillLatestByCheck(); err != nil {
		t.Fatal(err)
	}
	if got := db.LatestByCheck(); !got["a"].Equal(base.Add(time.Hour)) {
		t.Fatalf("a = %s after a second backfill, want the live value", got["a"])
	}
}
