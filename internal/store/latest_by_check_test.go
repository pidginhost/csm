package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

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
