package store

import (
	"bytes"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestOperatorPref_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	const opkey = "op-alpha"

	if blob, err := db.GetOperatorPref(opkey, "user"); err != nil || blob != nil {
		t.Fatalf("expected empty pref to read nil, got blob=%q err=%v", blob, err)
	}

	want := []byte(`{"density":"compact"}`)
	if err := db.PutOperatorPref(opkey, "user", want); err != nil {
		t.Fatalf("PutOperatorPref: %v", err)
	}
	got, err := db.GetOperatorPref(opkey, "user")
	if err != nil {
		t.Fatalf("GetOperatorPref: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("blob round-trip mismatch: got %q want %q", got, want)
	}

	// Different operator does not see another operator's pref.
	other, err := db.GetOperatorPref("op-beta", "user")
	if err != nil || other != nil {
		t.Fatalf("cross-operator leak: blob=%q err=%v", other, err)
	}

	if err := db.DeleteOperatorPref(opkey, "user"); err != nil {
		t.Fatalf("DeleteOperatorPref: %v", err)
	}
	if blob, err := db.GetOperatorPref(opkey, "user"); err != nil || blob != nil {
		t.Fatalf("after delete expected nil, got blob=%q err=%v", blob, err)
	}
}

func TestOperatorPref_BlobTooLarge(t *testing.T) {
	db := openTestDB(t)
	huge := make([]byte, MaxPrefBlobSize+1)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := db.PutOperatorPref("op", "user", huge); err != ErrPrefBlobTooLarge {
		t.Fatalf("expected ErrPrefBlobTooLarge, got %v", err)
	}
}

func TestOperatorPref_RejectsEmptyKey(t *testing.T) {
	db := openTestDB(t)
	if err := db.PutOperatorPref("", "user", []byte("{}")); err == nil {
		t.Fatalf("empty opkey accepted")
	}
	if err := db.PutOperatorPref("op", "", []byte("{}")); err == nil {
		t.Fatalf("empty namespace accepted")
	}
}

func TestUndoQueue_AppendLatestConsume(t *testing.T) {
	db := openTestDB(t)
	const opkey = "op"

	if _, ok, err := db.LatestUndoEntry(opkey); err != nil || ok {
		t.Fatalf("expected no entry on empty queue, ok=%v err=%v", ok, err)
	}

	first, err := db.AppendUndoEntry(opkey, UndoEntry{
		Action:  "threat_bulk_block",
		Inverse: "threat_bulk_unblock",
		Payload: []byte(`{"ips":["192.0.2.1"]}`),
		Summary: "Blocked 1 IP",
	})
	if err != nil {
		t.Fatalf("AppendUndoEntry: %v", err)
	}
	if first.ID == "" || first.RecordedAt.IsZero() {
		t.Fatalf("entry missing id/timestamp: %+v", first)
	}

	// Force a different big-endian nano on the second entry.
	time.Sleep(time.Millisecond)
	second, err := db.AppendUndoEntry(opkey, UndoEntry{
		Action:  "threat_bulk_whitelist",
		Inverse: "threat_bulk_unwhitelist",
		Payload: []byte(`{"ips":["192.0.2.2"]}`),
		Summary: "Whitelisted 1 IP",
	})
	if err != nil {
		t.Fatalf("AppendUndoEntry second: %v", err)
	}

	got, ok, err := db.LatestUndoEntry(opkey)
	if err != nil {
		t.Fatalf("LatestUndoEntry: %v", err)
	}
	if !ok {
		t.Fatalf("expected latest entry, got none")
	}
	if got.ID != second.ID {
		t.Fatalf("latest entry id=%s want=%s", got.ID, second.ID)
	}
	if got.Action != "threat_bulk_whitelist" {
		t.Fatalf("latest entry action=%s", got.Action)
	}

	consumed, ok, err := db.ConsumeUndoEntry(opkey, second.ID)
	if err != nil || !ok {
		t.Fatalf("ConsumeUndoEntry: ok=%v err=%v", ok, err)
	}
	if consumed.ID != second.ID {
		t.Fatalf("consumed wrong id: %s vs %s", consumed.ID, second.ID)
	}

	// After consume, latest is now the first entry.
	got, ok, err = db.LatestUndoEntry(opkey)
	if err != nil || !ok {
		t.Fatalf("LatestUndoEntry after consume: ok=%v err=%v", ok, err)
	}
	if got.ID != first.ID {
		t.Fatalf("latest after consume=%s want=%s", got.ID, first.ID)
	}

	// Consume the second time returns not found.
	if _, ok, err := db.ConsumeUndoEntry(opkey, second.ID); err != nil || ok {
		t.Fatalf("expected second consume to miss, ok=%v err=%v", ok, err)
	}
}

func TestUndoQueue_TTLExpiry(t *testing.T) {
	db := openTestDB(t)
	const opkey = "op"

	entry, err := db.AppendUndoEntry(opkey, UndoEntry{
		Action:  "x",
		Inverse: "y",
	})
	if err != nil {
		t.Fatalf("AppendUndoEntry: %v", err)
	}

	// Rewrite the entry with a backdated RecordedAt to simulate expiry.
	if err := RewriteUndoEntryRecordedAt(db, entry.ID, time.Now().Add(-2*UndoTTL)); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if _, ok, err := db.LatestUndoEntry(opkey); err != nil || ok {
		t.Fatalf("expected expired entry to be skipped, ok=%v err=%v", ok, err)
	}
	if _, ok, err := db.ConsumeUndoEntry(opkey, entry.ID); err != nil || ok {
		t.Fatalf("expected expired consume to miss, ok=%v err=%v", ok, err)
	}
}

func TestUndoQueue_TrimsToMaxEntries(t *testing.T) {
	db := openTestDB(t)
	const opkey = "op"

	for i := 0; i < MaxUndoEntries+5; i++ {
		time.Sleep(time.Microsecond) // ensure different unix nano
		if _, err := db.AppendUndoEntry(opkey, UndoEntry{
			Action:  "x",
			Inverse: "y",
		}); err != nil {
			t.Fatalf("AppendUndoEntry %d: %v", i, err)
		}
	}

	// Count entries directly.
	count := 0
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(prefsBucket))
		prefix := undoKeyPrefix(opkey)
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
			count++
		}
		return nil
	})
	if count != MaxUndoEntries {
		t.Fatalf("queue length=%d want=%d", count, MaxUndoEntries)
	}
}

func TestUndoQueue_PurgeRemovesAll(t *testing.T) {
	db := openTestDB(t)
	const opkey = "op"

	for i := 0; i < 3; i++ {
		time.Sleep(time.Microsecond)
		if _, err := db.AppendUndoEntry(opkey, UndoEntry{Action: "x", Inverse: "y"}); err != nil {
			t.Fatalf("AppendUndoEntry: %v", err)
		}
	}
	if err := db.PurgeOperatorUndo(opkey); err != nil {
		t.Fatalf("PurgeOperatorUndo: %v", err)
	}
	if _, ok, err := db.LatestUndoEntry(opkey); err != nil || ok {
		t.Fatalf("expected empty after purge, ok=%v err=%v", ok, err)
	}
}

func TestUndoQueue_RejectsMissingInverse(t *testing.T) {
	db := openTestDB(t)
	_, err := db.AppendUndoEntry("op", UndoEntry{Action: "x"})
	if err == nil || !strings.Contains(err.Error(), "inverse") {
		t.Fatalf("expected inverse-required error, got %v", err)
	}
}

func bytesHasPrefix(s, prefix []byte) bool { return bytes.HasPrefix(s, prefix) }
