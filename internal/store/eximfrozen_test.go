package store

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestOpenCreatesEximFrozenSeenBucket(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if !db.HasBucket(eximFrozenSeenBucket) {
		t.Fatalf("missing bucket %q", eximFrozenSeenBucket)
	}
}

func TestEximFrozenSeenRoundTrip(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Date(2026, 9, 30, 12, 0, 0, 123456789, time.UTC)
	data := map[string]time.Time{
		"1aaaaa-000000AAAAA-0aa": now.Add(-time.Hour),
		"1bbbbb-000000BBBBB-0bb": now,
	}
	if saveErr := db.SaveEximFrozenSeen(data); saveErr != nil {
		t.Fatalf("SaveEximFrozenSeen: %v", saveErr)
	}

	got, err := db.LoadEximFrozenSeen()
	if err != nil {
		t.Fatalf("LoadEximFrozenSeen: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("loaded %d IDs, want %d", len(got), len(data))
	}
	for id, want := range data {
		if !got[id].Equal(want) {
			t.Errorf("%s last seen = %v, want %v", id, got[id], want)
		}
	}
}

func TestEximFrozenSeenSaveReplacesPrevious(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if saveErr := db.SaveEximFrozenSeen(map[string]time.Time{"1aaaaa-000000AAAAA-0aa": now}); saveErr != nil {
		t.Fatalf("initial save: %v", saveErr)
	}
	if saveErr := db.SaveEximFrozenSeen(map[string]time.Time{"1bbbbb-000000BBBBB-0bb": now}); saveErr != nil {
		t.Fatalf("replacement save: %v", saveErr)
	}

	got, err := db.LoadEximFrozenSeen()
	if err != nil {
		t.Fatalf("LoadEximFrozenSeen: %v", err)
	}
	if _, ok := got["1aaaaa-000000AAAAA-0aa"]; ok {
		t.Error("ID absent from the latest snapshot survived the replacement")
	}
	if len(got) != 1 || !got["1bbbbb-000000BBBBB-0bb"].Equal(now) {
		t.Errorf("loaded %v, want only the replacement ID", got)
	}
}

func TestEximFrozenSeenLoadSkipsUndecodableEntries(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if saveErr := db.SaveEximFrozenSeen(map[string]time.Time{"1aaaaa-000000AAAAA-0aa": now}); saveErr != nil {
		t.Fatalf("SaveEximFrozenSeen: %v", saveErr)
	}
	if putErr := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(eximFrozenSeenBucket)).Put([]byte("1ccccc-000000CCCCC-0cc"), []byte("not a time"))
	}); putErr != nil {
		t.Fatal(putErr)
	}

	got, err := db.LoadEximFrozenSeen()
	if err != nil {
		t.Fatalf("LoadEximFrozenSeen: %v", err)
	}
	if len(got) != 1 || !got["1aaaaa-000000AAAAA-0aa"].Equal(now) {
		t.Errorf("loaded %v, want only the decodable entry", got)
	}
}
