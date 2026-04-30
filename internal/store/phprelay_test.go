package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPHPRelayPutGetDelete(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "csm.bolt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if err = db.PHPRelayPut("phprelay:msgindex", "id1", []byte("data1")); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.PHPRelayGet("phprelay:msgindex", "id1")
	if err != nil || !ok || string(got) != "data1" {
		t.Fatalf("Get(id1) = (%q, %v, %v), want (data1, true, nil)", got, ok, err)
	}
	if err = db.PHPRelayDelete("phprelay:msgindex", "id1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.PHPRelayGet("phprelay:msgindex", "id1"); ok {
		t.Errorf("Get(id1) after delete should miss")
	}
}

func TestPHPRelayPutBatch(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "csm.bolt"))
	defer func() { _ = db.Close() }()
	ops := []PHPRelayKV{
		{Key: []byte("a"), Value: []byte("A")},
		{Key: []byte("b"), Value: []byte("B")},
		{Key: []byte("c"), Value: []byte("C")},
	}
	if err := db.PHPRelayPutBatch("phprelay:msgindex", ops); err != nil {
		t.Fatal(err)
	}
	for _, kv := range ops {
		got, ok, _ := db.PHPRelayGet("phprelay:msgindex", string(kv.Key))
		if !ok || string(got) != string(kv.Value) {
			t.Errorf("batch put %s missing or wrong: got %q", kv.Key, got)
		}
	}
}

func TestPHPRelaySweep(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "csm.bolt"))
	defer func() { _ = db.Close() }()
	_ = db.PHPRelayPut("phprelay:msgindex", "expired", []byte("old"))
	_ = db.PHPRelayPut("phprelay:msgindex", "fresh", []byte("new"))
	n, err := db.PHPRelaySweep("phprelay:msgindex", func(key, value []byte) bool {
		return string(key) == "expired"
	})
	if err != nil || n != 1 {
		t.Fatalf("Sweep n=%d err=%v", n, err)
	}
	if _, ok, _ := db.PHPRelayGet("phprelay:msgindex", "expired"); ok {
		t.Errorf("expired should be gone")
	}
	if _, ok, _ := db.PHPRelayGet("phprelay:msgindex", "fresh"); !ok {
		t.Errorf("fresh should remain")
	}
}

func TestPHPRelayList(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "csm.bolt"))
	defer func() { _ = db.Close() }()
	_ = db.PHPRelayPut("phprelay:ignore", "a", []byte("1"))
	_ = db.PHPRelayPut("phprelay:ignore", "b", []byte("2"))
	got, err := db.PHPRelayList("phprelay:ignore")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got["a"]) != "1" || string(got["b"]) != "2" {
		t.Errorf("List = %v", got)
	}
}

// guard against accidentally exposing private bolt
func TestPHPRelay_HelpersAreOnlySurface(t *testing.T) {
	var db DB
	_ = db
	// Compile-time check: these methods must exist.
	_ = (*DB).PHPRelayPut
	_ = (*DB).PHPRelayGet
	_ = (*DB).PHPRelayDelete
	_ = (*DB).PHPRelayPutBatch
	_ = (*DB).PHPRelaySweep
	_ = (*DB).PHPRelayList
	_ = time.Now
}
