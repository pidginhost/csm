package store

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestAppliedThreatBatchIsAtomic(t *testing.T) {
	db := openThreatTestDB(t)
	expires := time.Now().Add(time.Hour)
	entries := []PermanentBlockEntry{{IP: "192.0.2.73", Reason: "CSM auto-block: ssh_brute", ExpiresAt: expires},
		{IP: "192.0.2.74", Reason: "CSM auto-block: ssh_brute", ExpiresAt: expires}}
	if err := db.AddTempBlock("192.0.2.74", "CSM auto-block: ssh_brute", expires); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("threats")).Put([]byte("192.0.2.74"), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAppliedTempBlocks(entries); err == nil {
		t.Fatal("corrupt second row did not refuse the batch")
	}
	if _, ok := db.GetPermanentBlock("192.0.2.73"); ok {
		t.Fatal("a failed batch committed its first row")
	}
	if err := db.RemovePermanentBlock("192.0.2.74"); err != nil {
		t.Fatal(err)
	}
	var before, after int
	if err := db.bolt.View(func(tx *bolt.Tx) error { before = tx.ID(); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAppliedTempBlocks(entries); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error { after = tx.ID(); return nil }); err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("batch used %d transactions, want one", after-before)
	}
	for _, e := range entries {
		if row, ok := db.GetPermanentBlock(e.IP); !ok || !row.ExpiresAt.Equal(expires) {
			t.Fatalf("missing batch member: %+v, %t", row, ok)
		}
	}
}
