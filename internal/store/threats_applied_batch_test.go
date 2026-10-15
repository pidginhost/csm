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
	// An empty key cannot be stored, so the batch fails at its second row.
	failing := []PermanentBlockEntry{entries[0], {IP: "", Reason: "CSM auto-block: ssh_brute", ExpiresAt: expires}}
	if err := db.AddAppliedTempBlocks(failing); err == nil {
		t.Fatal("an unstorable second row did not refuse the batch")
	}
	if _, ok := db.GetPermanentBlock("192.0.2.73"); ok {
		t.Fatal("a failed batch committed its first row")
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

// An undecodable stored value is replaced, as the legacy writer replaces it:
// refusing it would hold every later admission record behind one entry.
func TestAppliedThreatReplacesAnUndecodableEntry(t *testing.T) {
	db := openThreatTestDB(t)
	expires := time.Now().Add(time.Hour)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("threats")).Put([]byte("192.0.2.75"), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAppliedTempBlocks([]PermanentBlockEntry{{IP: "192.0.2.75", Reason: "CSM auto-block: ssh_brute", ExpiresAt: expires}}); err != nil {
		t.Fatalf("an undecodable entry held the batch back: %v", err)
	}
	row, ok := db.GetPermanentBlock("192.0.2.75")
	if !ok || row.Source != ThreatSourceAutoBlock || row.Reason != "CSM auto-block: ssh_brute" || !row.ExpiresAt.Equal(expires) {
		t.Fatalf("undecodable entry not replaced: %+v, %t", row, ok)
	}
}
