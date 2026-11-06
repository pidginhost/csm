package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The bucket holds exactly the live set the daemon reports: an upsert of a
// held key rewrites it, a delete removes it, and a damaged record is never
// loaded into memory.
func TestKnownCustomersBucketBounded(t *testing.T) {
	db := openTestDB(t)
	if !db.HasBucket(knownCustomersBucket) {
		t.Fatalf("missing bucket %q", knownCustomersBucket)
	}
	empty, err := db.LoadKnownCustomers()
	if err != nil || len(empty) != 0 {
		t.Fatalf("LoadKnownCustomers before save = %v, %v; want empty", empty, err)
	}

	at := time.Date(2026, 11, 5, 9, 0, 0, 123456789, time.UTC)
	ip := func(i int) string { return fmt.Sprintf("2001:db8::%x", i) }
	upserts := make(map[string]KnownCustomer)
	for i := 0; i < 100; i++ {
		upserts[ip(i)] = KnownCustomer{Kind: "imap", Account: "a@example.com", At: at}
	}
	if err = db.SaveKnownCustomers(upserts, nil); err != nil {
		t.Fatal(err)
	}

	later := at.Add(time.Hour)
	upserts = map[string]KnownCustomer{ip(0): {Kind: "cpanel", Account: "alice", At: later}}
	var deletes []string
	for i := 50; i < 100; i++ {
		deletes = append(deletes, ip(i))
	}
	for i := 100; i < 105; i++ {
		upserts[ip(i)] = KnownCustomer{Kind: "ftp", At: later}
	}
	if err = db.SaveKnownCustomers(upserts, deletes); err != nil {
		t.Fatal(err)
	}

	if err = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(knownCustomersBucket))
		for key, val := range map[string]string{
			"203.0.113.1":              "not json",
			"203.0.113.2":              `{"kind":"imap","account":"` + strings.Repeat("x", 1<<20) + `","at":"2026-11-05T09:00:00Z"}`,
			strings.Repeat("2", 1<<10): `{"kind":"ftp","at":"2026-11-05T09:00:00Z"}`,
		} {
			if perr := b.Put([]byte(key), []byte(val)); perr != nil {
				return perr
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	got, err := db.LoadKnownCustomers()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 55 {
		t.Fatalf("loaded %d records, want 55", len(got))
	}
	if c := got[ip(0)]; c.Kind != "cpanel" || c.Account != "alice" || !c.At.Equal(later) {
		t.Errorf("rewritten record = %+v", c)
	}
	if c := got[ip(1)]; c.Kind != "imap" || c.Account != "a@example.com" || !c.At.Equal(at) {
		t.Errorf("kept record = %+v, want the saved value with its full time", c)
	}
	if c, ok := got[ip(104)]; !ok || c.Kind != "ftp" || c.Account != "" {
		t.Errorf("added record = %+v, %v", c, ok)
	}
	for _, k := range []string{ip(50), ip(99), "203.0.113.1", "203.0.113.2"} {
		if c, ok := got[k]; ok {
			t.Errorf("loaded %s: %+v", k, c)
		}
	}
	// Records that cannot be read are deleted, so they do not stay on disk.
	if n := knownCustomerRecords(t, db); n != 55 {
		t.Errorf("bucket holds %d records after load, want 55", n)
	}
}

func knownCustomerRecords(t *testing.T, db *DB) (n int) {
	t.Helper()
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		n = tx.Bucket([]byte(knownCustomersBucket)).Stats().KeyN
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// A load past the bound keeps the newest records and deletes the rest.
func TestKnownCustomersLoadKeepsNewest(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	ip := func(i int) string { return fmt.Sprintf("2001:db8:%x:%x::", i>>16, i&0xffff) }
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(knownCustomersBucket))
		for i := 0; i < maxKnownCustomerRecords+5; i++ {
			val, err := json.Marshal(KnownCustomer{Kind: "imap", At: at.Add(time.Duration(i) * time.Second)})
			if err != nil {
				return err
			}
			if err := b.Put([]byte(ip(i)), val); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := db.LoadKnownCustomers()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxKnownCustomerRecords {
		t.Fatalf("loaded %d records, want %d", len(got), maxKnownCustomerRecords)
	}
	for i := 0; i < 5; i++ {
		if _, ok := got[ip(i)]; ok {
			t.Errorf("oldest record %d kept", i)
		}
	}
	if _, ok := got[ip(maxKnownCustomerRecords+4)]; !ok {
		t.Error("newest record dropped")
	}
	if n := knownCustomerRecords(t, db); n != maxKnownCustomerRecords {
		t.Errorf("bucket holds %d records after load, want %d", n, maxKnownCustomerRecords)
	}
}
