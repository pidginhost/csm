package store

import (
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
}
