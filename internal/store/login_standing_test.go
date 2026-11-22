package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// The bucket holds what the daemon hands it: upserts rewrite a key, deletes
// remove one, and a replace leaves exactly the rows it carries.
func TestLoginStandingBucketRoundTrip(t *testing.T) {
	db := openTestDB(t)
	if !db.HasBucket(loginStandingBucket) {
		t.Fatalf("missing bucket %q", loginStandingBucket)
	}
	empty, err := db.LoadLoginStanding()
	if err != nil || len(empty) != 0 {
		t.Fatalf("LoadLoginStanding before save = %v, %v; want empty", empty, err)
	}

	want := map[string]LoginStanding{
		"203.0.113.5 a@example.com":    {First: 1776160800, Days: []int64{1776160800, 1776247200}},
		"2001:db8::1 b@example.com":    {First: 1776160800, Days: []int64{1776160800}},
		"198.51.100.7 a b@example.org": {First: 1776000000, Days: []int64{1776000000, 1776100000, 1776200000}},
	}
	if err = db.SaveLoginStanding(want, nil, false); err != nil {
		t.Fatal(err)
	}
	if got, loadErr := db.LoadLoginStanding(); loadErr != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadLoginStanding = %v, %v; want %v", got, loadErr, want)
	}

	update := LoginStanding{First: 1776160800, Days: []int64{1776160800, 1776247200, 1776333600}}
	if err = db.SaveLoginStanding(map[string]LoginStanding{"203.0.113.5 a@example.com": update}, []string{"2001:db8::1 b@example.com"}, false); err != nil {
		t.Fatal(err)
	}
	want["203.0.113.5 a@example.com"] = update
	delete(want, "2001:db8::1 b@example.com")
	if got, loadErr := db.LoadLoginStanding(); loadErr != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("after upsert and delete = %v, %v; want %v", got, loadErr, want)
	}

	only := map[string]LoginStanding{"192.0.2.9 c@example.net": {First: 1776160800, Days: []int64{1776160800}}}
	if err = db.SaveLoginStanding(only, nil, true); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveLoginStanding(nil, nil, false); err != nil {
		t.Fatal(err)
	}
	if got, loadErr := db.LoadLoginStanding(); loadErr != nil || !reflect.DeepEqual(got, only) {
		t.Fatalf("after replace = %v, %v; want %v", got, loadErr, only)
	}
	if err = db.SaveLoginStanding(nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if got, loadErr := db.LoadLoginStanding(); loadErr != nil || len(got) != 0 {
		t.Fatalf("after an empty replace = %v, %v; want empty", got, loadErr)
	}
}

// A damaged record is never loaded and the bucket sheds it.
func TestLoginStandingLoadDropsDamage(t *testing.T) {
	db := openTestDB(t)
	valid := map[string]LoginStanding{"203.0.113.5 a@example.com": {First: 1776160800, Days: []int64{1776160800}}}
	if err := db.SaveLoginStanding(valid, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(loginStandingBucket))
		for key, val := range map[string]string{
			"203.0.113.6 a@example.com": "not json",
			"203.0.113.7 a@example.com": `{"first":1,"days":[` + strings.Repeat("1,", 1024) + `1]}`,
			strings.Repeat("k", 1024):   `{"first":1,"days":[1]}`,
		} {
			if err := b.Put([]byte(key), []byte(val)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	got, err := db.LoadLoginStanding()
	if err != nil || !reflect.DeepEqual(got, valid) {
		t.Fatalf("LoadLoginStanding = %v, %v; want %v", got, err, valid)
	}
	var n int
	if err = db.bolt.View(func(tx *bolt.Tx) error {
		n = tx.Bucket([]byte(loginStandingBucket)).Stats().KeyN
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("bucket keeps %d records, want the valid one", n)
	}
}

// Login standing is earned from live logins; a snapshot carried to another
// time or host must not bring it back.
func TestDisarmLoginStandingSnapshot(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.SaveLoginStanding(map[string]LoginStanding{"203.0.113.5 a@example.com": {First: 1776160800, Days: []int64{1776160800}}}, nil, false); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = DisarmLoginStandingSnapshot(filepath.Join(dir, "csm.db")); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if got, loadErr := reopened.LoadLoginStanding(); loadErr != nil || len(got) != 0 {
		t.Fatalf("LoadLoginStanding after disarm = %v, %v; want empty", got, loadErr)
	}
}

// A backup or restore with nothing to strip copies the database unchanged.
func TestDisarmLoginStandingSnapshotLeavesCleanSnapshot(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "csm.db")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = DisarmLoginStandingSnapshot(path); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("disarming a snapshot without login standing rewrote it")
	}
}

// Nested buckets are damaged records too, and must not roll back cleanup.
func TestLoginStandingLoadDropsNestedBuckets(t *testing.T) {
	db := openTestDB(t)
	want := map[string]LoginStanding{"opaque mailbox with spaces": {First: 1, Days: []int64{1}}}
	if err := db.SaveLoginStanding(want, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(loginStandingBucket))
		for _, key := range []string{"a", "b", "z"} {
			child, err := b.CreateBucket([]byte(key))
			if err != nil {
				return err
			}
			if err := child.Put([]byte("child"), []byte("damage")); err != nil {
				return err
			}
		}
		return b.Put([]byte("c"), []byte("not json"))
	}); err != nil {
		t.Fatal(err)
	}
	got, err := db.LoadLoginStanding()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("load = %v, %v; want %v", got, err, want)
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(loginStandingBucket))
		if n := b.Stats().KeyN; n != 1 {
			t.Errorf("retained %d keys, want one valid row", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLoginStandingLoadPrunesSurplus(t *testing.T) {
	db := openTestDB(t)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(loginStandingBucket))
		for i := 0; i < maxLoginStandingRecords+10; i++ {
			if err := b.Put(fmt.Appendf(nil, "%06d", i), []byte(`{"first":1,"days":[1]}`)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := db.LoadLoginStanding()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxLoginStandingRecords {
		t.Fatalf("loaded %d rows", len(got))
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(loginStandingBucket))
		if n := b.Stats().KeyN; n != maxLoginStandingRecords {
			t.Errorf("retained %d rows", n)
		}
		return b.ForEach(func(k, v []byte) error {
			if _, ok := got[string(k)]; !ok {
				t.Errorf("unloaded row retained: %s", k)
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDisarmLoginStandingSnapshotPreservesUnsyncedFreelist(t *testing.T) {
	for _, bucketPresent := range []bool{false, true} {
		t.Run(fmt.Sprint(bucketPresent), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "csm.db")
			db, openErr := bolt.Open(path, 0600, &bolt.Options{NoFreelistSync: true})
			if openErr != nil {
				t.Fatal(openErr)
			}
			if err := db.Update(func(tx *bolt.Tx) error {
				name := "unrelated"
				if bucketPresent {
					name = loginStandingBucket
				}
				_, err := tx.CreateBucket([]byte(name))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = DisarmLoginStandingSnapshot(path); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("disarming a clean snapshot changed its bytes")
			}
		})
	}
}
