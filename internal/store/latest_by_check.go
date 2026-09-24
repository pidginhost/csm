package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// stats:latest_by_check maps a check name to the timestamp of its newest
// history entry. AppendHistory updates it in the same transaction, so asking
// when a check last fired reads one small bucket instead of decoding up to
// maxHistoryEntries findings.
const (
	bucketLatestByCheck         = "stats:latest_by_check"
	metaLatestByCheckBackfilled = "stats:latest_by_check:backfilled"
)

// bumpLatestByCheck records t for check unless a newer time is already
// stored. It runs inside the caller's write transaction.
func bumpLatestByCheck(tx *bolt.Tx, check string, t time.Time) error {
	if check == "" {
		return nil
	}
	b := tx.Bucket([]byte(bucketLatestByCheck))
	if b == nil {
		return fmt.Errorf("bucket %s missing", bucketLatestByCheck)
	}
	if v := b.Get([]byte(check)); v != nil {
		if prev, err := time.Parse(time.RFC3339Nano, string(v)); err == nil && !t.After(prev) {
			return nil
		}
	}
	return b.Put([]byte(check), []byte(t.UTC().Format(time.RFC3339Nano)))
}

// LatestByCheck returns the timestamp of the newest history entry of every
// check that has written history.
func (db *DB) LatestByCheck() map[string]time.Time {
	out := map[string]time.Time{}
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketLatestByCheck))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if t, err := time.Parse(time.RFC3339Nano, string(v)); err == nil {
				out[string(k)] = t
			}
			return nil
		})
	})
	return out
}

// BackfillLatestByCheck seeds stats:latest_by_check from history once, on
// the first start after an upgrade. A meta sentinel makes it a no-op after.
func (db *DB) BackfillLatestByCheck() error {
	var done bool
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		done = tx.Bucket([]byte("meta")).Get([]byte(metaLatestByCheckBackfilled)) != nil
		return nil
	})
	if done {
		return nil
	}
	latest := map[string]time.Time{}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			// A corrupt entry is skipped, as every history reader does.
			var f alert.Finding
			if json.Unmarshal(v, &f) == nil && f.Check != "" && f.Timestamp.After(latest[f.Check]) {
				latest[f.Check] = f.Timestamp
			}
			return nil
		})
	}); err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		for check, t := range latest {
			if err := bumpLatestByCheck(tx, check, t); err != nil {
				return err
			}
		}
		return tx.Bucket([]byte("meta")).Put([]byte(metaLatestByCheckBackfilled), []byte(time.Now().UTC().Format(time.RFC3339)))
	})
}
