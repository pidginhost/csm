package store

import (
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

const mailGoodSourceBucket = "mail:good_source"

// GoodSourcePair is the persisted established-sender window for one (IP,
// mailbox): the earliest and most recent successful auth. Persisting it lets
// established good standing survive a daemon restart so the post-restart
// cold-start does not re-open the mail brute-force false-positive window.
type GoodSourcePair struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// SaveMailGoodSource replaces the persisted mail good-source snapshot with data.
// Snapshot semantics: the bucket is fully rewritten so IPs no longer present are
// dropped, keeping the persisted set in step with the live tracker.
func (db *DB) SaveMailGoodSource(data map[string]map[string]GoodSourcePair) error {
	encoded := make(map[string][]byte, len(data))
	for ip, accts := range data {
		if ip == "" || len(accts) == 0 {
			continue
		}
		val, err := json.Marshal(accts)
		if err != nil {
			return err
		}
		encoded[ip] = val
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(mailGoodSourceBucket)); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
			return err
		}
		b, err := tx.CreateBucket([]byte(mailGoodSourceBucket))
		if err != nil {
			return err
		}
		for ip, val := range encoded {
			if perr := b.Put([]byte(ip), val); perr != nil {
				return perr
			}
		}
		return nil
	})
}

// LoadMailGoodSource returns the persisted mail good-source snapshot keyed by
// IP. Returns an empty map when nothing has been persisted yet.
func (db *DB) LoadMailGoodSource() (map[string]map[string]GoodSourcePair, error) {
	out := make(map[string]map[string]GoodSourcePair)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(mailGoodSourceBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var accts map[string]GoodSourcePair
			if json.Unmarshal(v, &accts) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			out[string(k)] = accts
			return nil
		})
	})
	return out, err
}
