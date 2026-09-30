package store

import (
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

const eximFrozenSeenBucket = "exim:frozen_seen"

// SaveEximFrozenSeen replaces the persisted frozen-message dedup snapshot:
// queue ID -> last time the daemon saw the message frozen. Persisting it lets
// a restart recognise messages it already reported, so the first queue run
// after a restart does not re-report every message that is still frozen.
// The bucket is rewritten whole, so IDs the daemon has dropped disappear.
func (db *DB) SaveEximFrozenSeen(seen map[string]time.Time) error {
	encoded := make(map[string][]byte, len(seen))
	for id, lastSeen := range seen {
		if id == "" {
			continue
		}
		val, err := lastSeen.UTC().MarshalText()
		if err != nil {
			return err
		}
		encoded[id] = val
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(eximFrozenSeenBucket)); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
			return err
		}
		b, err := tx.CreateBucket([]byte(eximFrozenSeenBucket))
		if err != nil {
			return err
		}
		for id, val := range encoded {
			if err := b.Put([]byte(id), val); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadEximFrozenSeen returns the persisted frozen-message dedup snapshot.
// Returns an empty map when nothing has been persisted yet.
func (db *DB) LoadEximFrozenSeen() (map[string]time.Time, error) {
	out := make(map[string]time.Time)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(eximFrozenSeenBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var lastSeen time.Time
			if lastSeen.UnmarshalText(v) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			out[string(k)] = lastSeen
			return nil
		})
	})
	return out, err
}
