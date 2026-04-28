package store

import (
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Persistence helpers for the signature-update watcher's mtime map.
// The daemon stores the last-seen mtime per signature file in bbolt
// so a restart does not trigger a phantom rescan -- without this the
// in-memory map starts empty after every restart and every file
// looks new.

const sigWatchKey = "last_mtimes"

// GetSignatureMtimes returns the persisted mtime map. Empty (not
// nil) when the bucket has no value yet -- callers can range over
// the result without a nil check.
func (db *DB) GetSignatureMtimes() (map[string]time.Time, error) {
	out := map[string]time.Time{}
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sig_watch"))
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(sigWatchKey))
		if len(raw) == 0 {
			return nil
		}
		return json.Unmarshal(raw, &out)
	})
	return out, err
}

// PutSignatureMtimes overwrites the persisted mtime map. Called
// from the watcher's tick after every walk, regardless of whether
// any file changed -- removed files need to disappear from the
// store, not stick around forever.
func (db *DB) PutSignatureMtimes(m map[string]time.Time) error {
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sig_watch"))
		if b == nil {
			return errors.New("sig_watch bucket missing (store not migrated)")
		}
		return b.Put([]byte(sigWatchKey), payload)
	})
}
