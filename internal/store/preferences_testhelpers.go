package store

import (
	"bytes"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// RewriteUndoEntryRecordedAt rewrites the RecordedAt field of an undo
// entry identified by id. Used by tests that need to age an entry past the
// TTL window without sleeping for real.
func RewriteUndoEntryRecordedAt(db *DB, id string, at time.Time) error {
	if db == nil || db.bolt == nil {
		return fmt.Errorf("store unavailable")
	}
	if id == "" {
		return fmt.Errorf("id required")
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(prefsBucket))
		if b == nil {
			return fmt.Errorf("prefs bucket missing")
		}
		c := b.Cursor()
		needle := []byte(":undo:")
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if !bytes.Contains(k, needle) {
				continue
			}
			e, err := decodeUndoEntry(v)
			if err != nil {
				continue
			}
			if e.ID != id {
				continue
			}
			e.RecordedAt = at
			raw, err := encodeUndoEntry(e)
			if err != nil {
				return err
			}
			return b.Put(k, raw)
		}
		return fmt.Errorf("entry %s not found", id)
	})
}
