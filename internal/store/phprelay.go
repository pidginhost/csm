package store

import (
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// PHPRelayKV is a single key/value pair for batched writes.
type PHPRelayKV struct {
	Key   []byte
	Value []byte
}

// allowed php_relay buckets. Validated on every helper to prevent the
// daemon from accidentally writing into other buckets through these
// generic wrappers.
var phpRelayBucketAllowlist = map[string]struct{}{
	"phprelay:meta":     {},
	"phprelay:msgindex": {},
	"phprelay:ignore":   {},
	"phprelay:settings": {},
	"phprelay:baseline": {}, // Stage 3
}

func phpRelayCheckBucket(name string) error {
	if _, ok := phpRelayBucketAllowlist[name]; !ok {
		return fmt.Errorf("php_relay: bucket %q is not in the allowlist", name)
	}
	return nil
}

// PHPRelayPut writes a single key/value into the named php_relay bucket.
func (db *DB) PHPRelayPut(bucket, key string, value []byte) error {
	if err := phpRelayCheckBucket(bucket); err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", bucket)
		}
		return b.Put([]byte(key), append([]byte(nil), value...))
	})
}

// PHPRelayGet reads a single value. ok=false when the key is absent.
func (db *DB) PHPRelayGet(bucket, key string) ([]byte, bool, error) {
	if err := phpRelayCheckBucket(bucket); err != nil {
		return nil, false, err
	}
	var out []byte
	var found bool
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", bucket)
		}
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		out = append([]byte(nil), v...)
		found = true
		return nil
	})
	return out, found, err
}

// PHPRelayDelete removes a key. Missing keys are not an error.
func (db *DB) PHPRelayDelete(bucket, key string) error {
	if err := phpRelayCheckBucket(bucket); err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", bucket)
		}
		return b.Delete([]byte(key))
	})
}

// PHPRelayPutBatch writes many key/value pairs in a single bbolt
// transaction. Used by the msgIndexPersister to keep IOPS bounded.
// Returns on the first encode/put error; partial commits are visible
// only at transaction boundary.
func (db *DB) PHPRelayPutBatch(bucket string, ops []PHPRelayKV) error {
	if err := phpRelayCheckBucket(bucket); err != nil {
		return err
	}
	if len(ops) == 0 {
		return nil
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", bucket)
		}
		for _, kv := range ops {
			if len(kv.Key) == 0 {
				return errors.New("php_relay: empty key")
			}
			if err := b.Put(append([]byte(nil), kv.Key...), append([]byte(nil), kv.Value...)); err != nil {
				return err
			}
		}
		return nil
	})
}

// PHPRelaySweep iterates the bucket and deletes every key for which
// shouldDelete returns true. Decoding is the caller's responsibility.
// Returns the number of deletions.
func (db *DB) PHPRelaySweep(bucket string, shouldDelete func(key, value []byte) bool) (int, error) {
	if err := phpRelayCheckBucket(bucket); err != nil {
		return 0, err
	}
	n := 0
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", bucket)
		}
		var toDelete [][]byte
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if shouldDelete(k, v) {
				toDelete = append(toDelete, append([]byte(nil), k...))
			}
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		n = len(toDelete)
		return nil
	})
	return n, err
}

// PHPRelayList returns a copy of every key/value in the bucket. Used at
// daemon start to restore the in-memory ignoreList.
func (db *DB) PHPRelayList(bucket string) (map[string][]byte, error) {
	if err := phpRelayCheckBucket(bucket); err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", bucket)
		}
		return b.ForEach(func(k, v []byte) error {
			out[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	return out, err
}
