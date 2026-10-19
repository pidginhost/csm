package store

import (
	"errors"
	"fmt"
	"slices"

	bolt "go.etcd.io/bbolt"
)

// Learning ledger buckets (antispam learning, spec 7.4). Only the learning
// engine writes them, through LearnUpdate.
const (
	LearnMetaBucket     = "antispam:learn:meta"
	LearnClustersBucket = "antispam:learn:clusters"
	LearnAliasesBucket  = "antispam:learn:aliases"
	LearnTargetsBucket  = "antispam:learn:targets"
	LearnIntentsBucket  = "antispam:learn:intents"
	LearnOpsBucket      = "antispam:learn:ops"
	LearnUsageBucket    = "antispam:learn:usage"
	LearnCursorBucket   = "antispam:learn:cursor"
)

// LearnBuckets lists every learning ledger bucket.
var LearnBuckets = []string{
	LearnMetaBucket, LearnClustersBucket, LearnAliasesBucket, LearnTargetsBucket,
	LearnIntentsBucket, LearnOpsBucket, LearnUsageBucket, LearnCursorBucket,
}

// LearnTx is a bbolt transaction limited to the learning buckets.
type LearnTx struct {
	tx *bolt.Tx
}

func (t LearnTx) bucket(name string) (*bolt.Bucket, error) {
	if !slices.Contains(LearnBuckets, name) {
		return nil, fmt.Errorf("learning: bucket %q is not a learning bucket", name)
	}
	b := t.tx.Bucket([]byte(name))
	if b == nil {
		return nil, fmt.Errorf("learning: bucket %q missing", name)
	}
	return b, nil
}

// Get returns a copy of the value at key, nil when absent.
func (t LearnTx) Get(bucket string, key []byte) ([]byte, error) {
	b, err := t.bucket(bucket)
	if err != nil {
		return nil, err
	}
	if v := b.Get(key); v != nil {
		return append([]byte{}, v...), nil
	}
	return nil, nil
}

// Put stores value at key.
func (t LearnTx) Put(bucket string, key, value []byte) error {
	b, err := t.bucket(bucket)
	if err != nil {
		return err
	}
	if len(key) == 0 {
		return errors.New("learning: empty key")
	}
	return b.Put(append([]byte(nil), key...), append([]byte(nil), value...))
}

// Delete removes key; a missing key is not an error.
func (t LearnTx) Delete(bucket string, key []byte) error {
	b, err := t.bucket(bucket)
	if err != nil {
		return err
	}
	return b.Delete(key)
}

// ForEach visits every key in order. fn must not keep k or v.
func (t LearnTx) ForEach(bucket string, fn func(k, v []byte) error) error {
	b, err := t.bucket(bucket)
	if err != nil {
		return err
	}
	return b.ForEach(fn)
}

// Scan visits keys strictly after after (from the first key when after is
// empty) in order until fn returns false. fn must not keep k or v.
func (t LearnTx) Scan(bucket string, after []byte, fn func(k, v []byte) (bool, error)) error {
	b, err := t.bucket(bucket)
	if err != nil {
		return err
	}
	c := b.Cursor()
	k, v := c.First()
	if len(after) > 0 {
		k, v = c.Seek(after)
		if k != nil && string(k) == string(after) {
			k, v = c.Next()
		}
	}
	for ; k != nil; k, v = c.Next() {
		more, err := fn(k, v)
		if err != nil || !more {
			return err
		}
	}
	return nil
}

// NextSequence returns the bucket's next sequence number. Numbers are never
// reused, even after their records are deleted.
func (t LearnTx) NextSequence(bucket string) (uint64, error) {
	b, err := t.bucket(bucket)
	if err != nil {
		return 0, err
	}
	return b.NextSequence()
}

// LearnUpdate runs fn in one read-write transaction; an error rolls it back.
func (db *DB) LearnUpdate(fn func(LearnTx) error) error {
	return db.bolt.Update(func(tx *bolt.Tx) error { return fn(LearnTx{tx: tx}) })
}

// LearnView runs fn in one read-only transaction.
func (db *DB) LearnView(fn func(LearnTx) error) error {
	return db.bolt.View(func(tx *bolt.Tx) error { return fn(LearnTx{tx: tx}) })
}

// clearLearning drops every learning record from a private snapshot.
func (db *DB) clearLearning() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		for _, name := range LearnBuckets {
			if tx.Bucket([]byte(name)) == nil {
				continue
			}
			if err := tx.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
}
