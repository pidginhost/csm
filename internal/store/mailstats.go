package store

import (
	"bytes"
	"encoding/binary"

	bolt "go.etcd.io/bbolt"
)

// The mail decision counter of the Email Security page. Stats and gap keys
// are unix seconds; a gap is keyed by its end, so pruning by key drops only
// gaps that ended before the cutoff. Ring keys are reject classes.
const (
	mailStatsBucket   = "mail:stats"
	mailRejectsBucket = "mail:rejects"
	mailGapsBucket    = "mail:gaps"
)

func unixKey(sec int64) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(sec)) // #nosec G115 -- unix seconds since 1970 are non-negative, so key order is time order
}

func keyUnix(k []byte) int64 {
	return int64(binary.BigEndian.Uint64(k)) // #nosec G115 -- reverses unixKey
}

// PutMailStats writes the given counter buckets and reject rings, each ring
// replacing the class's stored ring, and deletes stats buckets and gaps
// keyed below pruneBefore.
func (db *DB) PutMailStats(buckets map[int64][]byte, rejects map[string][]byte, pruneBefore int64) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		stats := tx.Bucket([]byte(mailStatsBucket))
		for k, v := range buckets {
			if err := stats.Put(unixKey(k), v); err != nil {
				return err
			}
		}
		rings := tx.Bucket([]byte(mailRejectsBucket))
		for class, v := range rejects {
			if err := rings.Put([]byte(class), v); err != nil {
				return err
			}
		}
		cutoff := unixKey(pruneBefore)
		for _, b := range []*bolt.Bucket{stats, tx.Bucket([]byte(mailGapsBucket))} {
			// Re-seek after each delete: Next skips keys once this
			// transaction has written to the bucket.
			c := b.Cursor()
			for k, _ := c.First(); k != nil && bytes.Compare(k, cutoff) < 0; k, _ = c.First() {
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// MailStats returns the stored counter buckets by start and reject rings by
// class.
func (db *DB) MailStats() (buckets map[int64][]byte, rejects map[string][]byte, err error) {
	buckets, rejects = map[int64][]byte{}, map[string][]byte{}
	err = db.bolt.View(func(tx *bolt.Tx) error {
		if statsErr := tx.Bucket([]byte(mailStatsBucket)).ForEach(func(k, v []byte) error {
			if len(k) == 8 {
				buckets[keyUnix(k)] = bytes.Clone(v)
			}
			return nil
		}); statsErr != nil {
			return statsErr
		}
		return tx.Bucket([]byte(mailRejectsBucket)).ForEach(func(k, v []byte) error {
			rejects[string(k)] = bytes.Clone(v)
			return nil
		})
	})
	return buckets, rejects, err
}

// AddMailStatsGap stores a stretch the counter did not see.
func (db *DB) AddMailStatsGap(start, end int64) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(mailGapsBucket)).Put(unixKey(end), unixKey(start))
	})
}

// MailStatsGaps returns the stored gaps that end after since as
// [start, end] pairs, oldest first.
func (db *DB) MailStatsGaps(since int64) ([][2]int64, error) {
	var gaps [][2]int64
	err := db.bolt.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte(mailGapsBucket)).Cursor()
		for k, v := c.Seek(unixKey(since + 1)); k != nil; k, v = c.Next() {
			if len(k) == 8 && len(v) == 8 {
				gaps = append(gaps, [2]int64{keyUnix(v), keyUnix(k)})
			}
		}
		return nil
	})
	return gaps, err
}
