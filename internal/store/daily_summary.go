package store

import (
	"bytes"

	bolt "go.etcd.io/bbolt"
)

// dailySummaryKey holds the daily alert summary window in the meta bucket.
const dailySummaryKey = "alerts:daily_summary"

// LoadDailySummary returns the saved daily alert summary, or nil when none
// was saved.
func (db *DB) LoadDailySummary() ([]byte, error) {
	var out []byte
	err := db.bolt.View(func(tx *bolt.Tx) error {
		out = bytes.Clone(tx.Bucket([]byte("meta")).Get([]byte(dailySummaryKey)))
		return nil
	})
	return out, err
}

// SaveDailySummary replaces the saved daily alert summary.
func (db *DB) SaveDailySummary(b []byte) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte(dailySummaryKey), b)
	})
}
