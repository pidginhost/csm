package store

import (
	"encoding/json"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ReputationEntry holds the cached reputation data for an IP address.
type ReputationEntry struct {
	Score     int       `json:"score"`
	Category  string    `json:"category"`
	CheckedAt time.Time `json:"checked_at"`
}

// SetReputation stores a reputation entry for the given IP.
func (db *DB) SetReputation(ip string, entry ReputationEntry) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("reputation"))
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(ip), val)
	})
}

// GetReputation retrieves a reputation entry for the given IP.
// Returns the entry and true if found, or a zero value and false if not.
func (db *DB) GetReputation(ip string) (ReputationEntry, bool) {
	var entry ReputationEntry
	var found bool

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("reputation"))
		v := b.Get([]byte(ip))
		if v == nil {
			return nil
		}
		if json.Unmarshal(v, &entry) != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		found = true
		return nil
	})

	return entry, found
}

// CleanExpiredReputation deletes entries older than maxAge.
// Uses a collect-then-delete pattern because bbolt does not allow mutation
// during ForEach iteration. Returns the count of entries removed.
func (db *DB) CleanExpiredReputation(maxAge time.Duration) int {
	var removed int
	cutoff := time.Now().Add(-maxAge)

	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("reputation"))

		// Collect keys to delete.
		var toDelete [][]byte
		_ = b.ForEach(func(k, v []byte) error {
			var entry ReputationEntry
			if json.Unmarshal(v, &entry) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			if entry.CheckedAt.Before(cutoff) {
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				toDelete = append(toDelete, keyCopy)
			}
			return nil
		})

		// Delete collected keys.
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			removed++
		}

		return nil
	})

	return removed
}

// EnforceReputationCap ensures the reputation bucket has at most max entries.
// If the count exceeds max, the oldest entries (by CheckedAt) are deleted.
// Returns the count of entries removed.
func (db *DB) EnforceReputationCap(max int) int {
	var removed int

	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("reputation"))

		// Collect all entries with their keys.
		type keyed struct {
			key       []byte
			checkedAt time.Time
		}
		var all []keyed

		_ = b.ForEach(func(k, v []byte) error {
			var entry ReputationEntry
			if json.Unmarshal(v, &entry) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			keyCopy := make([]byte, len(k))
			copy(keyCopy, k)
			all = append(all, keyed{key: keyCopy, checkedAt: entry.CheckedAt})
			return nil
		})

		if len(all) <= max {
			return nil
		}

		// Sort by CheckedAt ascending (oldest first).
		sort.Slice(all, func(i, j int) bool {
			return all[i].checkedAt.Before(all[j].checkedAt)
		})

		// Delete the oldest entries beyond the cap.
		excess := len(all) - max
		for i := 0; i < excess; i++ {
			if err := b.Delete(all[i].key); err != nil {
				return err
			}
			removed++
		}

		return nil
	})

	return removed
}
