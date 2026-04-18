package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Meta-bucket keys for AbuseIPDB quota accounting. Persisted so enforcement
// survives daemon restarts and spans across 10-minute scan cycles.
const (
	abuseQuotaExhaustedKey = "abuse:quota_exhausted_until"
	abuseDailyCountPrefix  = "abuse:daily_count:" // + YYYY-MM-DD in UTC
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

// AllReputation returns all reputation entries keyed by IP.
func (db *DB) AllReputation() map[string]ReputationEntry {
	entries := make(map[string]ReputationEntry)
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("reputation")).ForEach(func(k, v []byte) error {
			var e ReputationEntry
			if json.Unmarshal(v, &e) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			entries[string(k)] = e
			return nil
		})
	})
	return entries
}

// SetAbuseQuotaExhaustedUntil records the time at which the AbuseIPDB
// quota is expected to reset. While now < t, callers should skip API
// queries. The daemon re-reads this on every cycle so the flag survives
// restarts and multi-hour backoffs.
func (db *DB) SetAbuseQuotaExhaustedUntil(t time.Time) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put(
			[]byte(abuseQuotaExhaustedKey),
			[]byte(t.UTC().Format(time.RFC3339)),
		)
	})
}

// AbuseQuotaExhaustedUntil returns the persisted quota-reset timestamp,
// or zero time if none is recorded (or the stored value is unparseable).
func (db *DB) AbuseQuotaExhaustedUntil() time.Time {
	var ts time.Time
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte("meta")).Get([]byte(abuseQuotaExhaustedKey))
		if v == nil {
			return nil
		}
		parsed, err := time.Parse(time.RFC3339, string(v))
		if err != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		ts = parsed
		return nil
	})
	return ts
}

// IncrementAbuseQueryCount bumps and returns the AbuseIPDB query counter
// for the given UTC date (YYYY-MM-DD). Used as a daily circuit breaker.
func (db *DB) IncrementAbuseQueryCount(utcDate string) int {
	var count int
	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		key := []byte(abuseDailyCountPrefix + utcDate)
		if v := b.Get(key); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
		}
		count++
		return b.Put(key, []byte(fmt.Sprintf("%d", count)))
	})
	return count
}

// AbuseQueryCount returns the AbuseIPDB query count for the given UTC date.
func (db *DB) AbuseQueryCount(utcDate string) int {
	var count int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte("meta")).Get([]byte(abuseDailyCountPrefix + utcDate))
		if v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
		}
		return nil
	})
	return count
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
