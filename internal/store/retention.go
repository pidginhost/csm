package store

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// timeKeyLowerBound computes the lexicographic lower bound of any TimeKey
// produced for timestamp t. Any TimeKey whose stored time is strictly
// earlier than t sorts before this string; any TimeKey at or after t sorts
// at or above it. Matches the format in TimeKey().
func timeKeyLowerBound(t time.Time) string {
	return fmt.Sprintf("%04d%02d%02d%02d%02d%02d%09d-0000",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(),
		t.Nanosecond())
}

// SweepHistoryOlderThan deletes history entries whose TimeKey is strictly
// older than cutoff. Returns the number of entries deleted. All work runs
// in a single bbolt transaction so the UI never sees a half-swept state;
// callers pick cutoffs that keep the batch bounded.
func (db *DB) SweepHistoryOlderThan(cutoff time.Time) (int, error) {
	cutoffKey := timeKeyLowerBound(cutoff)
	var deleted int
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil && string(k) < cutoffKey; k, _ = c.First() {
			if err := c.Delete(); err != nil {
				return err
			}
			deleted++
		}
		if deleted == 0 {
			return nil
		}
		// Decrement the history:count counter without letting it underflow.
		current := 0
		if v := tx.Bucket([]byte("meta")).Get([]byte("history:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &current)
		}
		newCount := current - deleted
		if newCount < 0 {
			newCount = 0
		}
		return setCounter(tx, "history:count", newCount)
	})
	return deleted, err
}

// SweepAttackEventsOlderThan deletes attacks:events entries older than
// cutoff and the matching entries from the attacks:events:ip secondary
// index. Returns the number of primary-bucket entries deleted.
func (db *DB) SweepAttackEventsOlderThan(cutoff time.Time) (int, error) {
	cutoffKey := timeKeyLowerBound(cutoff)
	var deleted int
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		primary := tx.Bucket([]byte("attacks:events"))
		secondary := tx.Bucket([]byte("attacks:events:ip"))
		if primary == nil {
			return nil
		}
		c := primary.Cursor()
		for k, v := c.First(); k != nil && string(k) < cutoffKey; k, v = c.First() {
			// The secondary index is keyed "<ip>/<TimeKey>", so we need
			// the event's IP to prune it.
			var ev AttackEvent
			if err := json.Unmarshal(v, &ev); err == nil && secondary != nil {
				secKey := []byte(ev.IP + "/" + string(k))
				if err := secondary.Delete(secKey); err != nil {
					return err
				}
			}
			if err := c.Delete(); err != nil {
				return err
			}
			deleted++
		}
		if deleted == 0 {
			return nil
		}
		current := 0
		if v := tx.Bucket([]byte("meta")).Get([]byte("attacks:events:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &current)
		}
		newCount := current - deleted
		if newCount < 0 {
			newCount = 0
		}
		return setCounter(tx, "attacks:events:count", newCount)
	})
	return deleted, err
}

// SweepReputationOlderThan deletes reputation entries whose CheckedAt is
// strictly older than cutoff. The bucket is keyed by IP and not by time,
// so the sweep inspects each value; malformed rows are skipped rather than
// aborting the sweep.
func (db *DB) SweepReputationOlderThan(cutoff time.Time) (int, error) {
	var deleted int
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("reputation"))
		if b == nil {
			return nil
		}
		var stale [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var e ReputationEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return nil
			}
			if e.CheckedAt.Before(cutoff) {
				// Copy k because the slice is only valid for the
				// duration of the callback.
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
			deleted++
		}
		return nil
	})
	return deleted, err
}
