package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

// Size returns the on-disk size of the bbolt file in bytes. bbolt does
// not shrink the file on delete; compare Size() before and after a
// CompactInto call to see how much space would be reclaimed.
func (db *DB) Size() (int64, error) {
	info, err := os.Stat(db.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// CompactInto snapshots the live DB into a fresh bbolt file at dstPath
// using bolt.Compact. Returns the source size and the compacted size
// (both in bytes).
//
// Correctness: bolt.Compact runs a View transaction on src for the
// duration of the walk, so concurrent Update calls on src will either
// land before the walk begins (captured in the snapshot) or after it
// completes (not in the snapshot). It is the caller's job to quiesce
// writers between the CompactInto call and the file rename+reopen that
// promotes the new file; otherwise post-snapshot writes are silently
// dropped during the swap.
//
// txMaxSize caps per-transaction bytes written to the destination (see
// bolt.Compact docs). Zero means "one transaction for the whole copy",
// which is the fastest path for DBs that comfortably fit in memory.
func (db *DB) CompactInto(dstPath string, txMaxSize int64) (srcSize, dstSize int64, err error) {
	if dstPath == "" {
		return 0, 0, errors.New("dst path is empty")
	}
	// Snapshot the src size up front; if bolt.Compact mutates src in ways
	// we didn't anticipate, a concurrent reader still sees consistent
	// numbers.
	srcInfo, statErr := os.Stat(db.path)
	if statErr != nil {
		return 0, 0, fmt.Errorf("stat src: %w", statErr)
	}
	srcSize = srcInfo.Size()

	dst, err := bolt.Open(dstPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		// bolt.Open may have created a zero-byte file before failing; clean it up.
		_ = os.Remove(dstPath)
		return srcSize, 0, fmt.Errorf("opening dst: %w", err)
	}

	compactErr := bolt.Compact(dst, db.bolt, txMaxSize)
	if closeErr := dst.Close(); closeErr != nil && compactErr == nil {
		compactErr = fmt.Errorf("closing dst: %w", closeErr)
	}
	if compactErr != nil {
		_ = os.Remove(dstPath)
		return srcSize, 0, compactErr
	}

	dstInfo, err := os.Stat(dstPath)
	if err != nil {
		return srcSize, 0, fmt.Errorf("stat dst: %w", err)
	}
	return srcSize, dstInfo.Size(), nil
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
