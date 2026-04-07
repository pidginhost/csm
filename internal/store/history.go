package store

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// maxHistoryEntries is the maximum number of history entries to retain.
// It is a var (not const) so tests can override it.
var maxHistoryEntries = 100_000

// AppendHistory inserts findings into the history bucket with TimeKey keys.
// It increments the history:count counter and prunes oldest entries if the
// count exceeds maxHistoryEntries.
func (db *DB) AppendHistory(findings []alert.Finding) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))

		for i, f := range findings {
			key := TimeKey(f.Timestamp, i)
			val, err := json.Marshal(f)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(key), val); err != nil {
				return err
			}
		}

		if err := incrCounter(tx, "history:count", len(findings)); err != nil {
			return err
		}

		// Prune oldest entries if count exceeds maxHistoryEntries.
		meta := tx.Bucket([]byte("meta"))
		var count int
		if v := meta.Get([]byte("history:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
		}

		if count > maxHistoryEntries {
			excess := count - maxHistoryEntries
			c := b.Cursor()
			k, _ := c.First()
			for ; k != nil && excess > 0; excess-- {
				// Delete() moves the cursor to the next item, so we
				// must NOT call c.Next() after it.
				if err := c.Delete(); err != nil {
					return err
				}
				k, _ = c.First()
			}
			if err := setCounter(tx, "history:count", maxHistoryEntries); err != nil {
				return err
			}
		}

		return nil
	})
}

// ReadHistory reads findings from the history bucket, newest-first.
// It returns up to limit findings starting at offset, plus the total count.
func (db *DB) ReadHistory(limit, offset int) ([]alert.Finding, int) {
	total := db.getCounter("history:count")
	var results []alert.Finding

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		c := b.Cursor()

		// Skip offset entries from the end (newest first).
		skipped := 0
		k, v := c.Last()
		for ; k != nil && skipped < offset; k, v = c.Prev() {
			skipped++
		}

		// Collect up to limit entries.
		for ; k != nil && len(results) < limit; k, v = c.Prev() {
			var f alert.Finding
			if err := json.Unmarshal(v, &f); err == nil {
				results = append(results, f)
			}
		}

		return nil
	})

	return results, total
}

// ReadHistoryFiltered reads findings with optional filtering.
// Parameters:
//   - from, to: date strings "YYYY-MM-DD" for time-range filtering (empty to skip)
//   - severity: filter by severity level (-1 for no filter)
//   - search: case-insensitive substring match on check/message/details (empty to skip)
func (db *DB) ReadHistoryFiltered(limit, offset int, from, to string, severity int, search string) ([]alert.Finding, int) {
	var results []alert.Finding
	matched := 0
	searchLower := strings.ToLower(search)

	var fromPrefix, toPrefix string
	if from != "" {
		fromPrefix = ParseTimeKeyPrefix(from)
	}
	if to != "" {
		// toPrefix needs to match the entire day, so we use the next day's prefix
		// by appending a high character to ensure all entries on that day are included.
		toPrefix = ParseTimeKeyPrefix(to) + "99" // "YYYYMMDD99" is > any time on that day
	}

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		c := b.Cursor()

		// Start from the end (newest) and iterate backward.
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			key := string(k)

			// Time-range: if key is above toPrefix, skip it.
			if toPrefix != "" && key > toPrefix {
				continue
			}

			// Time-range: if key is below fromPrefix, all remaining are older - stop.
			if fromPrefix != "" && key < fromPrefix {
				break
			}

			var f alert.Finding
			if err := json.Unmarshal(v, &f); err != nil {
				continue
			}

			// Severity filter.
			if severity >= 0 && int(f.Severity) != severity {
				continue
			}

			// Search filter.
			if search != "" && !containsLower(f.Check, searchLower) &&
				!containsLower(f.Message, searchLower) &&
				!containsLower(f.Details, searchLower) {
				continue
			}

			matched++
			if matched > offset && len(results) < limit {
				results = append(results, f)
			}
		}

		return nil
	})

	return results, matched
}

// containsLower checks if s contains substr using case-insensitive matching.
// substr must already be lowercase.
func containsLower(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), substr)
}
