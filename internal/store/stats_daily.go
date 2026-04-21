package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// stats:daily holds pre-aggregated SeverityBucket counters keyed by
// "YYYY-MM-DD" date. It is updated atomically with every history insert
// so the 30-day trend chart is decoupled from history pruning. The
// bucket has at most dailyRetentionDays rows and grows by ~50 bytes/day.
const (
	bucketStatsDaily        = "stats:daily"
	metaStatsDailyBackfilled = "stats:daily:backfilled"
)

// dailyRetentionDays caps how far back stats:daily keeps per-day rows.
// Var (not const) so tests can override.
var dailyRetentionDays = 365

// incrStatsDaily increments the per-severity counters for a single
// finding's date inside an existing bbolt write transaction. The caller
// owns the transaction; this helper does not commit.
func incrStatsDaily(tx *bolt.Tx, t time.Time, sev alert.Severity) error {
	b := tx.Bucket([]byte(bucketStatsDaily))
	if b == nil {
		return fmt.Errorf("bucket %s missing", bucketStatsDaily)
	}
	key := []byte(t.Format("2006-01-02"))

	var sb SeverityBucket
	if v := b.Get(key); v != nil {
		if err := json.Unmarshal(v, &sb); err != nil {
			// Corrupted entry - reset rather than refusing to record.
			sb = SeverityBucket{}
		}
	}

	sb.Total++
	switch sev {
	case alert.Critical:
		sb.Critical++
	case alert.High:
		sb.High++
	case alert.Warning:
		sb.Warning++
	}

	val, err := json.Marshal(sb)
	if err != nil {
		return err
	}
	return b.Put(key, val)
}

// pruneStatsDaily deletes stats:daily rows older than dailyRetentionDays.
// Cheap because the bucket is bounded to ~dailyRetentionDays entries and
// keys sort lexicographically as YYYY-MM-DD.
func pruneStatsDaily(tx *bolt.Tx, now time.Time) error {
	b := tx.Bucket([]byte(bucketStatsDaily))
	if b == nil {
		return nil
	}
	cutoff := now.AddDate(0, 0, -(dailyRetentionDays - 1)).Format("2006-01-02")
	c := b.Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		if string(k) >= cutoff {
			break
		}
		if err := c.Delete(); err != nil {
			return err
		}
	}
	return nil
}

// BackfillStatsDaily seeds stats:daily from the history bucket on first
// run after upgrade. Idempotent: a meta sentinel ensures it only runs
// once. Safe on hosts where the meta:migrated sentinel was set before
// stats:daily existed.
func (db *DB) BackfillStatsDaily() error {
	var alreadyDone bool
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket([]byte("meta")).Get([]byte(metaStatsDailyBackfilled)); v != nil {
			alreadyDone = true
		}
		return nil
	})
	if alreadyDone {
		return nil
	}

	// Read history in a View transaction and aggregate in memory so we
	// don't hold the write lock while scanning potentially large history.
	type counts struct {
		c, h, w, total int
	}
	perDay := make(map[string]*counts)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var f alert.Finding
			if err := json.Unmarshal(v, &f); err != nil {
				continue
			}
			key := f.Timestamp.Format("2006-01-02")
			cnt, ok := perDay[key]
			if !ok {
				cnt = &counts{}
				perDay[key] = cnt
			}
			cnt.total++
			switch f.Severity {
			case alert.Critical:
				cnt.c++
			case alert.High:
				cnt.h++
			case alert.Warning:
				cnt.w++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Apply the aggregated counts and set the sentinel atomically. We
	// merge into existing rows (additive) so the operation stays
	// idempotent if the sentinel write somehow gets lost mid-flight.
	return db.bolt.Update(func(tx *bolt.Tx) error {
		// Re-check sentinel inside the write transaction in case another
		// process raced ahead of us.
		if v := tx.Bucket([]byte("meta")).Get([]byte(metaStatsDailyBackfilled)); v != nil {
			return nil
		}
		b := tx.Bucket([]byte(bucketStatsDaily))
		if b == nil {
			return fmt.Errorf("bucket %s missing", bucketStatsDaily)
		}
		for key, cnt := range perDay {
			var sb SeverityBucket
			if v := b.Get([]byte(key)); v != nil {
				if err := json.Unmarshal(v, &sb); err != nil {
					sb = SeverityBucket{}
				}
			}
			sb.Critical += cnt.c
			sb.High += cnt.h
			sb.Warning += cnt.w
			sb.Total += cnt.total
			val, mErr := json.Marshal(sb)
			if mErr != nil {
				return mErr
			}
			if pErr := b.Put([]byte(key), val); pErr != nil {
				return pErr
			}
		}
		return tx.Bucket([]byte("meta")).Put(
			[]byte(metaStatsDailyBackfilled),
			[]byte(time.Now().Format(time.RFC3339)),
		)
	})
}
