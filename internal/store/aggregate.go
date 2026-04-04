package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// SeverityBucket holds aggregated counts by severity.
type SeverityBucket struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Warning  int `json:"warning"`
	Total    int `json:"total"`
}

// HourBucket is a SeverityBucket keyed by hour label.
type HourBucket struct {
	Hour string `json:"hour"`
	SeverityBucket
}

// DayBucket is a SeverityBucket keyed by date.
type DayBucket struct {
	Date string `json:"date"`
	SeverityBucket
}

// AggregateByHour returns 24 hourly buckets (oldest first) for the last 24 hours.
// It seeks directly to the start key in bbolt, scanning only the relevant range.
func (db *DB) AggregateByHour() []HourBucket {
	now := time.Now()
	currentHour := now.Truncate(time.Hour)
	cutoff := currentHour.Add(-23 * time.Hour)

	// Map: hours-ago (0=current, 23=oldest) → counts
	counts := make(map[int]*SeverityBucket, 24)
	for i := 0; i < 24; i++ {
		counts[i] = &SeverityBucket{}
	}

	seekPrefix := fmt.Sprintf("%04d%02d%02d%02d",
		cutoff.Year(), cutoff.Month(), cutoff.Day(), cutoff.Hour())

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		if b == nil {
			return nil
		}
		c := b.Cursor()

		// Seek to the earliest key that could be in our 24h window.
		for k, v := c.Seek([]byte(seekPrefix)); k != nil; k, v = c.Next() {
			var f alert.Finding
			if err := json.Unmarshal(v, &f); err != nil {
				continue
			}
			if f.Timestamp.Before(cutoff) {
				continue
			}
			if f.Timestamp.After(now) {
				continue
			}

			fHour := f.Timestamp.Truncate(time.Hour)
			hoursAgo := int(currentHour.Sub(fHour).Hours())
			if hoursAgo < 0 || hoursAgo >= 24 {
				continue
			}

			bucket := counts[hoursAgo]
			bucket.Total++
			switch f.Severity {
			case alert.Critical:
				bucket.Critical++
			case alert.High:
				bucket.High++
			case alert.Warning:
				bucket.Warning++
			}
		}
		return nil
	})

	// Build result oldest→newest (23h ago → 0h ago)
	result := make([]HourBucket, 24)
	for i := 0; i < 24; i++ {
		hoursAgo := 23 - i
		t := currentHour.Add(-time.Duration(hoursAgo) * time.Hour)
		result[i] = HourBucket{
			Hour:           fmt.Sprintf("%02d:00", t.Hour()),
			SeverityBucket: *counts[hoursAgo],
		}
	}
	return result
}

// ReadHistorySince returns all findings since the given time, using bbolt cursor
// seeking for efficiency. Results are newest-first.
func (db *DB) ReadHistorySince(since time.Time) []alert.Finding {
	seekPrefix := fmt.Sprintf("%04d%02d%02d%02d%02d%02d",
		since.Year(), since.Month(), since.Day(),
		since.Hour(), since.Minute(), since.Second())

	var results []alert.Finding
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		if b == nil {
			return nil
		}
		c := b.Cursor()

		for k, v := c.Seek([]byte(seekPrefix)); k != nil; k, v = c.Next() {
			var f alert.Finding
			if err := json.Unmarshal(v, &f); err != nil {
				continue
			}
			results = append(results, f)
		}
		return nil
	})

	// Reverse to newest-first
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
	return results
}

// AggregateByDay returns 30 daily buckets (oldest first) for the last 30 days.
// It seeks directly to the start key in bbolt, scanning only the relevant range.
func (db *DB) AggregateByDay() []DayBucket {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	cutoff := today.AddDate(0, 0, -29)

	// Map: date string → bucket index
	dateIndex := make(map[string]int, 30)
	buckets := make([]DayBucket, 30)
	for i := 0; i < 30; i++ {
		d := cutoff.AddDate(0, 0, i)
		key := d.Format("2006-01-02")
		buckets[i] = DayBucket{Date: key}
		dateIndex[key] = i
	}

	seekPrefix := fmt.Sprintf("%04d%02d%02d",
		cutoff.Year(), cutoff.Month(), cutoff.Day())

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		if b == nil {
			return nil
		}
		c := b.Cursor()

		for k, v := c.Seek([]byte(seekPrefix)); k != nil; k, v = c.Next() {
			var f alert.Finding
			if err := json.Unmarshal(v, &f); err != nil {
				continue
			}
			if f.Timestamp.Before(cutoff) {
				continue
			}

			key := f.Timestamp.Format("2006-01-02")
			idx, ok := dateIndex[key]
			if !ok {
				continue
			}

			buckets[idx].Total++
			switch f.Severity {
			case alert.Critical:
				buckets[idx].Critical++
			case alert.High:
				buckets[idx].High++
			case alert.Warning:
				buckets[idx].Warning++
			}
		}
		return nil
	})

	return buckets
}
