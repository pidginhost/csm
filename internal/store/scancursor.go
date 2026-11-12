package store

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

const scanCursorBucket = "scan_cursor"

// ScanCursorRecord is the rolling-coverage cursor for one (account, check).
type ScanCursorRecord struct {
	Account         string    `json:"account"`
	Check           string    `json:"check"`
	LastPath        string    `json:"last_path"`          // last path-sorted candidate scanned
	WrappedAt       time.Time `json:"wrapped_at"`         // when the cursor last wrapped to start
	LastFullCycleTS time.Time `json:"last_full_cycle_ts"` // when a full sweep last completed

	// Signature rescan progress (deep YARA cursor only). RulesGeneration is
	// the queued rescan the walk is covering, RulesFrom is where the walk
	// stood when it took that generation, and RulesWrapped is set once the
	// walk has since wrapped to the start. RulesRootsHash ties the lap to its
	// resolved roots so a new root behind the cursor cannot be cleared unseen.
	RulesGeneration uint64 `json:"rules_generation,omitempty"`
	RulesFrom       string `json:"rules_from,omitempty"`
	RulesWrapped    bool   `json:"rules_wrapped,omitempty"`
	RulesRootsHash  string `json:"rules_roots_hash,omitempty"`

	// ChangedThrough is the lower ctime bound for priority scans, not proof
	// that older files were read: those remain the rolling window's job.
	// A lap visits paths once up to ChangedEnd. Errors retain the old bound
	// after the lap, so unreadable files get another chance on the next lap.
	ChangedThrough   time.Time `json:"changed_through,omitempty"`
	ChangedFrom      string    `json:"changed_from,omitempty"`
	ChangedEnd       string    `json:"changed_end,omitempty"`
	ChangedLapStart  time.Time `json:"changed_lap_start,omitempty"`
	ChangedLapFailed bool      `json:"changed_lap_failed,omitempty"`
	// ServedAt is a logical ordering timestamp, independent of clock steps.
	ChangedServedAt time.Time `json:"changed_served_at,omitempty"`
	// Wall and boot clocks allow a backward clock step to rewind the ctime
	// bound even when the next scan's wall time exceeds the previous one.
	ChangedClock  time.Time `json:"changed_clock,omitempty"`
	ChangedUptime float64   `json:"changed_uptime,omitempty"`
	ChangedBootID string    `json:"changed_boot_id,omitempty"`
}

// scanCursorKey builds the bucket key for a (account, check) pair.
// Format: "<account>/<check>".
func scanCursorKey(account, check string) []byte {
	return []byte(account + "/" + check)
}

// GetScanCursor retrieves the cursor record for (account, check).
// ok=false when absent (no error).
func (db *DB) GetScanCursor(account, check string) (ScanCursorRecord, bool, error) {
	var rec ScanCursorRecord
	var found bool
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(scanCursorBucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", scanCursorBucket)
		}
		v := b.Get(scanCursorKey(account, check))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &rec)
	})
	if err != nil {
		return ScanCursorRecord{}, false, err
	}
	return rec, found, nil
}

// PutScanCursor creates or replaces the cursor record for rec.Account/rec.Check.
func (db *DB) PutScanCursor(rec ScanCursorRecord) error {
	val, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("scancursor: marshal: %w", err)
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(scanCursorBucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", scanCursorBucket)
		}
		return b.Put(scanCursorKey(rec.Account, rec.Check), val)
	})
}
