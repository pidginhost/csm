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
	// walk has since wrapped to the start.
	RulesGeneration uint64 `json:"rules_generation,omitempty"`
	RulesFrom       string `json:"rules_from,omitempty"`
	RulesWrapped    bool   `json:"rules_wrapped,omitempty"`
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
