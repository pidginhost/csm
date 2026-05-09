package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// FirewallRollback is a pending tentative-apply record. The previous
// csm.yaml bytes are stashed verbatim so a recovery path can restore the
// file byte-for-byte without re-rendering through any encoder. Hashes are
// recorded so the daemon can sanity-check the on-disk file matches what
// was applied before deciding to revert.
type FirewallRollback struct {
	PrevYAML  []byte    `json:"prev_yaml"`
	PrevHash  string    `json:"prev_hash"`
	NewHash   string    `json:"new_hash"`
	AppliedAt time.Time `json:"applied_at"`
	ExpiresAt time.Time `json:"expires_at"`
	AppliedBy string    `json:"applied_by"`
}

const fwRollbackBucket = "fw:rollback"
const fwRollbackKey = "pending"

// SaveFirewallRollback writes a pending rollback record. Overwrites any
// existing pending entry; callers must clear or revert the previous one
// first if that matters for their flow.
func (db *DB) SaveFirewallRollback(rb FirewallRollback) error {
	val, err := json.Marshal(rb)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(fwRollbackBucket))
		return b.Put([]byte(fwRollbackKey), val)
	})
}

// GetFirewallRollback returns the pending rollback or (zero, false) if
// none. The bool distinguishes "no record" from a zero-valued record.
// A bbolt unmarshal failure is treated as "no usable record" so the
// daemon can skip a corrupt entry instead of refusing to start.
func (db *DB) GetFirewallRollback() (FirewallRollback, bool) {
	var rb FirewallRollback
	found := false
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(fwRollbackBucket))
		val := b.Get([]byte(fwRollbackKey))
		if val == nil {
			return nil
		}
		if uerr := json.Unmarshal(val, &rb); uerr != nil {
			// Corrupt record: leave found=false so the caller treats
			// it as "no pending rollback" rather than panicking.
			return nil //nolint:nilerr // swallowing is the intent; see comment.
		}
		found = true
		return nil
	})
	return rb, found
}

// ClearFirewallRollback drops the pending rollback. Idempotent: deleting
// a non-existent key is not an error in bbolt.
func (db *DB) ClearFirewallRollback() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(fwRollbackBucket))
		return b.Delete([]byte(fwRollbackKey))
	})
}
