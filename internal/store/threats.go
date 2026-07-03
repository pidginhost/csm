package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Threat entry sources. Rows written before source tagging existed carry
// an empty Source; Expired classifies those by their reason text.
const (
	ThreatSourceOperator  = "operator"
	ThreatSourceAutoBlock = "autoblock"
)

// legacyOperatorReasonPrefixes identifies pre-source-tagging rows added by a
// human. The Web UI manual/bulk block handlers are the only operator-facing
// writers this bucket ever had and they always used these exact reason
// strings; flat-file migration appended a "[YYYY-MM-DD]" suffix, hence the
// prefix match. Every other legacy row came from the temporary auto-block
// path, which historically wrote no-expiry rows that re-flagged the IP on
// every access after the block lapsed (permablock loop).
var legacyOperatorReasonPrefixes = []string{
	"Manually blocked via CSM Web UI",
	"Bulk blocked via CSM Web UI",
}

// PermanentBlockEntry represents an IP blocked by the threat system.
// A zero ExpiresAt with a non-empty Source means the row never expires.
type PermanentBlockEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	Source    string    `json:"source,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Expired reports whether the entry should no longer count as a live
// threat. Legacy rows (no source, no expiry) that do not match a known
// operator reason are treated as expired: they were written by the old
// temporary auto-block path and keeping them alive re-creates the
// permablock loop on upgraded hosts.
func (e PermanentBlockEntry) Expired(now time.Time) bool {
	if !e.ExpiresAt.IsZero() {
		return !e.ExpiresAt.After(now)
	}
	if e.Source != "" {
		return false
	}
	for _, prefix := range legacyOperatorReasonPrefixes {
		if strings.HasPrefix(e.Reason, prefix) {
			return false
		}
	}
	return true
}

// WhitelistEntry represents an IP that should bypass threat checks.
type WhitelistEntry struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
	Permanent bool      `json:"permanent"`
}

// AddPermanentBlock adds an IP to the block list as a never-expiring
// operator entry. Only increments threats:count if the key is new.
// Overwrites any temp entry for the same IP: an explicit operator block
// upgrades it to permanent.
func (db *DB) AddPermanentBlock(ip, reason string) error {
	return db.putThreatEntry(PermanentBlockEntry{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		Source:    ThreatSourceOperator,
	})
}

// AddTempBlock records an auto-blocked IP with an expiry matching the
// firewall block, so the entry lapses together with the block instead of
// flagging the IP forever. A zero expiresAt mirrors a never-expiring block.
// Never downgrades an existing permanent row, and never shortens a longer
// temp expiry already on file. Only increments threats:count if the key is
// new.
func (db *DB) AddTempBlock(ip, reason string, expiresAt time.Time) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))

		entry := PermanentBlockEntry{
			IP:        ip,
			Reason:    reason,
			BlockedAt: time.Now(),
			Source:    ThreatSourceAutoBlock,
			ExpiresAt: expiresAt,
		}

		existing := b.Get([]byte(ip))
		if existing != nil {
			var cur PermanentBlockEntry
			if json.Unmarshal(existing, &cur) == nil && !cur.Expired(time.Now()) {
				if cur.ExpiresAt.IsZero() {
					return nil
				}
				if !expiresAt.IsZero() && cur.ExpiresAt.After(expiresAt) {
					return nil
				}
			}
		}

		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(ip), val); err != nil {
			return err
		}
		if existing == nil {
			return incrCounter(tx, "threats:count", 1)
		}
		return nil
	})
}

// putThreatEntry writes an entry as-is. Only increments threats:count if
// the key is new. Migration uses it directly so flat-file rows keep their
// empty Source and stay subject to legacy classification in Expired;
// routing them through AddPermanentBlock would stamp them as operator rows
// and bless historical auto-block poison as permanent.
func (db *DB) putThreatEntry(entry PermanentBlockEntry) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))

		isNew := b.Get([]byte(entry.IP)) == nil

		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(entry.IP), val); err != nil {
			return err
		}

		if isNew {
			return incrCounter(tx, "threats:count", 1)
		}
		return nil
	})
}

// PruneExpiredThreats deletes threat entries whose lifetime has lapsed,
// including legacy no-source auto-block rows (see Expired). Returns the
// count removed. Collect-then-delete because bbolt forbids mutation during
// ForEach iteration.
func (db *DB) PruneExpiredThreats() int {
	var removed int
	now := time.Now()

	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))

		var toDelete [][]byte
		_ = b.ForEach(func(k, v []byte) error {
			var entry PermanentBlockEntry
			if json.Unmarshal(v, &entry) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			if entry.Expired(now) {
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				toDelete = append(toDelete, keyCopy)
			}
			return nil
		})

		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			removed++
		}

		if removed == 0 {
			return nil
		}
		// Clamp instead of blind decrement: a bulk prune of legacy rows
		// surfaces any historical counter drift at scale, and the counter
		// must never go negative.
		current := 0
		if v := tx.Bucket([]byte("meta")).Get([]byte("threats:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &current)
		}
		newCount := current - removed
		if newCount < 0 {
			newCount = 0
		}
		return setCounter(tx, "threats:count", newCount)
	})

	return removed
}

// RemovePermanentBlock removes an IP from the permanent block list and decrements the count.
func (db *DB) RemovePermanentBlock(ip string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))
		if b.Get([]byte(ip)) == nil {
			return nil
		}
		if err := b.Delete([]byte(ip)); err != nil {
			return err
		}
		return incrCounter(tx, "threats:count", -1)
	})
}

// RemoveAutoBlock deletes the threat row for ip only when it was written by
// the temporary auto-block path (Source == autoblock). Operator rows and
// legacy no-source rows are left untouched, so a firewall-only unblock never
// silently clears an operator's deliberate permanent block. Under
// block_expiry:0 an auto-block row has no expiry and would otherwise outlive
// the firewall block and keep re-flagging the IP via ip_reputation. Returns
// whether a row was removed. The read and delete run in one transaction so a
// concurrent upgrade to an operator row cannot be clobbered.
func (db *DB) RemoveAutoBlock(ip string) (bool, error) {
	removed := false
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))
		v := b.Get([]byte(ip))
		if v == nil {
			return nil
		}
		var entry PermanentBlockEntry
		if json.Unmarshal(v, &entry) != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		if entry.Source != ThreatSourceAutoBlock {
			return nil
		}
		if err := b.Delete([]byte(ip)); err != nil {
			return err
		}
		removed = true
		return incrCounter(tx, "threats:count", -1)
	})
	return removed, err
}

// GetPermanentBlock looks up a permanent block entry by IP.
// Returns the entry and true if found, or a zero value and false if not.
func (db *DB) GetPermanentBlock(ip string) (PermanentBlockEntry, bool) {
	var entry PermanentBlockEntry
	var found bool

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))
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

// AllPermanentBlocks returns all entries in the permanent block list
// (including expired ones - callers filter via Expired).
func (db *DB) AllPermanentBlocks() []PermanentBlockEntry {
	var entries []PermanentBlockEntry

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))
		return b.ForEach(func(k, v []byte) error {
			var entry PermanentBlockEntry
			if json.Unmarshal(v, &entry) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			entries = append(entries, entry)
			return nil
		})
	})

	return entries
}

// AddWhitelistEntry adds an IP to the whitelist.
func (db *DB) AddWhitelistEntry(ip string, expiresAt time.Time, permanent bool) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats:whitelist"))

		entry := WhitelistEntry{
			IP:        ip,
			ExpiresAt: expiresAt,
			Permanent: permanent,
		}
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(ip), val)
	})
}

// RemoveWhitelistEntry removes an IP from the whitelist.
func (db *DB) RemoveWhitelistEntry(ip string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats:whitelist"))
		return b.Delete([]byte(ip))
	})
}

// IsWhitelisted checks if an IP is whitelisted and not expired.
func (db *DB) IsWhitelisted(ip string) bool {
	var whitelisted bool

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats:whitelist"))
		v := b.Get([]byte(ip))
		if v == nil {
			return nil
		}
		var entry WhitelistEntry
		if json.Unmarshal(v, &entry) != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		if entry.Permanent || entry.ExpiresAt.After(time.Now()) {
			whitelisted = true
		}
		return nil
	})

	return whitelisted
}

// ListWhitelist returns all whitelist entries (including expired - caller filters).
func (db *DB) ListWhitelist() []WhitelistEntry {
	var entries []WhitelistEntry

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats:whitelist"))
		return b.ForEach(func(k, v []byte) error {
			var entry WhitelistEntry
			if json.Unmarshal(v, &entry) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			entries = append(entries, entry)
			return nil
		})
	})

	return entries
}

// PruneExpiredWhitelist deletes expired non-permanent whitelist entries.
// Returns the count of entries removed. Uses a collect-then-delete pattern
// because bbolt does not allow mutation during ForEach iteration.
func (db *DB) PruneExpiredWhitelist() int {
	var removed int
	now := time.Now()

	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats:whitelist"))

		// Collect keys to delete.
		var toDelete [][]byte
		_ = b.ForEach(func(k, v []byte) error {
			var entry WhitelistEntry
			if json.Unmarshal(v, &entry) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			if !entry.Permanent && !entry.ExpiresAt.After(now) {
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
