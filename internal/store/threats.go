package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// PermanentBlockEntry represents an IP permanently blocked by the threat system.
type PermanentBlockEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
}

// WhitelistEntry represents an IP that should bypass threat checks.
type WhitelistEntry struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
	Permanent bool      `json:"permanent"`
}

// AddPermanentBlock adds an IP to the permanent block list.
// Only increments threats:count if the key is new.
func (db *DB) AddPermanentBlock(ip, reason string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))

		isNew := b.Get([]byte(ip)) == nil

		entry := PermanentBlockEntry{
			IP:        ip,
			Reason:    reason,
			BlockedAt: time.Now(),
		}
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(ip), val); err != nil {
			return err
		}

		if isNew {
			return incrCounter(tx, "threats:count", 1)
		}
		return nil
	})
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

// AllPermanentBlocks returns all entries in the permanent block list.
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
