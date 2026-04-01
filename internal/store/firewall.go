package store

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// FWBlockedEntry represents an IP blocked by the firewall.
type FWBlockedEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"` // zero = permanent
}

// FWAllowedEntry represents an IP explicitly allowed through the firewall.
type FWAllowedEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Port      int       `json:"port"`       // 0 = all ports
	ExpiresAt time.Time `json:"expires_at"` // zero = permanent
}

// FWSubnetEntry represents a subnet added to the firewall.
type FWSubnetEntry struct {
	CIDR    string    `json:"cidr"`
	Reason  string    `json:"reason"`
	AddedAt time.Time `json:"added_at"`
}

// FWPortAllowEntry represents a per-IP port allow rule.
type FWPortAllowEntry struct {
	Key    string `json:"key"` // IP:port/proto
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Reason string `json:"reason"`
}

// FirewallState holds the full state across all 4 firewall buckets.
type FirewallState struct {
	Blocked     []FWBlockedEntry
	Allowed     []FWAllowedEntry
	Subnets     []FWSubnetEntry
	PortAllowed []FWPortAllowEntry
}

// portAllowKey returns the composite key "IP:port/proto".
func portAllowKey(ip string, port int, proto string) string {
	return fmt.Sprintf("%s:%d/%s", ip, port, proto)
}

// BlockIP adds an IP to the fw:blocked bucket.
func (db *DB) BlockIP(ip, reason string, expiresAt time.Time) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:blocked"))
		entry := FWBlockedEntry{
			IP:        ip,
			Reason:    reason,
			BlockedAt: time.Now(),
			ExpiresAt: expiresAt,
		}
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(ip), val)
	})
}

// UnblockIP removes an IP from the fw:blocked bucket.
func (db *DB) UnblockIP(ip string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:blocked"))
		return b.Delete([]byte(ip))
	})
}

// GetBlockedIP looks up a blocked IP. Returns false if not found or expired.
func (db *DB) GetBlockedIP(ip string) (FWBlockedEntry, bool) {
	var entry FWBlockedEntry
	var found bool

	db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:blocked"))
		v := b.Get([]byte(ip))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &entry); err != nil {
			return nil
		}
		// Filter expired entries (zero ExpiresAt = permanent).
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(time.Now()) {
			return nil
		}
		found = true
		return nil
	})

	return entry, found
}

// AllowIP adds an IP to the fw:allowed bucket.
func (db *DB) AllowIP(ip, reason string, expiresAt time.Time) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:allowed"))
		entry := FWAllowedEntry{
			IP:        ip,
			Reason:    reason,
			ExpiresAt: expiresAt,
		}
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(ip), val)
	})
}

// RemoveAllow removes an IP from the fw:allowed bucket.
func (db *DB) RemoveAllow(ip string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:allowed"))
		return b.Delete([]byte(ip))
	})
}

// AddSubnet adds a CIDR to the fw:subnets bucket.
func (db *DB) AddSubnet(cidr, reason string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:subnets"))
		entry := FWSubnetEntry{
			CIDR:    cidr,
			Reason:  reason,
			AddedAt: time.Now(),
		}
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(cidr), val)
	})
}

// RemoveSubnet removes a CIDR from the fw:subnets bucket.
func (db *DB) RemoveSubnet(cidr string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:subnets"))
		return b.Delete([]byte(cidr))
	})
}

// AddPortAllow adds a per-IP port allow rule to the fw:port_allowed bucket.
func (db *DB) AddPortAllow(ip string, port int, proto, reason string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:port_allowed"))
		key := portAllowKey(ip, port, proto)
		entry := FWPortAllowEntry{
			Key:    key,
			IP:     ip,
			Port:   port,
			Proto:  proto,
			Reason: reason,
		}
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), val)
	})
}

// RemovePortAllow removes a per-IP port allow rule from the fw:port_allowed bucket.
func (db *DB) RemovePortAllow(ip string, port int, proto string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:port_allowed"))
		key := portAllowKey(ip, port, proto)
		return b.Delete([]byte(key))
	})
}

// ListPortAllows returns all entries in the fw:port_allowed bucket.
func (db *DB) ListPortAllows() []FWPortAllowEntry {
	var entries []FWPortAllowEntry

	db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:port_allowed"))
		return b.ForEach(func(k, v []byte) error {
			var entry FWPortAllowEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return nil
			}
			entries = append(entries, entry)
			return nil
		})
	})

	return entries
}

// LoadFirewallState reads all 4 firewall buckets and assembles a FirewallState.
// Expired blocked entries are filtered out.
func (db *DB) LoadFirewallState() FirewallState {
	var state FirewallState
	now := time.Now()

	db.bolt.View(func(tx *bolt.Tx) error {
		// fw:blocked — filter expired
		blocked := tx.Bucket([]byte("fw:blocked"))
		blocked.ForEach(func(k, v []byte) error {
			var entry FWBlockedEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return nil
			}
			if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
				return nil // expired
			}
			state.Blocked = append(state.Blocked, entry)
			return nil
		})

		// fw:allowed
		allowed := tx.Bucket([]byte("fw:allowed"))
		allowed.ForEach(func(k, v []byte) error {
			var entry FWAllowedEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return nil
			}
			state.Allowed = append(state.Allowed, entry)
			return nil
		})

		// fw:subnets
		subnets := tx.Bucket([]byte("fw:subnets"))
		subnets.ForEach(func(k, v []byte) error {
			var entry FWSubnetEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return nil
			}
			state.Subnets = append(state.Subnets, entry)
			return nil
		})

		// fw:port_allowed
		portAllowed := tx.Bucket([]byte("fw:port_allowed"))
		portAllowed.ForEach(func(k, v []byte) error {
			var entry FWPortAllowEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return nil
			}
			state.PortAllowed = append(state.PortAllowed, entry)
			return nil
		})

		return nil
	})

	return state
}
