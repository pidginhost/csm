package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// maxAttackEvents is the maximum number of attack events to retain.
// It is a var (not const) so tests can override it.
var maxAttackEvents = 100_000

// AttackEvent is the store-layer representation of an attack event.
type AttackEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	IP         string    `json:"ip"`
	AttackType string    `json:"attack_type"`
	CheckName  string    `json:"check_name"`
	Severity   int       `json:"severity"`
	Account    string    `json:"account,omitempty"`
	Message    string    `json:"message,omitempty"`
}

// IPRecord is the store-layer representation of an IP attack record.
type IPRecord struct {
	IP           string         `json:"ip"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	EventCount   int            `json:"event_count"`
	AttackCounts map[string]int `json:"attack_counts,omitempty"`
	Accounts     map[string]int `json:"accounts,omitempty"`
	ThreatScore  int            `json:"threat_score"`
	AutoBlocked  bool           `json:"auto_blocked,omitempty"`
}

// RecordAttackEvent inserts an attack event into both the primary bucket
// (attacks:events, keyed by TimeKey) and the secondary index bucket
// (attacks:events:ip, keyed by IP/TimeKey). It increments the event counter
// and prunes oldest entries if the count exceeds maxAttackEvents.
func (db *DB) RecordAttackEvent(event AttackEvent, counter int) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		primary := tx.Bucket([]byte("attacks:events"))
		secondary := tx.Bucket([]byte("attacks:events:ip"))

		key := TimeKey(event.Timestamp, counter)
		val, err := json.Marshal(event)
		if err != nil {
			return err
		}

		if err := primary.Put([]byte(key), val); err != nil {
			return err
		}

		secondaryKey := event.IP + "/" + key
		if err := secondary.Put([]byte(secondaryKey), val); err != nil {
			return err
		}

		if err := incrCounter(tx, "attacks:events:count", 1); err != nil {
			return err
		}

		// Prune oldest entries if count exceeds maxAttackEvents.
		meta := tx.Bucket([]byte("meta"))
		var count int
		if v := meta.Get([]byte("attacks:events:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
		}

		if count > maxAttackEvents {
			excess := count - maxAttackEvents
			c := primary.Cursor()
			k, v := c.First()
			for ; k != nil && excess > 0; excess-- {
				// Unmarshal to get the IP for secondary index cleanup.
				var ev AttackEvent
				if err := json.Unmarshal(v, &ev); err != nil {
					return err
				}
				secKey := ev.IP + "/" + string(k)
				if err := secondary.Delete([]byte(secKey)); err != nil {
					return err
				}

				if err := c.Delete(); err != nil {
					return err
				}
				// Re-seek after delete (bbolt cursor behavior).
				k, v = c.First()
			}
			if err := setCounter(tx, "attacks:events:count", maxAttackEvents); err != nil {
				return err
			}
		}

		return nil
	})
}

// QueryAttackEvents returns up to limit attack events for the given IP,
// newest-first. It uses the secondary index bucket for efficient prefix-based
// iteration.
func (db *DB) QueryAttackEvents(ip string, limit int) []AttackEvent {
	var results []AttackEvent
	prefix := []byte(ip + "/")

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("attacks:events:ip"))
		c := b.Cursor()

		// Collect all events matching the prefix.
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var ev AttackEvent
			if err := json.Unmarshal(v, &ev); err == nil {
				results = append(results, ev)
			}
		}

		return nil
	})

	// Reverse for newest-first order.
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}

	// Take up to limit.
	if len(results) > limit {
		results = results[:limit]
	}

	return results
}

// SaveIPRecord stores an IP record in the attacks:records bucket, keyed by IP.
func (db *DB) SaveIPRecord(record IPRecord) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("attacks:records"))
		val, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return b.Put([]byte(record.IP), val)
	})
}

// LoadIPRecord retrieves an IP record from the attacks:records bucket.
// Returns the record and true if found, or a zero value and false if not.
func (db *DB) LoadIPRecord(ip string) (IPRecord, bool) {
	var record IPRecord
	var found bool

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("attacks:records"))
		v := b.Get([]byte(ip))
		if v == nil {
			return nil
		}
		if json.Unmarshal(v, &record) != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		found = true
		return nil
	})

	return record, found
}

// LoadAllIPRecords returns all IP records from the attacks:records bucket.
func (db *DB) LoadAllIPRecords() map[string]*IPRecord {
	records := make(map[string]*IPRecord)

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("attacks:records"))
		return b.ForEach(func(k, v []byte) error {
			var record IPRecord
			if json.Unmarshal(v, &record) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			records[string(k)] = &record
			return nil
		})
	})

	return records
}

// DeleteIPRecord removes an IP record from the attacks:records bucket.
func (db *DB) DeleteIPRecord(ip string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("attacks:records"))
		return b.Delete([]byte(ip))
	})
}

// ReadAllAttackEvents returns all attack events from the primary bucket.
// Used for stats computation (hourly/daily bucketing).
func (db *DB) ReadAllAttackEvents() []AttackEvent {
	var events []AttackEvent
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("attacks:events"))
		return b.ForEach(func(k, v []byte) error {
			var ev AttackEvent
			if json.Unmarshal(v, &ev) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			events = append(events, ev)
			return nil
		})
	})
	return events
}
