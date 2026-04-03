package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

const modsecNoEscalateKey = "modsec:no_escalate_rules"

// GetModSecNoEscalateRules returns the set of ModSecurity rule IDs that should
// NOT escalate to nftables firewall blocks. Stored in the meta bucket.
func (db *DB) GetModSecNoEscalateRules() map[int]bool {
	rules := make(map[int]bool)
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte("meta")).Get([]byte(modsecNoEscalateKey))
		if v == nil {
			return nil
		}
		var ids []int
		if json.Unmarshal(v, &ids) != nil {
			return nil //nolint:nilerr // skip corrupt data
		}
		for _, id := range ids {
			rules[id] = true
		}
		return nil
	})
	return rules
}

// SetModSecNoEscalateRules stores the set of rule IDs that should not escalate.
func (db *DB) SetModSecNoEscalateRules(rules map[int]bool) error {
	var ids []int
	for id := range rules {
		ids = append(ids, id)
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		val, err := json.Marshal(ids)
		if err != nil {
			return err
		}
		return tx.Bucket([]byte("meta")).Put([]byte(modsecNoEscalateKey), val)
	})
}

// AddModSecNoEscalateRule atomically adds a single rule ID to the no-escalate set.
// Read-modify-write happens in a single bbolt Update transaction to prevent races.
func (db *DB) AddModSecNoEscalateRule(ruleID int) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		var ids []int
		if v := b.Get([]byte(modsecNoEscalateKey)); v != nil {
			_ = json.Unmarshal(v, &ids)
		}
		for _, id := range ids {
			if id == ruleID {
				return nil // already present
			}
		}
		ids = append(ids, ruleID)
		val, err := json.Marshal(ids)
		if err != nil {
			return err
		}
		return b.Put([]byte(modsecNoEscalateKey), val)
	})
}

// RemoveModSecNoEscalateRule atomically removes a single rule ID from the no-escalate set.
func (db *DB) RemoveModSecNoEscalateRule(ruleID int) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		var ids []int
		if v := b.Get([]byte(modsecNoEscalateKey)); v != nil {
			_ = json.Unmarshal(v, &ids)
		}
		var filtered []int
		for _, id := range ids {
			if id != ruleID {
				filtered = append(filtered, id)
			}
		}
		val, err := json.Marshal(filtered)
		if err != nil {
			return err
		}
		return b.Put([]byte(modsecNoEscalateKey), val)
	})
}

// RuleHitStats holds hit count and last-hit time for a ModSecurity rule.
type RuleHitStats struct {
	Hits    int       `json:"hits"`
	LastHit time.Time `json:"last_hit"`
}

type ruleHitData struct {
	Buckets map[string]int `json:"buckets"` // key: "YYYYMMDDHH" → count
	LastHit time.Time      `json:"last_hit"`
}

func modsecHitKey(ruleID int) string {
	return fmt.Sprintf("modsec:hits:%d", ruleID)
}

func hourBucket(t time.Time) string {
	return fmt.Sprintf("%04d%02d%02d%02d", t.Year(), t.Month(), t.Day(), t.Hour())
}

// IncrModSecRuleHit increments the hit counter for a rule ID in the current hour bucket.
func (db *DB) IncrModSecRuleHit(ruleID int, timestamp time.Time) {
	key := modsecHitKey(ruleID)
	bucket := hourBucket(timestamp)

	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		var data ruleHitData
		if v := b.Get([]byte(key)); v != nil {
			if json.Unmarshal(v, &data) != nil {
				data = ruleHitData{Buckets: make(map[string]int)}
			}
		} else {
			data = ruleHitData{Buckets: make(map[string]int)}
		}

		data.Buckets[bucket]++
		data.LastHit = timestamp

		val, err := json.Marshal(data)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), val)
	})
}

// GetModSecRuleHits returns hit counts and last-hit timestamps for all rules
// within the last 24 hours. Prunes buckets older than 24h.
// Note: hourly bucket granularity means the window is 24h +/- 1h at boundaries.
func (db *DB) GetModSecRuleHits() map[int]RuleHitStats {
	result := make(map[int]RuleHitStats)
	cutoff := time.Now().Add(-24 * time.Hour)
	cutoffBucket := hourBucket(cutoff)
	prefix := []byte("modsec:hits:")

	// Track which keys need pruning — read first with View (no write lock),
	// then prune in a separate Update only if needed.
	type pruneItem struct {
		key  []byte
		data ruleHitData
	}
	var toPrune []pruneItem

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		c := b.Cursor()

		for k, v := c.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			idStr := string(k[len(prefix):])
			ruleID, err := strconv.Atoi(idStr)
			if err != nil {
				continue
			}

			var data ruleHitData
			if json.Unmarshal(v, &data) != nil {
				continue
			}

			total := 0
			needsPrune := false
			for bk, count := range data.Buckets {
				if bk >= cutoffBucket {
					total += count
				} else {
					needsPrune = true
				}
			}

			if needsPrune {
				// Deep copy key (bbolt keys are only valid inside tx)
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				toPrune = append(toPrune, pruneItem{key: keyCopy, data: data})
			}

			if total > 0 || !data.LastHit.IsZero() {
				result[ruleID] = RuleHitStats{
					Hits:    total,
					LastHit: data.LastHit,
				}
			}
		}
		return nil
	})

	// Prune old buckets in a separate write transaction (only if needed)
	if len(toPrune) > 0 {
		_ = db.bolt.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("meta"))
			for _, item := range toPrune {
				for bk := range item.data.Buckets {
					if bk < cutoffBucket {
						delete(item.data.Buckets, bk)
					}
				}
				val, _ := json.Marshal(item.data)
				_ = b.Put(item.key, val)
			}
			return nil
		})
	}

	return result
}
