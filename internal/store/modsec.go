package store

import (
	"encoding/json"

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
