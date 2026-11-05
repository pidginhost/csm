package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// knownCustomersBucket maps an address to the last successful customer login
// seen from it.
const knownCustomersBucket = "customer:logins"

// A record names one address and holds one bounded mailbox name. Anything
// larger is damage and is skipped rather than decoded.
const (
	maxKnownCustomerKeyBytes   = 64
	maxKnownCustomerValueBytes = 2048
)

// KnownCustomer is the last successful customer login from one address.
type KnownCustomer struct {
	Kind    string    `json:"kind"`
	Account string    `json:"account,omitempty"`
	At      time.Time `json:"at"`
}

// SaveKnownCustomers writes upserts and removes deletes in one transaction.
func (db *DB) SaveKnownCustomers(upserts map[string]KnownCustomer, deletes []string) error {
	if len(upserts)+len(deletes) == 0 {
		return nil
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(knownCustomersBucket))
		if err != nil {
			return err
		}
		for _, ip := range deletes {
			if ip == "" {
				continue
			}
			if err := b.Delete([]byte(ip)); err != nil {
				return err
			}
		}
		for ip, c := range upserts {
			if ip == "" {
				continue
			}
			val, err := json.Marshal(c)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(ip), val); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadKnownCustomers returns every readable record. Validating addresses and
// ages is the caller's job; malformed and oversized records are skipped.
func (db *DB) LoadKnownCustomers() (map[string]KnownCustomer, error) {
	out := make(map[string]KnownCustomer)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(knownCustomersBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if len(k) == 0 || len(k) > maxKnownCustomerKeyBytes || len(v) > maxKnownCustomerValueBytes {
				return nil
			}
			var c KnownCustomer
			if json.Unmarshal(v, &c) == nil {
				out[string(k)] = c
			}
			return nil
		})
	})
	return out, err
}
