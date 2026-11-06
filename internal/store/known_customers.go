package store

import (
	"container/heap"
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// knownCustomersBucket maps an address to the last successful customer login
// seen from it.
const knownCustomersBucket = "customer:logins"

// maxKnownCustomerRecords bounds a load: the daemon's set and as many again
// waiting for deletion.
const maxKnownCustomerRecords = 100000

// A record names one address and holds one bounded mailbox name. Anything
// larger is damage and is not decoded.
const (
	maxKnownCustomerKeyBytes   = 64
	maxKnownCustomerValueBytes = 2048
)

// KnownCustomer is the last successful customer login from one address.
// Syslog marks a login read from syslog rather than from a log only the
// service writes.
type KnownCustomer struct {
	Kind    string    `json:"kind"`
	Account string    `json:"account,omitempty"`
	At      time.Time `json:"at"`
	Syslog  bool      `json:"syslog,omitempty"`
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

// LoadKnownCustomers returns the newest readable records, at most
// maxKnownCustomerRecords. Validating addresses and ages is the caller's job.
// Malformed, oversized and older records are deleted, so the bucket stays
// bounded; the records are still returned when that deletion fails.
func (db *DB) LoadKnownCustomers() (map[string]KnownCustomer, error) {
	var kept knownCustomerHeap
	var drop [][]byte
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(knownCustomersBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			c, ok := decodeKnownCustomer(k, v)
			if !ok {
				drop = append(drop, append([]byte(nil), k...))
				return nil
			}
			heap.Push(&kept, knownCustomerRecord{string(k), c})
			if kept.Len() > maxKnownCustomerRecords {
				drop = append(drop, []byte(heap.Pop(&kept).(knownCustomerRecord).ip))
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]KnownCustomer, kept.Len())
	for _, r := range kept {
		out[r.ip] = r.c
	}
	if len(drop) > 0 {
		err = db.bolt.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(knownCustomersBucket))
			for _, k := range drop {
				if derr := b.Delete(k); derr != nil {
					return derr
				}
			}
			return nil
		})
	}
	return out, err
}

// decodeKnownCustomer reads one record, refusing one too large to be ours.
func decodeKnownCustomer(k, v []byte) (KnownCustomer, bool) {
	var c KnownCustomer
	if len(k) > maxKnownCustomerKeyBytes || len(v) > maxKnownCustomerValueBytes {
		return c, false
	}
	return c, json.Unmarshal(v, &c) == nil
}

type knownCustomerRecord struct {
	ip string
	c  KnownCustomer
}

// knownCustomerHeap keeps the oldest record on top, so a full heap drops it.
type knownCustomerHeap []knownCustomerRecord

func (h knownCustomerHeap) Len() int { return len(h) }
func (h knownCustomerHeap) Less(i, j int) bool {
	if c := h[i].c.At.Compare(h[j].c.At); c != 0 {
		return c < 0
	}
	return h[i].ip < h[j].ip
}
func (h knownCustomerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *knownCustomerHeap) Push(x any)   { *h = append(*h, x.(knownCustomerRecord)) }
func (h *knownCustomerHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}
