package reporting

import (
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// spoolItem is one queued report: the destination target name and the exact
// minimized body bytes to sign and send.
type spoolItem struct {
	Target string `json:"t"`
	Body   []byte `json:"b"`
}

// Spool is a durable, bounded outbound queue for reports, backed by bbolt so a
// down collector or a daemon restart does not drop confirmed-abuse reports.
type Spool struct {
	db     *bolt.DB
	bucket []byte
	max    int
	drain  sync.Mutex
}

// NewSpool opens (or creates) a spool at path with a per-node entry cap.
func NewSpool(path, bucket string, max int) (*Spool, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Spool{db: db, bucket: []byte(bucket), max: max}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(s.bucket)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database.
func (s *Spool) Close() error { return s.db.Close() }

// Enqueue appends a report body destined for target. When the queue exceeds its
// cap, the oldest entries are dropped (FIFO) and the dropped count is returned
// so the caller can surface it; reports are best-effort under sustained outage.
func (s *Spool) Enqueue(target string, body []byte) (dropped int, err error) {
	item := spoolItem{Target: target, Body: body}
	enc, err := json.Marshal(item)
	if err != nil {
		return 0, err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(s.bucket)
		seq, seqErr := b.NextSequence()
		if seqErr != nil {
			return seqErr
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], seq)
		if e := b.Put(key[:], enc); e != nil {
			return e
		}
		// Count current keys via the cursor; Bucket.Stats is not reliable for
		// pending changes inside the same write transaction.
		count := 0
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			count++
		}
		// Trim from the front (oldest keys sort first) until within cap.
		for count > s.max {
			tc := b.Cursor()
			k, _ := tc.First()
			if k == nil {
				break
			}
			if e := b.Delete(k); e != nil {
				return e
			}
			count--
			dropped++
		}
		return nil
	})
	return dropped, err
}

// Len returns the number of queued items.
func (s *Spool) Len() int {
	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(s.bucket).Stats().KeyN
		return nil
	})
	return n
}

// Drain processes queued items in FIFO order, calling send for each. An item is
// removed only when send returns nil; on the first send error Drain stops and
// leaves that item (and the rest) for a later retry, preserving order. It
// returns how many were delivered.
func (s *Spool) Drain(send func(target string, body []byte) error) (delivered int, err error) {
	s.drain.Lock()
	defer s.drain.Unlock()

	for {
		var (
			key  []byte
			item spoolItem
			has  bool
		)
		if e := s.db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket(s.bucket).Cursor()
			k, v := c.First()
			if k == nil {
				return nil
			}
			key = append([]byte(nil), k...)
			has = true
			return json.Unmarshal(v, &item)
		}); e != nil {
			return delivered, e
		}
		if !has {
			return delivered, nil
		}
		if e := send(item.Target, item.Body); e != nil {
			return delivered, e // keep this item; retry later
		}
		if e := s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(s.bucket).Delete(key)
		}); e != nil {
			return delivered, e
		}
		delivered++
	}
}
