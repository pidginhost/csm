package reporting

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
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
	db       *bolt.DB
	bucket   []byte
	max      int
	drain    sync.Mutex
	mutation sync.Mutex
	health   spoolHealth
}

// NewSpool opens (or creates) a spool at path with a per-node entry cap.
func NewSpool(path, bucket string, max int) (*Spool, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Spool{db: db, bucket: []byte(bucket), max: max, health: newSpoolHealth(max)}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		now := time.Now()
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			s.health.pending[string(k)] = &spoolWork{ticket: s.health.stats.Begin(now)}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database.
func (s *Spool) Close() error {
	s.mutation.Lock()
	defer s.mutation.Unlock()
	return s.db.Close()
}

// Enqueue appends a report body destined for target. When the queue exceeds its
// cap, the oldest entries are dropped (FIFO) and the dropped count is returned
// so the caller can surface it; reports are best-effort under sustained outage.
func (s *Spool) Enqueue(target string, body []byte) (dropped int, err error) {
	item := spoolItem{Target: target, Body: body}
	enc, err := json.Marshal(item)
	if err != nil {
		return 0, err
	}
	s.mutation.Lock()
	defer s.mutation.Unlock()
	ticket := s.health.stats.Begin(time.Now())
	ticket.Start(time.Now())
	var key [8]byte
	var evicted []string
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(s.bucket)
		seq, seqErr := b.NextSequence()
		if seqErr != nil {
			return seqErr
		}
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
			evicted = append(evicted, string(k))
			if e := b.Delete(k); e != nil {
				return e
			}
			count--
		}
		return nil
	})
	s.health.enqueueFailed.Store(err != nil)
	if err != nil {
		ticket.Reject(time.Now())
		return 0, err
	}
	s.applyEnqueue(string(key[:]), ticket, evicted)
	return len(evicted), nil
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
// removed when send returns nil. A send error pauses that item's target for
// the rest of the pass: the item and the target's later items stay queued, in
// order, for the next pass, while other targets keep draining. An item the
// collector refused as invalid (ErrReportRefused) is dropped, since the same
// body would be refused again; it counts as lost unless an earlier send of it
// was acknowledged. A spool read or removal
// failure stops the pass. Drain returns how many items were delivered and the
// failures it met.
func (s *Spool) Drain(send func(target string, body []byte) error) (delivered int, err error) {
	s.drain.Lock()
	defer s.drain.Unlock()

	paused := make(map[string]bool)
	refused := make(map[string]int)
	var failures []error
	// A paused target contributes one failure per pass; refusals are counted
	// per target so a burst of them stays one entry.
	result := func(extra error) error {
		errs := append(slices.Clone(failures), extra)
		for _, target := range slices.Sorted(maps.Keys(refused)) {
			errs = append(errs, fmt.Errorf("target %s: %d reports refused as invalid and dropped: %w",
				target, refused[target], ErrReportRefused))
		}
		return errors.Join(errs...)
	}
	var after []byte
	for {
		key, item, work, err := s.next(after, paused)
		if err != nil {
			return delivered, result(err)
		}
		if work == nil {
			// One target's success must not hide another target's stall.
			s.health.sendFailed.Store(len(paused) > 0)
			return delivered, result(nil)
		}
		after = key
		sendErr, ioErr := s.deliver(key, item, work, send)
		switch {
		case sendErr == nil:
		case errors.Is(sendErr, ErrReportRefused):
			// A refused item the spool failed to remove is still queued.
			if ioErr == nil {
				refused[item.Target]++
			}
		default:
			failures = append(failures, fmt.Errorf("target %s: %w", item.Target, sendErr))
			paused[item.Target] = true
		}
		if ioErr != nil {
			return delivered, result(ioErr)
		}
		if sendErr == nil {
			delivered++
		}
	}
}

// next returns the first queued item after the key `after` (from the start
// when nil) whose target is not paused in this pass.
func (s *Spool) next(after []byte, paused map[string]bool) (key []byte, item spoolItem, work *spoolWork, err error) {
	s.mutation.Lock()
	defer s.mutation.Unlock()
	empty := false
	err = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(s.bucket).Cursor()
		var k, v []byte
		if after == nil {
			k, v = c.First()
			empty = k == nil
		} else if k, v = c.Seek(after); k != nil && bytes.Equal(k, after) {
			k, v = c.Next()
		}
		for ; k != nil; k, v = c.Next() {
			var it spoolItem
			if decodeErr := json.Unmarshal(v, &it); decodeErr != nil {
				return decodeErr
			}
			if paused[it.Target] {
				continue
			}
			key, item = append([]byte(nil), k...), it
			return nil
		}
		return nil
	})
	s.health.readFailed.Store(err != nil)
	if err != nil {
		return nil, item, nil, err
	}
	if empty {
		s.health.sendFailed.Store(false)
		s.health.removeFailed.Store(false)
	}
	if key == nil {
		return nil, item, nil, nil
	}
	work = s.health.pending[string(key)]
	if work == nil {
		// The spool outlives the process that wrote it. A record with no
		// accounting still has to be delivered, so it is adopted here rather
		// than taken as an invariant.
		work = &spoolWork{ticket: s.health.stats.Begin(time.Now())}
		s.health.pending[string(key)] = work
	}
	work.ticket.Start(time.Now())
	s.health.active = work
	return key, item, work, nil
}

// deliver sends one item. sendErr is the collector's answer when it did not
// accept the item; a refused item is still removed. ioErr is a spool failure.
func (s *Spool) deliver(key []byte, item spoolItem, work *spoolWork, send func(string, []byte) error) (sendErr, ioErr error) {
	sent, refused, removed := false, false, false
	defer func() { s.finishDelivery(work, sent, refused, removed) }()
	if err := send(item.Target, item.Body); err != nil {
		if !errors.Is(err, ErrReportRefused) {
			return err, nil
		}
		refused, sendErr = true, err
	} else {
		sent = true
	}
	s.mutation.Lock()
	defer s.mutation.Unlock()
	if !work.evicted {
		err := s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(s.bucket).Delete(key)
		})
		s.health.removeFailed.Store(err != nil)
		if err != nil {
			return sendErr, err
		}
		delete(s.health.pending, string(key))
	}
	removed = true
	return sendErr, nil
}
