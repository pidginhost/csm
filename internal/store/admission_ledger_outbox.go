package store

import (
	"bytes"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func putNoticeRecord(tx *bolt.Tx, r admission.NoticeRecord) error {
	k, err := r.Key.Bytes()
	if err != nil {
		return err
	}
	data, err := r.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionOutboxBucket)).Put(k, data)
}

// putFixedNotices writes the empty records every ledger keeps: one
// overflow record per keyed kind and the two summaries.
func putFixedNotices(tx *bolt.Tx) error {
	for _, k := range admission.FixedNoticeKeys() {
		if err := putNoticeRecord(tx, admission.NewNoticeRecord(k)); err != nil {
			return err
		}
	}
	return nil
}

// upgradeLedgerToSchemaFive adds the outbox and the outcome buckets to a
// schema 4 ledger inside the opening transaction. The outbox starts with
// the fixed notice records, charged to the reserve, and holds the slots of
// the rows outstanding attempts may still write; no row or outcome is
// invented for earlier transitions. This upgrade completes the chain and records the
// schema.
func upgradeLedgerToSchemaFive(tx *bolt.Tx) error {
	for _, name := range admissionOutboxBuckets {
		if _, err := tx.CreateBucket([]byte(name)); err != nil {
			return err
		}
	}
	s, err := loadStorageState(tx)
	if err != nil {
		return err
	}
	s.NoticeRecords = admission.FixedNotices
	// Outstanding attempts will write the rows of their remaining steps.
	if err = tx.Bucket([]byte(admissionAttemptsBucket)).ForEach(func(_, v []byte) error {
		a, decodeErr := admission.UnmarshalAttempt(v)
		if decodeErr != nil {
			return decodeErr
		}
		s.AuditSlots += futureAuditSlots(a.State)
		return nil
	}); err != nil {
		return err
	}
	if err = putStorageState(tx, s); err != nil {
		return err
	}
	if err = putFixedNotices(tx); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion})
}

// proveOutbox checks every outbox row against the storage record: each
// notice record decodes under its own key and the fixed ones exist, each
// audit row decodes under its own key and belongs to a recorded attempt
// and a transition its candidate made, and the record counts exactly the
// rows stored and the slots outstanding attempts hold.
func proveOutbox(tx *bolt.Tx, s admission.StorageState) error {
	clock, clockErr := loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
	if clockErr != nil {
		return clockErr
	}
	now := clock.Now()
	fixed := map[admission.NoticeKey]bool{}
	for _, k := range admission.FixedNoticeKeys() {
		fixed[k] = true
	}
	var notices, rows uint64
	last := map[admission.ActionID]admission.AuditRow{}
	type transitions struct{ first, last uint32 }
	attempts := map[admission.CandidateID][admission.MaxAttempts]transitions{}
	quiet := map[admission.NoticeKey]time.Time{}
	var quietRecords int
	outbox := tx.Bucket([]byte(admissionOutboxBucket))
	err := outbox.ForEach(func(k, v []byte) error {
		if len(k) == 0 || outbox.Bucket(k) != nil {
			return admission.ErrCorruptRecord
		}
		switch k[0] {
		case 'q':
			at, key, err := admission.ParseQuietKey(k)
			if err != nil || len(v) != 0 {
				return admission.ErrCorruptRecord
			}
			if _, dup := quiet[key]; dup {
				return admission.ErrCorruptRecord
			}
			quiet[key] = at
		case 'n':
			key, err := admission.ParseNoticeKey(k)
			if err != nil {
				return err
			}
			r, err := admission.UnmarshalNoticeRecord(v)
			if err != nil || r.Key != key {
				return admission.ErrCorruptRecord
			}
			if r.Count > 0 && (now.IsZero() || r.Last.After(now) || r.Sent.After(now)) {
				return admission.ErrCorruptRecord
			}
			delete(fixed, key)
			if !r.QuietAt().IsZero() {
				quietRecords++
			}
			notices++
		case 'a':
			row, err := admission.UnmarshalAuditRow(v)
			if err != nil || !bytes.Equal(row.Key(), k) {
				return admission.ErrCorruptRecord
			}
			a, err := loadAttempt(tx, row.Attempt.ID)
			if err != nil {
				return corruptRecord(err)
			}
			c, err := loadCandidate(tx, row.Attempt.Candidate)
			if err != nil || row.Transition > c.Transitions {
				return admission.ErrCorruptRecord
			}
			if now.IsZero() || !auditStepMatches(row, a, c, now) {
				return admission.ErrCorruptRecord
			}
			if previous, found := last[row.Attempt.ID]; found && !auditFollows(previous, row) {
				return admission.ErrCorruptRecord
			}
			last[row.Attempt.ID] = row
			// Attempt IDs sort independently of lifecycle order. Their
			// transition ranges must still be disjoint and follow retries.
			bounds := attempts[row.Attempt.Candidate]
			for seq := uint32(1); seq <= admission.MaxAttempts; seq++ {
				bound := bounds[seq-1]
				if bound.first != 0 && ((seq < row.Attempt.Seq && bound.last >= row.Transition) ||
					(seq > row.Attempt.Seq && bound.first <= row.Transition)) {
					return admission.ErrCorruptRecord
				}
			}
			bound := &bounds[row.Attempt.Seq-1]
			if bound.first == 0 {
				bound.first = row.Transition
			}
			bound.last = row.Transition
			attempts[row.Attempt.Candidate] = bounds
			rows++
		default:
			return admission.ErrCorruptRecord
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The quiet index names exactly the records whose events were all
	// delivered, at the time each becomes quiet.
	if len(quiet) != quietRecords {
		return admission.ErrCorruptRecord
	}
	for key, at := range quiet {
		r, found, loadErr := loadNoticeRecord(tx, key)
		if loadErr != nil || !found || !r.QuietAt().Equal(at) {
			return admission.ErrCorruptRecord
		}
	}
	// Each attempt holds a slot for every row it wrote and every row it may
	// still write, and has written no more rows than steps it took.
	future := uint64(0)
	if err = tx.Bucket([]byte(admissionAttemptsBucket)).ForEach(func(_, v []byte) error {
		a, decodeErr := admission.UnmarshalAttempt(v)
		if decodeErr != nil {
			return decodeErr
		}
		future += futureAuditSlots(a.State)
		return nil
	}); err != nil {
		return err
	}
	if len(fixed) != 0 || notices != s.NoticeRecords || rows+future != s.AuditSlots {
		return admission.ErrCorruptRecord
	}
	return nil
}

// proveOutcomes checks every outcome bucket: it decodes, and it lies in
// its span's window at the stored clock. Before the first reading there is
// none.
func proveOutcomes(tx *bolt.Tx, now time.Time) error {
	return tx.Bucket([]byte(admissionWindowsBucket)).ForEach(func(k, v []byte) error {
		span, start, err := admission.ParseSpanKey(k)
		if err != nil {
			return err
		}
		if now.IsZero() || start.Before(span.Oldest(now)) || start.After(span.Start(now)) {
			return admission.ErrCorruptRecord
		}
		_, err = admission.UnmarshalOutcomeCounts(v)
		return err
	})
}

// flushOutcomes adds the transaction's counted events to the bucket of
// each span that holds the transaction's time.
func (q *queueTx) flushOutcomes() error {
	if len(q.outcomes.Rows()) == 0 {
		return nil
	}
	windows := q.tx.Bucket([]byte(admissionWindowsBucket))
	for _, span := range admission.Spans() {
		k := span.Key(span.Start(q.now))
		var c admission.OutcomeCounts
		if raw := windows.Get(k); raw != nil {
			var err error
			if c, err = admission.UnmarshalOutcomeCounts(raw); err != nil {
				return err
			}
		}
		c.Merge(q.outcomes)
		data, err := c.MarshalBinary()
		if err != nil {
			return err
		}
		if err = windows.Put(k, data); err != nil {
			return err
		}
	}
	return nil
}

// pruneOutcomes drops the buckets that have left their span's window at
// now. Each span keeps a bounded number of buckets, so this is bounded.
func pruneOutcomes(tx *bolt.Tx, now time.Time) error {
	cur := tx.Bucket([]byte(admissionWindowsBucket)).Cursor()
	for _, span := range admission.Spans() {
		oldest := span.Key(span.Oldest(now))
		prefix := oldest[:2]
		for k, _ := cur.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix) && bytes.Compare(k, oldest) < 0; k, _ = cur.Seek(prefix) {
			if err := cur.Delete(); err != nil {
				return err
			}
		}
	}
	return nil
}
