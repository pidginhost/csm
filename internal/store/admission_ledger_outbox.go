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
// the fixed notice records, charged to the reserve; no outcome is invented
// for earlier transitions. This upgrade completes the chain and records the
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
// audit row decodes under its own key and belongs to a recorded attempt,
// and the record counts exactly the rows stored.
func proveOutbox(tx *bolt.Tx, s admission.StorageState) error {
	fixed := map[admission.NoticeKey]bool{}
	for _, k := range admission.FixedNoticeKeys() {
		fixed[k] = true
	}
	var notices, rows uint64
	err := tx.Bucket([]byte(admissionOutboxBucket)).ForEach(func(k, v []byte) error {
		if v == nil || len(k) == 0 {
			return admission.ErrCorruptRecord
		}
		switch k[0] {
		case 'n':
			key, err := admission.ParseNoticeKey(k)
			if err != nil {
				return err
			}
			r, err := admission.UnmarshalNoticeRecord(v)
			if err != nil || r.Key != key {
				return admission.ErrCorruptRecord
			}
			delete(fixed, key)
			notices++
		case 'a':
			row, err := admission.UnmarshalAuditRow(v)
			if err != nil || !bytes.Equal(row.Key(), k) {
				return admission.ErrCorruptRecord
			}
			if _, err = loadAttempt(tx, row.Attempt.ID); err != nil {
				return corruptRecord(err)
			}
			rows++
		default:
			return admission.ErrCorruptRecord
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(fixed) != 0 || notices != s.NoticeRecords || rows != s.AuditSlots {
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
