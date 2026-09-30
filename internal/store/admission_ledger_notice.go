package store

import (
	"errors"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// quietRemovalsPerTick bounds the quiet notice records one Tick removes.
const quietRemovalsPerTick = 64

func loadNoticeRecord(tx *bolt.Tx, k admission.NoticeKey) (admission.NoticeRecord, bool, error) {
	kb, err := k.Bytes()
	if err != nil {
		return admission.NoticeRecord{}, false, err
	}
	raw := tx.Bucket([]byte(admissionOutboxBucket)).Get(kb)
	if raw == nil {
		return admission.NoticeRecord{}, false, nil
	}
	r, err := admission.UnmarshalNoticeRecord(raw)
	if err != nil || r.Key != k {
		return admission.NoticeRecord{}, false, admission.ErrCorruptRecord
	}
	return r, true, nil
}

// storeNoticeRecord writes r after old, keeping the quiet index in step:
// a record is indexed while all its events are delivered.
func storeNoticeRecord(tx *bolt.Tx, old, r admission.NoticeRecord) error {
	outbox := tx.Bucket([]byte(admissionOutboxBucket))
	if at := old.QuietAt(); !at.IsZero() {
		k, err := admission.QuietKey(at, old.Key)
		if err != nil {
			return err
		}
		if outbox.Get(k) == nil {
			return admission.ErrCorruptRecord
		}
		if err = outbox.Delete(k); err != nil {
			return err
		}
	}
	if at := r.QuietAt(); !at.IsZero() {
		k, err := admission.QuietKey(at, r.Key)
		if err != nil {
			return err
		}
		if err = outbox.Put(k, []byte{}); err != nil {
			return err
		}
	}
	return putNoticeRecord(tx, r)
}

// raise records one notice event under key: in its own record, or, when a
// new key finds no room in the notice share, in its kind's overflow
// record. A Critical event also counts in the Critical summary. A zero
// candidate names no example.
func (q *queueTx) raise(key admission.NoticeKey, id admission.CandidateID, transitions uint32) error {
	return q.notify(key, func(r admission.NoticeRecord) (admission.NoticeRecord, error) {
		return r.Add(q.now, id, transitions)
	})
}

// raiseCount records n events under key without examples, as raise does.
func (q *queueTx) raiseCount(key admission.NoticeKey, n uint64) error {
	return q.notify(key, func(r admission.NoticeRecord) (admission.NoticeRecord, error) {
		return r.AddCount(q.now, n)
	})
}

func (q *queueTx) notify(key admission.NoticeKey, add func(admission.NoticeRecord) (admission.NoticeRecord, error)) error {
	r, found, err := loadNoticeRecord(q.tx, key)
	if err != nil {
		return err
	}
	if !found {
		if key.Fixed() {
			return admission.ErrCorruptRecord
		}
		// A damaged storage record cannot pay for a new record, but the
		// transition may still be one allowed over it (1.3b-4 decision
		// 10): the event then counts in the fixed overflow record.
		allocated, allocErr := q.allocateNotice()
		if allocErr != nil && !errors.Is(allocErr, admission.ErrCorruptRecord) {
			return allocErr
		}
		if allocated {
			r = admission.NewNoticeRecord(key)
		} else if r, found, err = loadNoticeRecord(q.tx, admission.OverflowKey(key.Kind)); err != nil || !found {
			return admission.ErrCorruptRecord
		}
	}
	next, err := add(r)
	if err != nil {
		return err
	}
	if err = storeNoticeRecord(q.tx, r, next); err != nil {
		return err
	}
	if !key.Kind.Critical() {
		return nil
	}
	return q.notify(admission.NoticeKey{Kind: admission.NoticeCriticalSummary}, add)
}

// allocateNotice charges a new notice record to the notice share when the
// share and the reserve's room both allow it. The share is checked first:
// the room walks every live candidate.
func (q *queueTx) allocateNotice() (bool, error) {
	s, err := q.storageState()
	if err != nil {
		return false, err
	}
	next, ok := s.AddNotice()
	if !ok {
		return false, nil
	}
	room, err := q.recoveryRoom()
	if err != nil || room < admission.NoticeSlotBytes {
		return false, err
	}
	*s, q.storageDirty = next, true
	return true, nil
}

// noticeCheck is the check of c's highest-severity root, the lexically
// first on a tie: the check that made the work as severe as it is.
func noticeCheck(tx *bolt.Tx, c admission.Candidate) (string, error) {
	var check string
	var sev admission.Severity
	for _, id := range c.Roots {
		e, err := loadStoredEvidence(tx, id)
		if err != nil {
			return "", corruptRecord(err)
		}
		if e.Severity() > sev || (e.Severity() == sev && e.Check() < check) {
			check, sev = e.Check(), e.Severity()
		}
	}
	return check, nil
}

// gap raises the notice an event of candidate c raises, if any (spec
// 5.17). transitions is c's count after the event.
func (q *queueTx) gap(event admission.GapEvent, reason admission.Reason, outcome admission.Disposition, entry admission.QueueEntry, id admission.CandidateID, c admission.Candidate, transitions uint32) error {
	kind := admission.GapNotice(event, reason, outcome, entry.Tier)
	if kind == 0 {
		return nil
	}
	check, err := noticeCheck(q.tx, c)
	if err != nil {
		return err
	}
	return q.raise(admission.NoticeKey{Kind: kind, Reason: reason, Outcome: outcome, Check: check, Effect: c.Key.Kind.Effect()}, id, transitions)
}

// removeQuietNotices removes keyed records whose events were all delivered
// an interval ago, oldest first, at most quietRemovalsPerTick.
func (q *queueTx) removeQuietNotices() error {
	outbox := q.tx.Bucket([]byte(admissionOutboxBucket))
	cur := outbox.Cursor()
	for n := 0; n < quietRemovalsPerTick; n++ {
		k, _ := cur.Seek([]byte{'q'})
		if k == nil || k[0] != 'q' {
			return nil
		}
		at, key, err := admission.ParseQuietKey(k)
		if err != nil {
			return err
		}
		if at.After(q.now) {
			return nil
		}
		r, found, err := loadNoticeRecord(q.tx, key)
		if err != nil {
			return err
		}
		if !found || !r.QuietAt().Equal(at) {
			return admission.ErrCorruptRecord
		}
		kb, _ := key.Bytes()
		if err = cur.Delete(); err != nil {
			return err
		}
		if err = outbox.Delete(kb); err != nil {
			return err
		}
		s, err := q.storageState()
		if err != nil {
			return err
		}
		if *s, err = s.RemoveNotice(); err != nil {
			return err
		}
		q.storageDirty = true
	}
	return nil
}

// PendingNotices returns the notice records due at the stored admission
// time: a key at most once an hour, each summary at most once a minute.
// The sender delivers them and acknowledges what it delivered.
func (l *AdmissionLedger) PendingNotices() ([]admission.NoticeRecord, error) {
	var due []admission.NoticeRecord
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		clock, err := loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
		if err != nil {
			return err
		}
		cur := tx.Bucket([]byte(admissionOutboxBucket)).Cursor()
		for k, v := cur.Seek([]byte{'n'}); k != nil && k[0] == 'n'; k, v = cur.Next() {
			key, err := admission.ParseNoticeKey(k)
			if err != nil {
				return err
			}
			r, err := admission.UnmarshalNoticeRecord(v)
			if err != nil || r.Key != key {
				return admission.ErrCorruptRecord
			}
			if r.Due(clock.Now()) {
				due = append(due, r)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return due, nil
}

// AckNotices records deliveries in one transaction, each covering the
// count it names; events that arrived after the read stay pending. A
// record already removed is skipped.
func (l *AdmissionLedger) AckNotices(acks []admission.NoticeAck) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.recordedClock()
	if err != nil {
		return err
	}
	return l.update("notices", func(tx *bolt.Tx) error {
		for _, a := range acks {
			r, found, err := loadNoticeRecord(tx, a.Key)
			if err != nil {
				return err
			}
			if !found || !r.First.Equal(a.First) {
				continue
			}
			next, err := r.Ack(a.Count, now)
			if err != nil {
				return err
			}
			if err = storeNoticeRecord(tx, r, next); err != nil {
				return err
			}
		}
		return nil
	})
}
