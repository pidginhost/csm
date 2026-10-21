package store

import (
	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// liveStartKey holds the live start record in the queue state bucket.
var liveStartKey = []byte("live_start")

func loadLiveStart(tx *bolt.Tx) (admission.LiveStart, bool, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(liveStartKey)
	schema := tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey)
	if len(schema) != 1 || (schema[0] >= admissionSchemaLive) != (raw != nil) {
		return admission.LiveStart{}, false, admission.ErrCorruptRecord
	}
	if raw == nil {
		return admission.LiveStart{}, false, nil
	}
	s, err := admission.UnmarshalLiveStart(raw)
	return s, err == nil, err
}

// LiveStarted reports whether the ledger's live start ran.
func (l *AdmissionLedger) LiveStarted() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.live
}

// StartLive runs the live start (design C7) once, when the owner first
// executes, in one transaction: it carries the legacy hour's count over as
// the greater of that count and the charges retained in its hour, counts
// each legacy pending entry as refused for attribution, ends the answers
// of earlier observe previews, clears the notices raised while admission
// previewed, makes the previews' history eligible, and records the start
// under the schema that older builds refuse. A ledger that has
// started refuses with ErrTransitionConflict. It needs a reading this
// handle recorded.
func (l *AdmissionLedger) StartLive(h admission.LegacyHandover) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.live {
		return admission.ErrTransitionConflict
	}
	now, clockErr := l.clock()
	if clockErr != nil {
		return clockErr
	}
	err := l.update("live start", func(tx *bolt.Tx) error {
		if _, found, loadErr := loadLiveStart(tx); loadErr != nil || found {
			if found {
				return admission.ErrTransitionConflict
			}
			return loadErr
		}
		q, err := l.openQueue(tx, now)
		if err != nil {
			return err
		}
		if err = q.endPreviewAnswers(); err != nil {
			return err
		}
		if err = q.clearNotices(); err != nil {
			return err
		}
		if err = q.releasePreviewHistory(); err != nil {
			return err
		}
		if err = carryLegacySpend(tx, h.Spend); err != nil {
			return err
		}
		// Without an observation an entry is unassessed: it is counted as
		// a refused finding without evidence is, and raises no notice.
		for range h.Pending {
			if err = q.count(admission.EventRefused, admission.ReasonAttribution, admission.Tier{}); err != nil {
				return err
			}
		}
		data, err := admission.LiveStart{At: now}.MarshalBinary()
		if err != nil {
			return err
		}
		if err = tx.Bucket([]byte(admissionQueueStateBucket)).Put(liveStartKey, data); err != nil {
			return err
		}
		if err = raiseSchema(tx, admissionSchemaLive); err != nil {
			return err
		}
		return q.flush()
	})
	if err == nil {
		l.live = true
	}
	return err
}

// carryLegacySpend charges what the legacy hour counted beyond the charges
// retained in it: the window that ends at the hour's end, which may include
// the first import's charges for the same hour.
func carryLegacySpend(tx *bolt.Tx, spend admission.LegacySpend) error {
	if err := keepPreLiveCharges(tx); err != nil {
		return err
	}
	s, err := loadCeiling(tx)
	if err != nil {
		return err
	}
	charges, err := loadCharges(tx)
	if err != nil {
		return err
	}
	var retained uint32
	from := spend.At.Add(-admission.CeilingWindow)
	for _, c := range charges {
		if c.At.After(from) && !c.At.After(spend.At) {
			retained += c.Cost
		}
	}
	next, carried, err := s.CarryLegacy(spend, retained)
	if err != nil {
		return err
	}
	if err = putCharges(tx, carried); err != nil {
		return err
	}
	return putCeilingState(tx, next)
}

// endPreviewAnswers makes placement's forecast rule for preview answers
// durable (section 8, row 4): a block line a preview answered ends, so the
// next observation queues a new generation, and a row no candidate anchors
// any longer is deleted, so its target's next observation opens a new
// episode. Challenge lines keep their previews' answers, and a remembered
// answer of a verified block keeps its episode's verified end.
func (q *queueTx) endPreviewAnswers() error {
	episodes := q.tx.Bucket([]byte(admissionEpisodesBucket))
	type change struct {
		key string
		row admission.Episode
	}
	var changes []change
	err := episodes.ForEach(func(k, v []byte) error {
		e, err := admission.UnmarshalEpisode(v)
		if err != nil {
			return err
		}
		ended := false
		for i, line := range e.Lines {
			if line.Kind == admission.KindChallenge {
				continue
			}
			if line.Candidate == "" {
				if line.Answered && e.Verified.IsZero() {
					e.Lines[i].Answered, ended = false, true
				}
				continue
			}
			c, err := loadCandidate(q.tx, line.Candidate)
			if err != nil {
				return corruptRecord(err)
			}
			if c.State == admission.StateObserved {
				e.Lines[i].Candidate, ended = "", true
			}
		}
		if ended {
			changes = append(changes, change{string(k), e})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, c := range changes {
		if !c.row.HasCandidates() {
			err = episodes.Delete([]byte(c.key))
		} else {
			err = putEpisode(q.tx, c.key, c.row)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// clearNotices removes every notice record raised while admission only
// previewed, delivered or not: their gaps were legacy blocking's to close,
// and a preview delivery must not delay a key's first live notice. The
// fixed records stay, empty.
func (q *queueTx) clearNotices() error {
	outbox := q.tx.Bucket([]byte(admissionOutboxBucket))
	var quiet, records [][]byte
	cur := outbox.Cursor()
	for k, _ := cur.Seek([]byte{'n'}); k != nil && k[0] == 'n'; k, _ = cur.Next() {
		records = append(records, k)
	}
	for k, _ := cur.Seek([]byte{'q'}); k != nil && k[0] == 'q'; k, _ = cur.Next() {
		quiet = append(quiet, k)
	}
	for _, k := range quiet {
		if err := outbox.Delete(k); err != nil {
			return err
		}
	}
	for _, kb := range records {
		key, err := admission.ParseNoticeKey(kb)
		if err != nil {
			return err
		}
		if key.Fixed() {
			if err = putNoticeRecord(q.tx, admission.NewNoticeRecord(key)); err != nil {
				return err
			}
			continue
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

// releasePreviewHistory makes the history of every ended observe preview
// eligible now (design C7): a preview carries no review or undo, so
// pressure retires it before genuine history. Its index keys move with it;
// one whose audit rows wait gets them on acknowledgement.
func (q *queueTx) releasePreviewHistory() error {
	var ids []admission.CandidateID
	err := q.tx.Bucket([]byte(admissionHistoryBucket)).ForEach(func(k, v []byte) error {
		h, err := admission.UnmarshalHistoryEntry(v)
		if err != nil {
			return err
		}
		if h.Ended.IsZero() || h.Pinned || !h.Eligible.After(q.now) {
			return nil
		}
		c, err := loadCandidate(q.tx, admission.CandidateID(k))
		if err != nil {
			return corruptRecord(err)
		}
		if !admission.HistoryUntilExpiry(c) {
			ids = append(ids, admission.CandidateID(k))
		}
		return nil
	})
	if err != nil {
		return err
	}
	retire := q.tx.Bucket([]byte(admissionRetireBucket))
	for _, id := range ids {
		h, _, err := loadHistoryEntry(q.tx, id)
		if err != nil {
			return err
		}
		keys, err := retireKeysOf(q.tx, id, h)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err = retire.Delete(k); err != nil {
				return err
			}
		}
		h.Released, h.Eligible = true, q.now
		if err = putHistoryEntry(q.tx, id, h); err != nil {
			return err
		}
	}
	return nil
}

// keepPreLiveCharges makes the greater-of balance survive later forecasts
// and early preview-history retirement. Preserve each charge's lane and
// wall/elapsed deadlines; the handover must not grant a refund.
func keepPreLiveCharges(tx *bolt.Tx) error {
	charges, err := loadCharges(tx)
	if err != nil {
		return err
	}
	attempts := tx.Bucket([]byte(admissionAttemptsBucket))
	bucket := tx.Bucket([]byte(admissionChargesBucket))
	for _, c := range charges {
		if attempts.Get([]byte(c.Action)) == nil {
			continue
		}
		a, err := loadAttempt(tx, c.Action)
		if err != nil {
			return err
		}
		candidate, err := loadCandidate(tx, a.Attempt.Candidate)
		if err != nil || !c.At.Equal(a.Reserved) || c.Lane != a.Lane || c.Cost != candidate.Key.Kind.CeilingCost() {
			return admission.ErrCorruptRecord
		}
		if a.State != admission.StateObserved {
			continue
		}
		key, err := c.Key()
		if err != nil {
			return err
		}
		if err = bucket.Delete(key); err != nil {
			return err
		}
		c.Action = admission.LiveStartPreviewActionID(c.Action)
		if err = putCharges(tx, []admission.Charge{c}); err != nil {
			return err
		}
	}
	return nil
}
