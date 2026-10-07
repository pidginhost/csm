package store

import (
	"bytes"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// futureAuditSlots is the rows an attempt in state s may still write: a
// reserved one its execution and its outcome, an executing one its outcome.
func futureAuditSlots(s admission.State) uint64 {
	switch s {
	case admission.StateReserved:
		return 2
	case admission.StateExecuting:
		return 1
	}
	return 0
}

// auditStepMatches proves the row's intent and phase against its retained
// records. Retry support can grow, but roots paid for by an attempt stay.
func auditStepMatches(row admission.AuditRow, a admission.AttemptRecord, c admission.Candidate, now time.Time) bool {
	if row.Attempt != a.Attempt || row.Lane != a.Lane || !row.ExpiresAt.Equal(a.ExpiresAt) ||
		row.Kind != c.Key.Kind || row.Target != c.Key.Target || row.Check != c.Check || row.FindingID != c.FindingID ||
		row.At.Before(a.Reserved) || row.At.After(now) {
		return false
	}
	for _, root := range row.Roots {
		if !slices.Contains(c.Roots, root) {
			return false
		}
	}
	switch row.State {
	case admission.StateReserved:
		return row.At.Equal(a.Reserved)
	case admission.StateExecuting:
		// A preview never ran: no execution row can belong to it.
		return a.State != admission.StateReserved && a.State != admission.StateObserved && row.At.Before(a.ExpiresAt) &&
			(a.Finished.IsZero() || !row.At.After(a.Finished))
	default:
		return row.State == a.State && row.Disposition == a.Disposition && row.At.Equal(a.Finished)
	}
}

// auditFollows allows acknowledged phases to be absent, but remaining rows
// must describe one unchanged intent and consecutive lifecycle transitions.
func auditFollows(previous, row admission.AuditRow) bool {
	if row.At.Before(previous.At) || row.Tier != previous.Tier || !slices.Equal(row.Roots, previous.Roots) {
		return false
	}
	steps := row.Transition - previous.Transition
	switch previous.State {
	case admission.StateReserved:
		switch row.State {
		case admission.StateExecuting, admission.StateObserved:
			return steps == 1
		case admission.StateFailed:
			return steps == 1 || steps == 2
		case admission.StateVerified, admission.StateUnknown:
			return steps == 2
		}
	case admission.StateExecuting:
		return row.State.Terminal() && steps == 1
	}
	return false
}

// writeAuditRow stores the row of the transition c is recording, to
// attempt a's state; the reservation already holds its slot. c is the
// candidate as the step leaves it, before its transition is counted.
func (q *queueTx) writeAuditRow(c admission.Candidate, a admission.AttemptRecord, tier admission.Tier) error {
	c.Transitions++
	row, err := admission.NewAuditRow(c, a, tier, q.now)
	if err != nil {
		return err
	}
	data, err := row.MarshalBinary()
	if err != nil {
		return err
	}
	outbox := q.tx.Bucket([]byte(admissionOutboxBucket))
	if outbox.Get(row.Key()) != nil {
		return admission.ErrCorruptRecord
	}
	return outbox.Put(row.Key(), data)
}

// adjustAuditSlots holds or returns audit slots in the transaction's
// storage state.
func (q *queueTx) adjustAuditSlots(hold, release uint64) error {
	// A step that changes no slot needs no storage state: the outcome of
	// running work is recorded even when that record is damaged.
	if hold == 0 && release == 0 {
		return nil
	}
	s, err := q.storageState()
	if err != nil {
		return err
	}
	next, err := s.HoldAudit(hold)
	if err != nil {
		return err
	}
	if next, err = next.ReleaseAudit(release); err != nil {
		return err
	}
	*s, q.storageDirty = next, true
	return nil
}

// auditPending reports whether any attempt of candidate id still has an
// unacknowledged row. The upgrade to schema 4 runs before the outbox
// exists, when no row can be pending.
func auditPending(tx *bolt.Tx, id admission.CandidateID) (bool, error) {
	outbox := tx.Bucket([]byte(admissionOutboxBucket))
	if outbox == nil {
		return false, nil
	}
	cur := outbox.Cursor()
	for seq := uint32(1); seq <= admission.MaxAttempts; seq++ {
		a, err := admission.NewAttempt(id, seq)
		if err != nil {
			return false, err
		}
		prefix := admission.AuditPrefix(a.ID)
		if k, _ := cur.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// PendingAudit returns up to limit unacknowledged audit rows in key order.
// The consumer delivers them idempotently by their ID and time and
// acknowledges each with its Ack through AckAudit.
func (l *AdmissionLedger) PendingAudit(limit int) ([]admission.AuditRow, error) {
	var rows []admission.AuditRow
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		cur := tx.Bucket([]byte(admissionOutboxBucket)).Cursor()
		for k, v := cur.Seek([]byte{'a'}); k != nil && k[0] == 'a' && len(rows) < limit; k, v = cur.Next() {
			row, err := admission.UnmarshalAuditRow(v)
			if err != nil {
				return err
			}
			if !bytes.Equal(row.Key(), k) {
				return admission.ErrCorruptRecord
			}
			rows = append(rows, row)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// AckAudit removes delivered rows and returns their slots in one
// transaction. A row already acknowledged, or one written at another time
// than its acknowledgement names, is skipped. Once an ended candidate's
// last row is acknowledged, its history may be retired: the same
// transaction writes its retirement keys (spec 5.4).
func (l *AdmissionLedger) AckAudit(acks []admission.AuditAck) error {
	for _, ack := range acks {
		if _, err := admission.ParseActionID(string(ack.ID.Action)); err != nil || ack.ID.Transition == 0 {
			return refusal(admission.ReasonInvalid, "audit acknowledgement names no row")
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.update("audit", func(tx *bolt.Tx) error {
		q, err := l.openQueue(tx, l.now)
		if err != nil {
			return err
		}
		outbox := tx.Bucket([]byte(admissionOutboxBucket))
		touched := map[admission.CandidateID]bool{}
		var acked uint64
		for _, ack := range acks {
			raw := outbox.Get(ack.ID.Key())
			if raw == nil {
				continue
			}
			row, decodeErr := admission.UnmarshalAuditRow(raw)
			if decodeErr != nil || row.ID() != ack.ID {
				return admission.ErrCorruptRecord
			}
			if !row.At.Equal(ack.At) {
				continue
			}
			if err = outbox.Delete(ack.ID.Key()); err != nil {
				return err
			}
			touched[row.Attempt.Candidate] = true
			acked++
		}
		if acked == 0 {
			return nil
		}
		if err = q.adjustAuditSlots(0, acked); err != nil {
			return err
		}
		for id := range touched {
			pending, err := auditPending(tx, id)
			if err != nil {
				return err
			}
			if pending {
				continue
			}
			h, found, err := loadHistoryEntry(tx, id)
			if err != nil {
				return err
			}
			if !found {
				return admission.ErrCorruptRecord
			}
			if err = putHistoryEntry(tx, id, h); err != nil {
				return err
			}
		}
		return q.flush()
	})
}
