package store

import (
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var _ admission.Ledger = (*AdmissionLedger)(nil)

func loadAttempt(tx *bolt.Tx, id admission.ActionID) (admission.AttemptRecord, error) {
	if _, err := admission.ParseActionID(string(id)); err != nil {
		return admission.AttemptRecord{}, err
	}
	raw := tx.Bucket([]byte(admissionAttemptsBucket)).Get([]byte(id))
	if raw == nil {
		return admission.AttemptRecord{}, refusal(admission.ReasonInvalid, "attempt is not recorded")
	}
	a, err := admission.UnmarshalAttempt(raw)
	if err != nil {
		return admission.AttemptRecord{}, err
	}
	if a.Attempt.ID != id {
		return admission.AttemptRecord{}, admission.ErrCorruptRecord
	}
	return a, nil
}

func putAttempt(tx *bolt.Tx, a admission.AttemptRecord) error {
	data, err := a.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionAttemptsBucket)).Put([]byte(a.Attempt.ID), data)
}

// Attempt loads an attempt record.
func (l *AdmissionLedger) Attempt(id admission.ActionID) (admission.AttemptRecord, error) {
	var a admission.AttemptRecord
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		a, err = loadAttempt(tx, id)
		return err
	})
	return a, err
}

// modify applies fn to one candidate in a write transaction. fn reports
// whether it changed the record; only a change bumps Transitions. Queue
// bookkeeping fn changes commits with the candidate.
func (l *AdmissionLedger) modify(op string, id admission.CandidateID, fn func(q *queueTx, c *admission.Candidate) (bool, error)) (admission.Candidate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out admission.Candidate
	err := l.update(op, func(tx *bolt.Tx) error {
		c, err := loadCandidate(tx, id)
		if err != nil {
			return err
		}
		if c.Attempts > 0 {
			if _, err = currentAttempt(tx, c); err != nil {
				return err
			}
		}
		q, err := l.openQueue(tx, l.now)
		if err != nil {
			return err
		}
		from := c.State
		changed, err := fn(q, &c)
		if err != nil {
			return err
		}
		out = c
		if !changed {
			return nil
		}
		if !admission.CanTransition(from, c.State) {
			return admission.ErrTransitionConflict
		}
		out.Transitions++
		if err = putCandidate(tx, out); err != nil {
			return err
		}
		return q.flush()
	})
	if err != nil {
		return admission.Candidate{}, err
	}
	return out, nil
}

// Defer records a changed deferral reason on a queued candidate. The same
// reason again is not a new transition, so polling never inflates counts.
func (l *AdmissionLedger) Defer(id admission.CandidateID, reason admission.Reason) (admission.Candidate, error) {
	if reason.Disposition() != admission.DispositionDeferred {
		return admission.Candidate{}, refusal(admission.ReasonInvalid, "reason is not a deferral")
	}
	return l.modify("defer", id, func(q *queueTx, c *admission.Candidate) (bool, error) {
		switch {
		case c.State.Terminal():
			return false, admission.ErrCandidateTerminal
		case c.State != admission.StateQueued:
			return false, admission.ErrTransitionConflict
		case c.Reason == reason:
			return false, nil
		}
		e, err := loadQueueEntry(q.tx, id)
		if err != nil {
			return false, err
		}
		c.Reason = reason
		if err = q.count(admission.EventDeferred, reason, e.Tier); err != nil {
			return false, err
		}
		return true, q.gap(admission.GapDeferred, reason, 0, e, id, *c, c.Transitions+1)
	})
}

var terminalFor = map[admission.Disposition]admission.State{
	admission.DispositionRefused:  admission.StateRefused,
	admission.DispositionWithheld: admission.StateWithheld,
	admission.DispositionDropped:  admission.StateDropped,
}

// Terminate ends a queued candidate as refused, withheld or dropped and
// releases its queue position. The same ending again is a no-op; a
// candidate that already ended otherwise refuses like every other call on
// an ended candidate, and an in-flight one is a conflict.
func (l *AdmissionLedger) Terminate(id admission.CandidateID, reason admission.Reason) (admission.Candidate, error) {
	d := reason.Disposition()
	state, ok := terminalFor[d]
	if !ok {
		return admission.Candidate{}, refusal(admission.ReasonInvalid, "reason does not end a candidate")
	}
	return l.modify("terminate", id, func(q *queueTx, c *admission.Candidate) (bool, error) {
		switch {
		case c.State == state && c.Reason == reason:
			return false, nil
		case c.State.Terminal():
			return false, admission.ErrCandidateTerminal
		case c.State != admission.StateQueued:
			return false, admission.ErrTransitionConflict
		}
		e, err := loadQueueEntry(q.tx, id)
		if err != nil {
			return false, err
		}
		if err = q.trimUnreservedRoots(c); err != nil {
			return false, err
		}
		c.State, c.Disposition, c.Reason, c.NotBefore = state, d, reason, time.Time{}
		if err = q.release(id, e, admission.EventEnded, reason); err != nil {
			return false, err
		}
		if err = q.gap(admission.GapEnded, reason, 0, e, id, *c, c.Transitions+1); err != nil {
			return false, err
		}
		return true, q.ended(id, *c)
	})
}

// Reserve admits the next attempt of a queued candidate on lane and reports
// true. The first reservation fixes the absolute expiry, which must be in
// the future; retries keep it and refuse once it has passed. Every attempt
// is charged to its lane, retries included, and the charge commits with the
// attempt, as does the history the candidate's details may keep. A
// candidate that is already reserved or executing returns its current
// attempt and false, so recovery reuses the attempt ID without being
// granted or charged anything.
func (l *AdmissionLedger) Reserve(id admission.CandidateID, lane admission.Lane, expiresAt time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return admission.Candidate{}, admission.AttemptRecord{}, false, err
	}
	var c admission.Candidate
	var a admission.AttemptRecord
	var granted bool
	if err := l.update("reserve", func(tx *bolt.Tx) error {
		q, txErr := l.openQueue(tx, now)
		if txErr != nil {
			return txErr
		}
		if c, a, granted, txErr = l.reserveTx(q, id, lane, expiresAt); txErr != nil {
			return txErr
		}
		return q.flush()
	}); err != nil {
		return admission.Candidate{}, admission.AttemptRecord{}, false, err
	}
	return c, a, granted, nil
}

func (l *AdmissionLedger) reserveTx(q *queueTx, id admission.CandidateID, lane admission.Lane, expiresAt time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
	tx, now := q.tx, q.now
	c, err := loadCandidate(tx, id)
	if err != nil {
		return c, admission.AttemptRecord{}, false, err
	}
	var current admission.AttemptRecord
	if c.Attempts > 0 {
		current, err = currentAttempt(tx, c)
		if err != nil {
			return c, admission.AttemptRecord{}, false, err
		}
	}
	switch {
	case c.State == admission.StateReserved || c.State == admission.StateExecuting:
		if (!expiresAt.IsZero() && !expiresAt.Equal(c.ExpiresAt)) || (lane != 0 && lane != current.Lane) {
			return c, admission.AttemptRecord{}, false, admission.ErrTransitionConflict
		}
		return c, current, false, nil
	case c.State.Terminal():
		return c, admission.AttemptRecord{}, false, admission.ErrCandidateTerminal
	case now.Before(c.NotBefore):
		return c, admission.AttemptRecord{}, false, admission.ErrNotReady
	case !now.Before(c.AgeOut):
		return c, admission.AttemptRecord{}, false, refusal(admission.ReasonStale, "candidate aged out of the queue")
	case c.Attempts >= admission.MaxAttempts:
		return c, admission.AttemptRecord{}, false, admission.ErrCorruptRecord
	}
	if c.Attempts == 0 {
		if !expiresAt.After(now) {
			return c, admission.AttemptRecord{}, false, refusal(admission.ReasonInvalid, "absolute expiry must be in the future")
		}
		c.ExpiresAt = expiresAt
	} else {
		if !expiresAt.IsZero() && !expiresAt.Equal(c.ExpiresAt) {
			return c, admission.AttemptRecord{}, false, admission.ErrTransitionConflict
		}
		if !now.Before(c.ExpiresAt) {
			return c, admission.AttemptRecord{}, false, refusal(admission.ReasonStale, "absolute expiry has passed")
		}
	}
	// A queued candidate holds a queue position; one without an entry is
	// invisible to capacity and fairness.
	entry, err := loadQueueEntry(tx, id)
	if err != nil {
		return c, admission.AttemptRecord{}, false, err
	}
	if err = laneFits(q, liveCandidate{id: id, c: c, entry: entry}, lane); err != nil {
		return c, admission.AttemptRecord{}, false, err
	}
	next, err := admission.NewAttempt(id, c.Attempts+1)
	if err != nil {
		return c, admission.AttemptRecord{}, false, err
	}
	if tx.Bucket([]byte(admissionAttemptsBucket)).Get([]byte(next.ID)) != nil {
		return c, admission.AttemptRecord{}, false, admission.ErrCorruptRecord
	}
	if !admission.CanTransition(c.State, admission.StateReserved) {
		return c, admission.AttemptRecord{}, false, admission.ErrTransitionConflict
	}
	if cost := c.Key.Kind.CeilingCost(); cost > 0 {
		if err = chargeTx(tx, now, next.ID, lane, cost); err != nil {
			return c, admission.AttemptRecord{}, false, err
		}
	}
	a := admission.AttemptRecord{Attempt: next, State: admission.StateReserved, ExpiresAt: c.ExpiresAt, Reserved: now, Lane: lane}
	c.State, c.Attempts, c.Reason, c.NotBefore = admission.StateReserved, next.Seq, 0, time.Time{}
	c.Transitions++
	if err = q.chargeHistory(id, c, lane); err != nil {
		return c, admission.AttemptRecord{}, false, err
	}
	// The reservation holds a slot for each row its attempt can write and
	// writes the first, its own.
	if err = q.adjustAuditSlots(admission.AuditStepsPerAttempt, 0); err != nil {
		return c, admission.AttemptRecord{}, false, err
	}
	written := c
	written.Transitions--
	if err = q.writeAuditRow(written, a, entry.Tier); err != nil {
		return c, admission.AttemptRecord{}, false, err
	}
	if err := putAttempt(tx, a); err != nil {
		return c, a, false, err
	}
	return c, a, true, putCandidate(tx, c)
}

// currentAttempt proves the whole bounded predecessor chain and its link
// to the candidate. A readable row alone is not proof of admissible history.
func currentAttempt(tx *bolt.Tx, c admission.Candidate) (admission.AttemptRecord, error) {
	id, err := c.ID()
	if err != nil {
		return admission.AttemptRecord{}, admission.ErrCorruptRecord
	}
	var prev admission.AttemptRecord
	for seq := uint32(1); seq <= c.Attempts; seq++ {
		identity, err := admission.NewAttempt(id, seq)
		if err != nil {
			return admission.AttemptRecord{}, admission.ErrCorruptRecord
		}
		a, err := loadAttempt(tx, identity.ID)
		if err != nil || a.Attempt != identity || !a.ExpiresAt.Equal(c.ExpiresAt) || a.Reserved.Before(c.FirstQueued) || !a.Reserved.Before(c.AgeOut) {
			return admission.AttemptRecord{}, admission.ErrCorruptRecord
		}
		if seq > 1 && (prev.State != admission.StateFailed || a.Reserved.Before(prev.Finished.Add(admission.RetryBackoff(seq-1)))) {
			return admission.AttemptRecord{}, admission.ErrCorruptRecord
		}
		prev = a
	}
	valid := false
	switch c.State {
	case admission.StateQueued:
		valid = prev.State == admission.StateFailed && c.NotBefore.Equal(prev.Finished.Add(admission.RetryBackoff(c.Attempts)))
	case admission.StateRefused, admission.StateWithheld, admission.StateDropped:
		valid = prev.State == admission.StateFailed
	default:
		valid = prev.State == c.State && prev.Disposition == c.Disposition
	}
	if c.Attempts == 0 || !valid {
		return admission.AttemptRecord{}, admission.ErrCorruptRecord
	}
	return prev, nil
}

// Historical outcomes can be acknowledged again, but only the current
// attempt may make a new transition.
func attemptAndCandidate(tx *bolt.Tx, id admission.ActionID) (admission.AttemptRecord, admission.Candidate, error) {
	a, err := loadAttempt(tx, id)
	if err != nil {
		return a, admission.Candidate{}, err
	}
	c, err := loadCandidate(tx, a.Attempt.Candidate)
	if err != nil {
		return a, c, err
	}
	if _, err := currentAttempt(tx, c); err != nil {
		return a, c, err
	}
	if a.Attempt.Seq > c.Attempts {
		return a, c, admission.ErrCorruptRecord
	}
	return a, c, nil
}

// attemptStep runs one attempt transition and reports whether it changed
// anything. now is l.clock for a step that dispatches work and
// l.recordedClock for one that only records an outcome.
func (l *AdmissionLedger) attemptStep(op string, id admission.ActionID, now func() (time.Time, error), fn func(q *queueTx, a *admission.AttemptRecord, c *admission.Candidate) (bool, error)) (admission.Candidate, admission.AttemptRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	at, err := now()
	if err != nil {
		return admission.Candidate{}, admission.AttemptRecord{}, false, err
	}
	var outC admission.Candidate
	var outA admission.AttemptRecord
	var changed bool
	err = l.update(op, func(tx *bolt.Tx) error {
		a, c, loadErr := attemptAndCandidate(tx, id)
		if loadErr != nil {
			return loadErr
		}
		q, loadErr := l.openQueue(tx, at)
		if loadErr != nil {
			return loadErr
		}
		from := c.State
		stepChanged, stepErr := fn(q, &a, &c)
		if stepErr != nil {
			return stepErr
		}
		outC, outA = c, a
		if !stepChanged {
			return nil
		}
		if !admission.CanTransition(from, c.State) {
			return admission.ErrTransitionConflict
		}
		c.Transitions++
		outC, changed = c, true
		if putErr := putAttempt(tx, a); putErr != nil {
			return putErr
		}
		if putErr := putCandidate(tx, c); putErr != nil {
			return putErr
		}
		return q.flush()
	})
	if err != nil {
		return admission.Candidate{}, admission.AttemptRecord{}, false, err
	}
	return outC, outA, changed, nil
}

// Execute marks a reserved attempt as running and reports true. On an
// attempt already running it is a no-op that reports false: a readback is
// not permission to dispatch the attempt's effect again.
func (l *AdmissionLedger) Execute(id admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
	return l.attemptStep("execute", id, l.clock, func(q *queueTx, a *admission.AttemptRecord, c *admission.Candidate) (bool, error) {
		switch {
		case a.State == admission.StateExecuting:
			return false, nil
		case a.State != admission.StateReserved:
			return false, admission.ErrTransitionConflict
		case !q.now.Before(a.ExpiresAt):
			return false, refusal(admission.ReasonStale, "absolute expiry has passed")
		}
		e, err := loadQueueEntry(q.tx, a.Attempt.Candidate)
		if err != nil {
			return false, err
		}
		a.State, c.State = admission.StateExecuting, admission.StateExecuting
		return true, q.writeAuditRow(*c, *a, e.Tier)
	})
}

// Finish records the outcome of the candidate's current attempt. Applied and
// narrowed need a running attempt, and so does unknown: an attempt that never
// ran is known not to have applied, so it can only fail. A proven failure
// with attempts left returns the candidate to the queue after a backoff; an
// unknown outcome ends it without a retry. An ended candidate releases its
// queue position in the same transaction.
func (l *AdmissionLedger) Finish(id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
	var state admission.State
	switch d {
	case admission.DispositionApplied, admission.DispositionNarrowed:
		state = admission.StateVerified
	case admission.DispositionFailed:
		state = admission.StateFailed
	case admission.DispositionUnknown:
		state = admission.StateUnknown
	default:
		return admission.Candidate{}, admission.AttemptRecord{}, refusal(admission.ReasonInvalid, "disposition is not an attempt outcome")
	}
	cand, att, _, err := l.attemptStep("finish", id, l.recordedClock, func(q *queueTx, a *admission.AttemptRecord, c *admission.Candidate) (bool, error) {
		if a.State.Terminal() {
			if a.Disposition == d {
				return false, nil
			}
			return false, admission.ErrTransitionConflict
		}
		e, err := loadQueueEntry(q.tx, a.Attempt.Candidate)
		if err != nil {
			return false, err
		}
		// The candidate moves in step with its current attempt, so the
		// lifecycle table decides which outcomes a reserved attempt allows.
		from := c.State
		// An attempt that never ran returns the slot of its execution row.
		var unused uint64
		if a.State == admission.StateReserved {
			unused = 1
		}
		a.State, a.Disposition, a.Finished = state, d, q.now
		if err = q.outcomes.Add(admission.AttemptOutcome(d, e.Tier)); err != nil {
			return false, err
		}
		switch {
		case d == admission.DispositionFailed && c.Attempts < admission.MaxAttempts:
			c.State, c.NotBefore = admission.StateQueued, q.now.Add(admission.RetryBackoff(c.Attempts))
		default:
			c.State, c.Disposition = state, d
		}
		// A row cannot record an outcome its attempt never reached, so the
		// table is asked before the row is written.
		if !admission.CanTransition(from, c.State) {
			return false, admission.ErrTransitionConflict
		}
		// The row goes first: the ending below writes retirement keys
		// only when no row of the candidate is pending.
		if err = q.writeAuditRow(*c, *a, e.Tier); err != nil {
			return false, err
		}
		if err = q.adjustAuditSlots(0, unused); err != nil {
			return false, err
		}
		if c.State == admission.StateQueued {
			q.noteDeadlines(*c, e)
			return true, nil
		}
		if err = q.release(a.Attempt.Candidate, e, 0, 0); err != nil {
			return false, err
		}
		// Pin the ending before allocating its notice: release removed
		// the outstanding hold, and the notice cannot spend those bytes.
		if err = q.ended(a.Attempt.Candidate, *c); err != nil {
			return false, err
		}
		if c.State == admission.StateVerified {
			if err = q.closeEpisode(*c); err != nil {
				return false, err
			}
			err = q.raise(admission.NoticeKey{Kind: admission.NoticeAppliedSummary}, a.Attempt.Candidate, c.Transitions+1)
		} else {
			err = q.gap(admission.GapOutcome, 0, d, e, a.Attempt.Candidate, *c, c.Transitions+1)
		}
		return true, err
	})
	return cand, att, err
}
