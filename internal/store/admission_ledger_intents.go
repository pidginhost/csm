package store

import (
	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// upgradeLedgerToSchemaSeven adds the intent bucket to a schema 6 ledger
// inside the opening transaction. An attempt that ran without an outcome,
// or ended unknown, gets the intent its execution would have recorded, as a
// batch of its own: no effect it may have applied goes unrecorded. This
// upgrade completes the chain and records the schema.
func upgradeLedgerToSchemaSeven(tx *bolt.Tx) error {
	if _, err := tx.CreateBucket([]byte(admissionIntentsBucket)); err != nil {
		return err
	}
	if err := tx.Bucket([]byte(admissionAttemptsBucket)).ForEach(func(_, v []byte) error {
		a, err := admission.UnmarshalAttempt(v)
		if err != nil {
			return err
		}
		if a.State != admission.StateExecuting && a.State != admission.StateUnknown {
			return nil
		}
		c, err := loadCandidate(tx, a.Attempt.Candidate)
		if err != nil {
			return corruptRecord(err)
		}
		batch, err := admission.NewBatchID([]admission.ActionID{a.Attempt.ID})
		if err != nil {
			return err
		}
		return putIntent(tx, admission.Intent{Action: a.Attempt.ID, Batch: batch, Kind: c.Key.Kind, Target: c.Key.Target, ExpiresAt: a.ExpiresAt})
	}); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion})
}

func loadIntent(tx *bolt.Tx, id admission.ActionID) (admission.Intent, bool, error) {
	raw := tx.Bucket([]byte(admissionIntentsBucket)).Get([]byte(id))
	if raw == nil {
		return admission.Intent{}, false, nil
	}
	in, err := admission.UnmarshalIntent(raw)
	if err != nil {
		return in, true, err
	}
	if in.Action != id {
		return in, true, admission.ErrCorruptRecord
	}
	return in, true, nil
}

func putIntent(tx *bolt.Tx, in admission.Intent) error {
	data, err := in.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(in.Action), data)
}

// deleteIntent removes the intent of an attempt whose outcome is settled.
// An attempt that ran always has one.
func deleteIntent(tx *bolt.Tx, id admission.ActionID) error {
	_, found, err := loadIntent(tx, id)
	if err != nil {
		return corruptRecord(err)
	}
	if !found {
		return admission.ErrCorruptRecord
	}
	return tx.Bucket([]byte(admissionIntentsBucket)).Delete([]byte(id))
}

// unsettled reports whether attempt a's outcome is unresolved: it runs, or
// it ended unknown.
func unsettled(a admission.AttemptRecord) bool {
	return a.State == admission.StateExecuting || a.State == admission.StateUnknown
}

// proveIntents checks every intent at open: it decodes under its own
// action, belongs to the current attempt of a stored candidate whose
// outcome is unresolved, and names that candidate's kind and target and the
// attempt's expiry. Every unresolved attempt has its intent.
func proveIntents(tx *bolt.Tx) error {
	rows := map[admission.ActionID]bool{}
	if err := tx.Bucket([]byte(admissionIntentsBucket)).ForEach(func(k, _ []byte) error {
		id, err := admission.ParseActionID(string(k))
		if err != nil {
			return admission.ErrCorruptRecord
		}
		in, _, err := loadIntent(tx, id)
		if err != nil {
			return err
		}
		a, c, err := attemptAndCandidate(tx, id)
		if err != nil {
			return corruptRecord(err)
		}
		if !unsettled(a) || in.Kind != c.Key.Kind || in.Target != c.Key.Target || !in.ExpiresAt.Equal(a.ExpiresAt) {
			return admission.ErrCorruptRecord
		}
		rows[id] = true
		return nil
	}); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionAttemptsBucket)).ForEach(func(_, v []byte) error {
		a, err := admission.UnmarshalAttempt(v)
		if err != nil {
			return err
		}
		if unsettled(a) && !rows[a.Attempt.ID] {
			return admission.ErrCorruptRecord
		}
		return nil
	})
}

// ExecuteBatch marks the reserved attempts of one batch as running and
// records each member's intent in the same transaction. See the Ledger
// interface.
func (l *AdmissionLedger) ExecuteBatch(ids []admission.ActionID) ([]admission.Intent, bool, error) {
	intents, _, _, granted, err := l.execute(ids)
	return intents, granted, err
}

// Execute runs one reserved attempt as a batch of its own and returns its
// records after the step.
func (l *AdmissionLedger) Execute(id admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
	_, attempts, candidates, granted, err := l.execute([]admission.ActionID{id})
	if err != nil {
		return admission.Candidate{}, admission.AttemptRecord{}, false, err
	}
	return candidates[0], attempts[0], granted, nil
}

func (l *AdmissionLedger) execute(ids []admission.ActionID) ([]admission.Intent, []admission.AttemptRecord, []admission.Candidate, bool, error) {
	batch, err := admission.NewBatchID(ids)
	if err != nil {
		return nil, nil, nil, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return nil, nil, nil, false, err
	}
	var intents []admission.Intent
	var attempts []admission.AttemptRecord
	var candidates []admission.Candidate
	running := 0
	err = l.update("execute", func(tx *bolt.Tx) error {
		intents, attempts, candidates, running = nil, nil, nil, 0
		q, txErr := l.openQueue(tx, now)
		if txErr != nil {
			return txErr
		}
		for _, id := range ids {
			a, c, loadErr := attemptAndCandidate(tx, id)
			if loadErr != nil {
				return loadErr
			}
			switch {
			case a.State == admission.StateExecuting:
				in, found, intentErr := loadIntent(tx, id)
				if intentErr != nil {
					return corruptRecord(intentErr)
				}
				if !found {
					return admission.ErrCorruptRecord
				}
				if in.Batch != batch {
					return admission.ErrTransitionConflict
				}
				intents, attempts, candidates = append(intents, in), append(attempts, a), append(candidates, c)
				running++
				continue
			case a.State != admission.StateReserved:
				return admission.ErrTransitionConflict
			case !now.Before(a.ExpiresAt):
				return refusal(admission.ReasonStale, "absolute expiry has passed")
			}
			e, loadErr := loadQueueEntry(tx, a.Attempt.Candidate)
			if loadErr != nil {
				return loadErr
			}
			in := admission.Intent{Action: id, Batch: batch, Kind: c.Key.Kind, Target: c.Key.Target, ExpiresAt: a.ExpiresAt}
			a.State, c.State = admission.StateExecuting, admission.StateExecuting
			if txErr = q.writeAuditRow(c, a, e.Tier); txErr != nil {
				return txErr
			}
			c.Transitions++
			if txErr = putAttempt(tx, a); txErr != nil {
				return txErr
			}
			if txErr = putCandidate(tx, c); txErr != nil {
				return txErr
			}
			if txErr = putIntent(tx, in); txErr != nil {
				return txErr
			}
			intents, attempts, candidates = append(intents, in), append(attempts, a), append(candidates, c)
		}
		// A batch's ID is its member set and its members run together, so
		// either all of them ran already or none did.
		if running > 0 {
			return nil
		}
		return q.flush()
	})
	if err != nil {
		return nil, nil, nil, false, err
	}
	return intents, attempts, candidates, running == 0, nil
}
