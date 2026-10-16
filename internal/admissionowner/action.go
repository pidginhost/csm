package admissionowner

import (
	"errors"
	"fmt"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

var readActionAttempt = (*store.AdmissionLedger).Attempt

// Action reads one admitted candidate and its attempts for `csm action
// show`. ref is a candidate ID or the action ID of one of its attempts.
// The read runs on the owner's goroutine, so it sees no half-made change.
func (o *Owner) Action(ref string) (admission.ActionView, error) {
	var view admission.ActionView
	err := o.do(func() error {
		if o.ledger == nil {
			return errors.New("the admission ledger is not running")
		}
		id, err := admission.ParseCandidateID(ref)
		if err != nil {
			action, actionErr := admission.ParseActionID(ref)
			if actionErr != nil {
				return fmt.Errorf("%q is neither a candidate nor an action ID", ref)
			}
			a, readErr := o.ledger.Attempt(action)
			if readErr != nil {
				return missingRecord(ref, readErr)
			}
			id = a.Attempt.Candidate
		}
		c, err := o.ledger.Candidate(id)
		if err != nil {
			return missingRecord(ref, err)
		}
		attempts := make([]admission.AttemptRecord, 0, c.Attempts)
		for seq := uint32(1); seq <= c.Attempts; seq++ {
			next, idErr := admission.NewAttempt(id, seq)
			if idErr != nil {
				return idErr
			}
			a, readErr := readActionAttempt(o.ledger, next.ID)
			if readErr != nil {
				if reason, refused := admission.ReasonOf(readErr); refused && reason == admission.ReasonInvalid {
					return fmt.Errorf("%w: candidate %s is missing attempt %s", admission.ErrCorruptRecord, id, next.ID)
				}
				return fmt.Errorf("reading attempt %s: %w", next.ID, readErr)
			}
			attempts = append(attempts, a)
		}
		view = admission.NewActionView(id, c, attempts)
		return nil
	})
	return view, err
}

// missingRecord names a record the ledger refuses to read as one it does
// not hold: never recorded, or retired with its history.
func missingRecord(ref string, err error) error {
	if reason, refused := admission.ReasonOf(err); refused && reason == admission.ReasonInvalid {
		return fmt.Errorf("the admission ledger has no record of %s; it was never admitted or its history has retired", ref)
	}
	return fmt.Errorf("reading %s: %w", ref, err)
}
