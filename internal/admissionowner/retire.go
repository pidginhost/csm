package admissionowner

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// retireRecheck is how long an unknown attempt whose element the kernel
// still holds waits before the engine is asked again.
const retireRecheck = time.Minute

// retire retires unknown attempts whose expiry has passed and of which the
// engine finds nothing left (spec 5.4, design P7). The engine removes each
// clear attempt's own row first, then the ledger retires it: a stop between
// the two leaves an unknown attempt without a row, which the next pass
// finds clear again. Running attempts are never sent. A degraded clock or a
// missing engine retires nothing and tries again after a backoff from one
// second to a minute; a held attempt waits a minute on its own, so a held
// batch cannot starve the intents behind it.
func (o *Owner) retire() error {
	if o.opts.Blocks == nil || monoNow().Before(o.retireAt) {
		return nil
	}
	// Nothing noted runs the pass; otherwise it waits until the noted
	// expiry or retry, whichever comes first.
	expiryAhead := o.retireDue.IsZero() || o.now.Before(o.retireDue)
	retryAhead := o.retireNext.IsZero() || monoNow().Before(o.retireNext)
	if expiryAhead && retryAhead && (!o.retireDue.IsZero() || !o.retireNext.IsZero()) {
		return nil
	}
	intents, err := unresolvedIntents(o.ledger)
	if err != nil {
		if errors.Is(err, admission.ErrCorruptRecord) {
			o.retireAt = monoNow().Add(retireRecheck)
			o.noteRetirementRetry(o.retireAt)
			if o.retireReadFault {
				return nil
			}
			o.retireReadFault = true
		} else {
			o.backoffRetirement()
		}
		return fmt.Errorf("reading unresolved intents: %w", err)
	}
	o.retireReadFault = false
	o.retireDue, o.retireNext = time.Time{}, time.Time{}
	waiting, delays, faults := o.retireRetry, o.retireDelay, o.retireFaults
	o.retireRetry = make(map[admission.ActionID]time.Time)
	o.retireDelay = make(map[admission.ActionID]time.Duration)
	o.retireFaults = make(map[admission.ActionID]bool)
	var due []admission.Intent
	var errs error
	// Intents are in action order. Rotate the scan so due retries cannot
	// starve the tail when a turn takes longer than their waits.
	start := sort.Search(len(intents), func(i int) bool { return intents[i].Action > o.retireAfter })
	for offset := range len(intents) {
		in := intents[(start+offset)%len(intents)]
		if in.Kind != admission.KindBlockIP {
			continue
		}
		if d, ok := delays[in.Action]; ok {
			o.retireDelay[in.Action] = d
		}
		if faults[in.Action] {
			o.retireFaults[in.Action] = true
		}
		// A damaged attempt can fail to decode before retirement reaches
		// the ledger write. Respect its wait before reading it again.
		if at := waiting[in.Action]; monoNow().Before(at) {
			o.retireRetry[in.Action] = at
			o.noteRetirementRetry(at)
			continue
		}
		a, readErr := o.ledger.Attempt(in.Action)
		if readErr != nil {
			if reason, refused := admission.ReasonOf(readErr); refused && reason == admission.ReasonInvalid {
				readErr = fmt.Errorf("%w: intent is missing its attempt", admission.ErrCorruptRecord)
			}
			errs = errors.Join(errs, o.retirementResult(in.Action, fmt.Errorf("reading retirement attempt %s: %w", in.Action, readErr)))
			continue
		}
		if a.State != admission.StateUnknown || a.Retired {
			delete(o.retireDelay, in.Action)
			delete(o.retireFaults, in.Action)
			continue
		}
		if o.now.Before(in.ExpiresAt) {
			o.noteRetirement(in.ExpiresAt)
			continue
		}
		if len(due) == firewall.MaxBlockBatchMembers {
			o.noteRetirementRetry(monoNow())
			continue
		}
		due = append(due, in)
	}
	if len(due) == 0 {
		return errs
	}
	if o.degraded {
		o.backoffRetirement()
		return errs
	}
	engine := o.opts.Blocks()
	if engine == nil {
		o.backoffRetirement()
		return errs
	}
	members := make([]firewall.BlockAction, len(due))
	for i, in := range due {
		addr, _ := in.Target.Addr()
		members[i] = firewall.BlockAction{Action: string(in.Action), IP: addr.String()}
	}
	gone, checked := o.checkRetirements(engine, members)
	if !checked {
		return errs
	}
	o.retireAfter = due[len(due)-1].Action
	for i, in := range due {
		if !gone[i] {
			o.retryRetirement(in.Action, retireRecheck)
			continue
		}
		_, _, _, err = retireLedger(o.ledger, in.Action)
		if err != nil {
			err = fmt.Errorf("retiring %s: %w", in.Action, err)
		}
		errs = errors.Join(errs, o.retirementResult(in.Action, err))
	}
	return errs
}

// Reads and writes share the same retry policy: damage must not fail every
// turn or keep unrelated attempts from reaching the engine.
func (o *Owner) retirementResult(id admission.ActionID, err error) error {
	switch _, refused := admission.ReasonOf(err); {
	case err == nil:
		delete(o.retireDelay, id)
		delete(o.retireFaults, id)
	case errors.Is(err, admission.ErrCorruptRecord), errors.Is(err, admission.ErrTransitionConflict):
		reported := o.retireFaults[id]
		o.retireFaults[id] = true
		o.retryRetirement(id, retireRecheck)
		if !reported {
			return err
		}
	case errors.Is(err, admission.ErrNotReady), refused:
		// Delivery or the ledger clock has not caught up. Keep a future
		// wake even if no new candidates arrive.
		o.retryRetirementLater(id)
	default:
		o.retryRetirementLater(id)
		return err
	}
	return nil
}

// checkRetirements asks the engine about members. A failed or short answer
// backs off without failing the turn.
func (o *Owner) checkRetirements(engine BlockEngine, members []firewall.BlockAction) ([]bool, bool) {
	gone, err := engine.RetireBlockActions(members)
	if err != nil || len(gone) != len(members) {
		o.backoffRetirement()
		return nil, false
	}
	o.retireWait, o.retireAt = 0, time.Time{}
	return gone, true
}

// backoffRetirement delays the next pass while nothing can be checked: an
// engine that fails or is missing, or a degraded clock. The wait starts at
// one second and doubles to a minute; a successful check resets it.
func (o *Owner) backoffRetirement() {
	o.retireWait = min(max(2*o.retireWait, firstProbeWait), maxProbeWait)
	o.retireAt = monoNow().Add(o.retireWait)
	o.noteRetirementRetry(o.retireAt)
}

// retryRetirementLater holds one attempt back while the ledger refuses
// to retire it: one second, doubling to retireRecheck.
func (o *Owner) retryRetirementLater(id admission.ActionID) {
	wait := min(max(2*o.retireDelay[id], firstProbeWait), retireRecheck)
	o.retireDelay[id] = wait
	o.retryRetirement(id, wait)
}

// retryRetirement holds one attempt back for wait on the monotonic clock.
func (o *Owner) retryRetirement(id admission.ActionID, wait time.Duration) {
	at := monoNow().Add(wait)
	o.retireRetry[id] = at
	o.noteRetirementRetry(at)
}

// noteRetirement keeps the earliest admission time a retirement pass is due.
func (o *Owner) noteRetirement(at time.Time) {
	if o.retireDue.IsZero() || at.Before(o.retireDue) {
		o.retireDue = at
	}
}

// Retry deadlines stay on the monotonic clock across slow calls and
// degraded admission readings. Only future expiries need conversion.
func (o *Owner) noteRetirementRetry(at time.Time) {
	if o.retireNext.IsZero() || at.Before(o.retireNext) {
		o.retireNext = at
	}
}

func (o *Owner) retirementWake(sample time.Time) time.Time {
	at := o.retireNext
	if !o.retireDue.IsZero() {
		expires := sample.Add(max(o.retireDue.Sub(o.now), 0))
		if at.IsZero() || expires.Before(at) {
			at = expires
		}
	}
	if !at.IsZero() && o.retireAt.After(at) {
		at = o.retireAt
	}
	return at
}
