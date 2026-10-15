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
// missing engine retires nothing and tries again a second later; a held
// attempt waits a minute on its own, so a held batch cannot starve the
// intents behind it.
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
		return fmt.Errorf("reading unresolved intents: %w", err)
	}
	o.retireDue, o.retireNext = time.Time{}, time.Time{}
	waiting := make(map[admission.ActionID]time.Time)
	var due []admission.Intent
	// Intents are in action order. Rotate the scan so due retries cannot
	// starve the tail when a turn takes longer than their waits.
	start := sort.Search(len(intents), func(i int) bool { return intents[i].Action > o.retireAfter })
	for offset := range len(intents) {
		in := intents[(start+offset)%len(intents)]
		if in.Kind != admission.KindBlockIP {
			continue
		}
		a, readErr := o.ledger.Attempt(in.Action)
		if readErr != nil {
			return fmt.Errorf("reading retirement attempt %s: %w", in.Action, readErr)
		}
		if a.State != admission.StateUnknown || a.Retired {
			continue
		}
		if o.now.Before(in.ExpiresAt) {
			o.noteRetirement(in.ExpiresAt)
			continue
		}
		if at := o.retireRetry[in.Action]; monoNow().Before(at) {
			waiting[in.Action] = at
			o.noteRetirementRetry(at)
			continue
		}
		if len(due) == firewall.MaxBlockBatchMembers {
			o.noteRetirementRetry(monoNow())
			continue
		}
		due = append(due, in)
	}
	o.retireRetry = waiting
	if len(due) == 0 {
		return nil
	}
	if o.degraded {
		o.retireAt = monoNow().Add(firstProbeWait)
		o.noteRetirementRetry(o.retireAt)
		return nil
	}
	engine := o.opts.Blocks()
	if engine == nil {
		o.retireAt = monoNow().Add(firstProbeWait)
		o.noteRetirementRetry(o.retireAt)
		return nil
	}
	members := make([]firewall.BlockAction, len(due))
	for i, in := range due {
		addr, _ := in.Target.Addr()
		members[i] = firewall.BlockAction{Action: string(in.Action), IP: addr.String()}
	}
	gone, checked := o.checkRetirements(engine, members)
	if !checked {
		return nil
	}
	o.retireAfter = due[len(due)-1].Action
	var errs error
	for i, in := range due {
		if !gone[i] {
			o.retryRetirement(in.Action, retireRecheck)
			continue
		}
		_, _, _, err = retireLedger(o.ledger, in.Action)
		switch _, refused := admission.ReasonOf(err); {
		case err == nil:
		case errors.Is(err, admission.ErrNotReady), refused:
			// Delivery or the ledger clock has not caught up. Keep a
			// future wake even if no new candidates arrive.
			o.retryRetirement(in.Action, firstProbeWait)
		default:
			errs = errors.Join(errs, fmt.Errorf("retiring %s: %w", in.Action, err))
			o.retryRetirement(in.Action, firstProbeWait)
		}
	}
	return errs
}

// checkRetirements asks the engine about members. A failed or short answer
// backs off (1 s doubling to 60 s) without failing the turn.
func (o *Owner) checkRetirements(engine BlockEngine, members []firewall.BlockAction) ([]bool, bool) {
	gone, err := engine.RetireBlockActions(members)
	if err != nil || len(gone) != len(members) {
		o.retireWait = min(max(2*o.retireWait, firstProbeWait), maxProbeWait)
		o.retireAt = monoNow().Add(o.retireWait)
		o.noteRetirementRetry(o.retireAt)
		return nil, false
	}
	o.retireWait, o.retireAt = 0, time.Time{}
	return gone, true
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
