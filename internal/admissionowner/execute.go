package admissionowner

import (
	"errors"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// BlockEngine runs batches of timed full-address blocks. The firewall
// engine is one on every platform; only Linux runs them.
type BlockEngine interface {
	CheckBlockBatchEffects(members []firewall.BlockMember) ([]firewall.BlockCheck, error)
	// RetireBlockActions reports which unknown attempts left nothing in the
	// kernel and removes their own rows.
	RetireBlockActions(actions []firewall.BlockAction) ([]bool, error)
	ApplyBlockBatch(members []firewall.BlockMember) ([]firewall.BlockResult, error)
	// LeaseNow is the clock the engine turns expiries into kernel
	// timeouts against. A first attempt's expiry is set on it.
	LeaseNow() time.Time
	// MarkBlockActionsUnverified with no actions writes the safe state
	// again while a failed state write holds batches, and so releases it.
	MarkBlockActionsUnverified(actions []string) (int, error)
	ProbeBlockState() error
}

// errNoEngine holds execution while no firewall engine runs.
var errNoEngine = errors.New("the firewall engine is not running")

// Probe waits while execution is held (spec 5.16: 1 s doubling to 60 s).
const (
	firstProbeWait = time.Second
	maxProbeWait   = time.Minute
)

// batchEvery spaces batch starts (spec 5.5: one a second at most).
const batchEvery = time.Second

// execPick is a block_ip pick of the turn with its candidate.
type execPick struct {
	pick admission.Pick
	c    admission.Candidate
}

type pendingFinish struct {
	id          admission.ActionID
	disposition admission.Disposition
	rejected    bool
	// existing is a failure because a proven block already holds the
	// address: after a fresh proof of member, the pick ends linked to that
	// block instead of retrying against it.
	existing bool
	member   firewall.BlockMember
}

// refusalReasons are the admission reasons for the engine's refusals of a
// member before it is reserved (spec 5.16): a full set or an unproven hold
// defers it; the rest end it without a charge. An existing effect ends
// linked to its block (endExisting). A refusal missing here (a duplicate
// address in the batch) leaves the pick queued for a later turn.
var refusalReasons = map[firewall.BlockRefusal]admission.Reason{
	firewall.BlockRefusedFull:        admission.ReasonSetFull,
	firewall.BlockRefusedPending:     admission.ReasonPendingRecovery,
	firewall.BlockRefusedInvalid:     admission.ReasonInvalid,
	firewall.BlockRefusedExpired:     admission.ReasonStale,
	firewall.BlockRefusedUnsupported: admission.ReasonUnsupportedContainment,
	firewall.BlockRefusedProtected:   admission.ReasonProtected,
	firewall.BlockRefusedAllowed:     admission.ReasonProtected,
}

// execute runs the turn's block picks as one batch (spec 5.5: one batch
// start per turn, one in flight). The engine checks every member against
// one snapshot before anything is reserved; the members it accepts are
// reserved and charged, recorded as running with their intents, applied
// and finished by their own effect. Nothing runs again: a failure keeps
// its charge and the ledger retries it after its backoff, and an unknown
// outcome holds its address until recovery retires it.
func (o *Owner) execute(picks []execPick) error {
	engine := o.opts.Blocks()
	// A degraded clock cannot bound a lease: the admission time stays at
	// its high-water mark while the wall clock is behind it or disagrees
	// with elapsed time. The engine encodes against its own lease clock.
	if o.degraded || !o.ready(engine, true) {
		return o.deferBlocks(picks, admission.ReasonEngineUnavailable)
	}
	// Picks before the next batch start stay queued as they are.
	if monoNow().Before(o.nextBatch) {
		return nil
	}
	picks = o.isolate(picks)
	// After a step back the engine's clock leads the wall clock: an expiry
	// set on the admission clock would lose that lead from its lifetime.
	lease := engine.LeaseNow()
	members := make([]firewall.BlockMember, len(picks))
	for i, p := range picks {
		next, err := admission.NewAttempt(p.pick.ID, p.c.Attempts+1)
		if err != nil {
			return fmt.Errorf("naming the attempt of pick %s: %w", p.pick.ID, err)
		}
		addr, _ := p.c.Key.Target.Addr()
		members[i] = firewall.BlockMember{Action: string(next.ID), IP: addr.String(), Reason: "CSM auto-block: " + p.c.Check, ExpiresAt: o.expiryOf(p.c, lease)}
	}
	checks, err := engine.CheckBlockBatchEffects(members)
	if err == nil && len(checks) != len(members) {
		err = fmt.Errorf("%d answers for %d members", len(checks), len(members))
		o.probeCheck = true
	}
	if err != nil {
		o.hold(fmt.Errorf("checking a block batch: %w", err), false)
		return o.deferBlocks(picks, admission.ReasonEngineUnavailable)
	}
	o.probeCheck = false
	if o.execHold != nil && o.applyHold == nil {
		o.release()
	}
	var run []int
	var stopped error
	for i, p := range picks {
		if checks[i].Refusal == firewall.BlockRefusedExisting {
			if err = o.endExisting(p, linkOf(checks[i].Existing)); err != nil {
				// A link the ledger refuses (no history budget for it, or
				// no name) leaves the pick queued, deferred when the reason
				// is a deferral; the next check tries again. Only a failed
				// write stops the batch.
				reason, refused := admission.ReasonOf(err)
				if !refused {
					stopped = err
					break
				}
				if reason.Disposition() == admission.DispositionDeferred {
					if err = o.endPick(p, reason); err != nil {
						stopped = err
						break
					}
				}
			}
			continue
		}
		if checks[i].Refusal != "" {
			if reason, known := refusalReasons[checks[i].Refusal]; known {
				if err = o.endPick(p, reason); err != nil {
					stopped = err
					break
				}
			}
			continue
		}
		_, a, granted, reserveErr := reserveLedger(o.ledger, p.pick.ID, p.pick.Lane, members[i].ExpiresAt)
		if reserveErr != nil {
			if reason, refused := admission.ReasonOf(reserveErr); refused {
				if err = o.endPick(p, reason); err != nil {
					stopped = err
					break
				}
				continue
			}
			if errors.Is(reserveErr, admission.ErrNotReady) || errors.Is(reserveErr, admission.ErrLaneIneligible) {
				continue
			}
			stopped = fmt.Errorf("reserving pick %s: %w", p.pick.ID, reserveErr)
			break
		}
		if !granted {
			stopped = fmt.Errorf("reserving pick %s: %w", p.pick.ID, admission.ErrTransitionConflict)
			break
		}
		members[i].Action = string(a.Attempt.ID)
		run = append(run, i)
	}
	if len(run) == 0 {
		if o.execHold != nil && o.applyHold != nil {
			o.hold(o.execHold, true)
		}
		return stopped
	}
	ids := make([]admission.ActionID, len(run))
	batch := make([]firewall.BlockMember, len(run))
	for k, i := range run {
		ids[k], batch[k] = admission.ActionID(members[i].Action), members[i]
	}
	// A batch the ledger will not record as running dispatches nothing.
	if _, granted, executeErr := executeLedger(o.ledger, ids); executeErr != nil || !granted {
		if o.execHold != nil && o.applyHold != nil {
			o.hold(o.execHold, true)
		}
		err = executeErr
		if executeErr == nil {
			return errors.Join(stopped, admission.ErrTransitionConflict, o.finishAll(ids, admission.DispositionUnknown))
		}
		failErr := o.finishAll(ids, admission.DispositionFailed)
		if _, refused := admission.ReasonOf(err); refused {
			return errors.Join(stopped, failErr)
		}
		return errors.Join(fmt.Errorf("running a block batch: %w", err), stopped, failErr)
	}
	o.nextBatch = monoNow().Add(batchEvery)
	results, err := engine.ApplyBlockBatch(batch)
	if err == nil && len(results) != len(batch) {
		// Something may have run: no answer proves which members failed.
		o.hold(fmt.Errorf("applying a block batch: %d results for %d members", len(results), len(batch)), true)
		return errors.Join(stopped, o.finishAll(ids, admission.DispositionUnknown))
	}
	if err != nil {
		// An error means nothing was written or sent.
		o.hold(fmt.Errorf("applying a block batch: %w", err), !errors.Is(err, firewall.ErrBlockBatchState))
		return errors.Join(stopped, o.finishAll(ids, admission.DispositionFailed))
	}
	var stateErr, applyErr error
	var applied bool
	for k, r := range results {
		applied = applied || r.Effect == firewall.BlockApplied
		if errors.Is(r.Err, firewall.ErrBlockBatchState) {
			stateErr = r.Err
		} else if r.Err != nil && !errors.Is(r.Err, firewall.ErrBlockBatchRejected) {
			applyErr = r.Err
		}
		o.finishes = append(o.finishes, pendingFinish{
			id: ids[k], disposition: effectDisposition(r.Effect),
			rejected: r.Effect == firewall.BlockFailed && errors.Is(r.Err, firewall.ErrBlockBatchRejected),
			existing: r.Effect == firewall.BlockFailed && r.Refusal == firewall.BlockRefusedExisting,
			member:   batch[k],
		})
	}
	switch {
	case stateErr != nil:
		// Repair the state first, retaining any independent apply fault.
		if applyErr != nil {
			o.applyHold = applyErr
		}
		o.hold(stateErr, false)
	case applyErr != nil:
		o.hold(applyErr, true)
	case o.execHold != nil && o.applyHold != nil && !applied:
		o.hold(o.execHold, true)
	case o.execHold != nil:
		o.release()
	}
	return errors.Join(stopped, o.finishPending())
}

// ready reports whether automatic execution may run this turn (P8, spec
// 5.16). Without an engine it is held. While held, one probe runs per wait:
// state repair is followed by a read-only snapshot proof, including on an
// idle turn. Apply faults keep their wait through a successful snapshot
// and member check until an apply succeeds. A newly available engine can
// serve at once. When checking members next, keep the hold until that
// check succeeds too: a probe alone cannot reset a failing turn's wait.
func (o *Owner) ready(engine BlockEngine, checking bool) bool {
	if engine == nil {
		if !errors.Is(o.execHold, errNoEngine) {
			o.hold(errNoEngine, false)
		}
		return false
	}
	switch {
	case o.execHold == nil:
		return true
	case errors.Is(o.execHold, errNoEngine):
		o.release()
		return true
	case monoNow().Before(o.probeAt):
		return false
	case errors.Is(o.execHold, firewall.ErrBlockBatchState):
		if _, err := engine.MarkBlockActionsUnverified(nil); err != nil {
			o.hold(err, false)
			return false
		}
	}
	if err := engine.ProbeBlockState(); err != nil {
		o.hold(err, false)
		return false
	}
	if o.applyHold == nil && !o.probeCheck && !checking {
		o.release()
	} else {
		if o.applyHold != nil {
			o.execHold = o.applyHold
			o.publishExecutionHold()
		}
		o.probeAt = monoNow().Add(o.probeWait)
	}
	return true
}

// hold stops automatic execution for cause until a probe succeeds; each
// hold while already held doubles the wait for the next probe, up to a
// minute.
func (o *Owner) hold(cause error, apply bool) {
	switch {
	case o.execHold == nil:
		o.probeWait = firstProbeWait
	case o.probeWait < maxProbeWait:
		o.probeWait = min(2*o.probeWait, maxProbeWait)
	}
	if apply {
		o.applyHold = cause
	}
	o.execHold, o.probeAt = cause, monoNow().Add(o.probeWait)
	o.publishExecutionHold()
}

func (o *Owner) release() {
	o.execHold, o.probeAt, o.probeWait = nil, time.Time{}, 0
	o.applyHold, o.probeCheck = nil, false
	o.publishExecutionHold()
}

// publishExecutionHold preserves the age of the cached ledger sample.
func (o *Owner) publishExecutionHold() {
	previous := o.current.Load()
	snapshot, owner := *previous, *previous.Owner
	owner.ExecutionHeld = ""
	if o.execHold != nil {
		owner.ExecutionHeld = o.execHold.Error()
	}
	snapshot.Owner = &owner
	o.current.Store(&snapshot)
}

// isolate keeps a member the kernel rejected from failing healthy ones
// again (P9, spec 5.5): while a pick's last batch was rejected, the turn
// runs that pick alone and leaves the others queued for later turns.
// Only queued retries remain isolated; terminal, displaced and aged-out
// candidates leave the index at the next successful queue publication.
func (o *Owner) isolate(picks []execPick) []execPick {
	for _, p := range picks {
		if _, ok := o.isolated[p.pick.ID]; ok {
			return []execPick{p}
		}
	}
	return picks
}

// A displaced, terminal or aged-out candidate cannot retry alone.
func (o *Owner) forgetIsolated(snap *admission.QueueSnapshot) {
	if len(o.isolated) == 0 {
		return
	}
	live := make(map[admission.CandidateID]bool, len(snap.Items))
	for _, item := range snap.Items {
		live[admission.CandidateID(item.Key)] = true
	}
	for id, expires := range o.isolated {
		if !live[id] || !o.now.Before(expires) {
			delete(o.isolated, id)
		}
	}
}

// effectDisposition is the outcome the ledger records for an effect; one
// the owner does not know proves nothing.
func effectDisposition(e firewall.BlockEffect) admission.Disposition {
	switch e {
	case firewall.BlockApplied:
		return admission.DispositionApplied
	case firewall.BlockFailed:
		return admission.DispositionFailed
	}
	return admission.DispositionUnknown
}

// endExisting ends a pick before it is reserved because a proven block
// already enforces its effect, linked to that block (spec 5.16, 5.17).
func (o *Owner) endExisting(p execPick, link admission.EffectLink) error {
	if _, err := terminateExistingLedger(o.ledger, p.pick.ID, link); err != nil {
		return fmt.Errorf("ending pick %s: %w", p.pick.ID, err)
	}
	return nil
}

// linkOf is the ledger's link to the block the engine named.
func linkOf(b firewall.ExistingBlock) admission.EffectLink {
	return admission.EffectLink{Effect: b.ID, ExpiresAt: b.ExpiresAt}
}

// endPick defers or ends a pick before it is reserved.
func (o *Owner) endPick(p execPick, reason admission.Reason) error {
	var err error
	switch reason.Disposition() {
	case admission.DispositionDeferred:
		// Deferring again for the same reason changes nothing but still
		// commits; a long hold would pay that per pick every turn.
		if p.c.Reason == reason {
			return nil
		}
		_, err = o.ledger.Defer(p.pick.ID, reason)
	case admission.DispositionRefused, admission.DispositionWithheld, admission.DispositionDropped:
		_, err = terminateLedger(o.ledger, p.pick.ID, reason)
	default:
		err = fmt.Errorf("reason %s ends nothing", reason)
	}
	if err != nil {
		return fmt.Errorf("ending pick %s: %w", p.pick.ID, err)
	}
	return nil
}

func (o *Owner) deferBlocks(picks []execPick, reason admission.Reason) error {
	for _, p := range picks {
		if err := o.endPick(p, reason); err != nil {
			return err
		}
	}
	return nil
}

func (o *Owner) finishAll(ids []admission.ActionID, d admission.Disposition) error {
	for _, id := range ids {
		o.finishes = append(o.finishes, pendingFinish{id: id, disposition: d})
	}
	return o.finishPending()
}

// finishPending attempts every outstanding write even if another fails.
// Only writes retry; the engine is never called again for these attempts.
func (o *Owner) finishPending() error {
	var err error
	pending := o.finishes[:0]
	for _, outcome := range o.finishes {
		var c admission.Candidate
		var a admission.AttemptRecord
		var finishErr error
		linked := false
		if outcome.existing {
			// Finishing can retry long after the apply-time proof expires.
			// Only a fresh proof may end the pick as already covered, and
			// it ends with the attempt's failure in one write. Any failure
			// of that attempts the plain failure at once. If both writes
			// fail the pending outcome holds new work until a later retry.
			link, proofErr := o.proveExisting(outcome.member)
			switch {
			case proofErr != nil:
				err = errors.Join(err, fmt.Errorf("checking existing effect for %s: %w", outcome.id, proofErr))
			case link != (admission.EffectLink{}):
				if c, a, finishErr = finishExistingLedger(o.ledger, outcome.id, link); finishErr != nil {
					// A refused link is expected (no history budget): the
					// plain failure below records the outcome instead.
					if _, refused := admission.ReasonOf(finishErr); !refused {
						err = errors.Join(err, fmt.Errorf("ending %s as an existing effect: %w", outcome.id, finishErr))
					}
				} else {
					linked = true
				}
			}
		}
		if !linked {
			c, a, finishErr = finishLedger(o.ledger, outcome.id, outcome.disposition)
		}
		if finishErr != nil {
			err = errors.Join(err, fmt.Errorf("finishing %s: %w", outcome.id, finishErr))
			// A damaged record, an attempt already ended another way or a
			// refused outcome cannot be written by retrying: the attempt
			// stays unresolved and holds its target until recovery.
			if _, refused := admission.ReasonOf(finishErr); !refused && !errors.Is(finishErr, admission.ErrCorruptRecord) && !errors.Is(finishErr, admission.ErrTransitionConflict) {
				pending = append(pending, outcome)
			}
			continue
		}
		id := a.Attempt.Candidate
		if c.State == admission.StateUnknown {
			o.noteRetirement(c.ExpiresAt)
		}
		if c.State == admission.StateQueued && outcome.rejected {
			if o.isolated == nil {
				o.isolated = map[admission.CandidateID]time.Time{}
			}
			expires := c.ExpiresAt
			if c.AgeOut.Before(expires) {
				expires = c.AgeOut
			}
			o.isolated[id] = expires
		} else {
			delete(o.isolated, id)
		}
	}
	o.finishes = pending
	return err
}

// proveExisting checks member again and links the block that now proves
// it is already enforced; zero when nothing does (the engine names a block
// only for an existing effect).
func (o *Owner) proveExisting(member firewall.BlockMember) (admission.EffectLink, error) {
	engine := o.opts.Blocks()
	if engine == nil {
		return admission.EffectLink{}, errNoEngine
	}
	checks, err := engine.CheckBlockBatchEffects([]firewall.BlockMember{member})
	if err != nil {
		return admission.EffectLink{}, err
	}
	if len(checks) != 1 {
		return admission.EffectLink{}, fmt.Errorf("%d answers for one existing effect", len(checks))
	}
	return linkOf(checks[0].Existing), nil
}
