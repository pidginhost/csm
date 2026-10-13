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
	CheckBlockBatch(members []firewall.BlockMember) ([]firewall.BlockRefusal, error)
	ApplyBlockBatch(members []firewall.BlockMember) ([]firewall.BlockResult, error)
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

// refusalReasons are the admission reasons for the engine's refusals of a
// member before it is reserved (spec 5.16): a full set defers it; the
// rest end it without a charge. A refusal missing here (a duplicate
// address in the batch) leaves the pick queued for a later turn.
var refusalReasons = map[firewall.BlockRefusal]admission.Reason{
	firewall.BlockRefusedFull:        admission.ReasonSetFull,
	firewall.BlockRefusedExisting:    admission.ReasonExistingEffect,
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
	// its high-water mark while the wall clock the engine encodes against
	// is behind it or disagrees with elapsed time.
	if !o.ready(engine) || o.degraded {
		return o.deferBlocks(picks, admission.ReasonEngineUnavailable)
	}
	// Picks before the next batch start stay queued as they are.
	if monoNow().Before(o.nextBatch) {
		return nil
	}
	picks = o.isolate(picks)
	members := make([]firewall.BlockMember, len(picks))
	for i, p := range picks {
		next, err := admission.NewAttempt(p.pick.ID, p.c.Attempts+1)
		if err != nil {
			return fmt.Errorf("naming the attempt of pick %s: %w", p.pick.ID, err)
		}
		addr, _ := p.c.Key.Target.Addr()
		members[i] = firewall.BlockMember{Action: string(next.ID), IP: addr.String(), Reason: "CSM auto-block: " + p.c.Check, ExpiresAt: o.expiryOf(p.c)}
	}
	refusals, err := engine.CheckBlockBatch(members)
	if err == nil && len(refusals) != len(members) {
		err = fmt.Errorf("%d answers for %d members", len(refusals), len(members))
		o.probeCheck = true
	}
	if err != nil {
		o.hold(fmt.Errorf("checking a block batch: %w", err), false)
		return o.deferBlocks(picks, admission.ReasonEngineUnavailable)
	}
	o.probeCheck = false
	if o.execHold != nil && !o.probeApply {
		o.release()
	}
	var run []int
	var stopped error
	for i, p := range picks {
		if refusals[i] != "" {
			if reason, known := refusalReasons[refusals[i]]; known {
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
		if o.execHold != nil && o.probeApply {
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
		o.hold(fmt.Errorf("applying a block batch: %w", err), true)
		return errors.Join(stopped, o.finishAll(ids, admission.DispositionFailed))
	}
	var finishErr, stateErr error
	for k, r := range results {
		if errors.Is(r.Err, firewall.ErrBlockBatchState) {
			stateErr = r.Err
		}
		finished, _, finishOneErr := o.finishMember(ids[k], r)
		if err = finishOneErr; err != nil {
			finishErr = errors.Join(finishErr, fmt.Errorf("finishing %s: %w", ids[k], err))
		}
		id := picks[run[k]].pick.ID
		if finishOneErr == nil && finished.State == admission.StateQueued && r.Effect == firewall.BlockFailed && errors.Is(r.Err, firewall.ErrBlockBatchRejected) {
			if o.isolated == nil {
				o.isolated = map[admission.CandidateID]time.Time{}
			}
			expires := batch[k].ExpiresAt
			if finished.AgeOut.Before(expires) {
				expires = finished.AgeOut
			}
			o.isolated[id] = expires
		} else {
			delete(o.isolated, id)
		}
	}
	if stateErr != nil {
		o.hold(stateErr, true)
	} else if o.execHold != nil {
		o.release()
	}
	return errors.Join(stopped, finishErr)
}

// ready reports whether automatic execution may run this turn (P8, spec
// 5.16). Without an engine it is held. While held, one probe runs per wait:
// state repair is followed by a read-only snapshot proof, including on an
// idle turn. Apply faults keep their wait through a successful snapshot
// and member check until an apply succeeds. A newly available engine can
// serve at once.
func (o *Owner) ready(engine BlockEngine) bool {
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
		o.probeApply = false
	}
	if err := engine.ProbeBlockState(); err != nil {
		o.hold(err, false)
		return false
	}
	if !o.probeApply && !o.probeCheck {
		o.release()
	} else {
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
		o.probeApply = apply
	case o.probeWait < maxProbeWait:
		o.probeWait = min(2*o.probeWait, maxProbeWait)
	}
	o.probeApply = o.probeApply || apply
	o.execHold, o.probeAt = cause, monoNow().Add(o.probeWait)
	o.publishExecutionHold()
}

func (o *Owner) release() {
	o.execHold, o.probeAt, o.probeWait = nil, time.Time{}, 0
	o.probeApply, o.probeCheck = false, false
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

// endPick defers or ends a pick before it is reserved.
func (o *Owner) endPick(p execPick, reason admission.Reason) error {
	var err error
	switch reason.Disposition() {
	case admission.DispositionDeferred:
		_, err = o.ledger.Defer(p.pick.ID, reason)
	case admission.DispositionRefused, admission.DispositionWithheld, admission.DispositionDropped:
		_, err = o.ledger.Terminate(p.pick.ID, reason)
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
	var err error
	for _, id := range ids {
		if _, _, finishErr := finishLedger(o.ledger, id, d); finishErr != nil {
			err = errors.Join(err, fmt.Errorf("finishing %s: %w", id, finishErr))
		}
	}
	return err
}

// finishMember keeps result metadata and its durable outcome on one path.
func (o *Owner) finishMember(id admission.ActionID, result firewall.BlockResult) (admission.Candidate, admission.AttemptRecord, error) {
	return finishLedger(o.ledger, id, effectDisposition(result.Effect))
}
