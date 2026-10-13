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
}

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
	if engine == nil {
		return o.deferBlocks(picks, admission.ReasonEngineUnavailable)
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
	}
	if err != nil {
		return errors.Join(fmt.Errorf("checking a block batch: %w", err), o.deferBlocks(picks, admission.ReasonEngineUnavailable))
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
	results, err := engine.ApplyBlockBatch(batch)
	if err == nil && len(results) != len(batch) {
		// Something may have run: no answer proves which members failed.
		return errors.Join(fmt.Errorf("applying a block batch: %d results for %d members", len(results), len(batch)), stopped, o.finishAll(ids, admission.DispositionUnknown))
	}
	if err != nil {
		// An error means nothing was written or sent.
		return errors.Join(fmt.Errorf("applying a block batch: %w", err), stopped, o.finishAll(ids, admission.DispositionFailed))
	}
	var finishErr error
	for k, r := range results {
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
	return errors.Join(stopped, finishErr)
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
