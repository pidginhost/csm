package admissionowner

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// sessionRand is where forecast session IDs come from; tests make it fail.
var sessionRand io.Reader = rand.Reader

// forecasting reports whether the turn forecasts its picks instead of
// running them: an executable owner under an installed dry-run policy.
func (o *Owner) forecasting() bool {
	return o.executable() && o.policyErr == nil && o.policy.DryRun
}

// beginForecast starts a forecast session unless one runs (spec 3.4, 3.7).
// The turn has finished the live outcomes already returned and made a
// reading, so the session copies the committed ceiling and its charges,
// spent credit included; nothing is copied again while it runs. A failure
// holds forecasting and fails the turn.
func (o *Owner) beginForecast() error {
	if o.shadow != nil {
		return nil
	}
	id, err := newSessionID(sessionRand)
	if err != nil {
		o.noteForecastError(forecastSessionID)
		return fmt.Errorf("naming a forecast session: %w", err)
	}
	ceiling, charges, err := o.ledger.ForecastSeed()
	if err != nil {
		o.noteForecastError(forecastLedgerUnavailable)
		return fmt.Errorf("reading the ceiling for a forecast: %w", err)
	}
	s, err := newShadow(id, time.Now(), o.forecastReset, ceiling, charges)
	if err != nil {
		o.noteForecastError(forecastLedgerUnavailable)
		return fmt.Errorf("starting a forecast: %w", err)
	}
	o.shadow, o.forecastReset = s, resetModeChange
	o.forecastErr, o.forecastErrAt = "", time.Time{}
	return nil
}

// dropForecast ends a session whose model cannot go on. The next session
// starts from the real state and names the failure as its reset.
func (o *Owner) dropForecast() {
	o.endSession(resetModelError)
	o.noteForecastError(forecastModelError)
}

// endSession discards the forecast session, keeping its identity for
// status, and names why the next one starts.
func (o *Owner) endSession(next resetReason) {
	if s := o.shadow; s != nil {
		o.out.last = sessionInfo{id: s.id, since: s.since, reset: s.reset}
	}
	o.shadow, o.forecastReset = nil, next
}

// noteForecastError records why forecasting failed, for status.
func (o *Owner) noteForecastError(e forecastError) {
	o.forecastErr, o.forecastErrAt = e, time.Now().UTC()
}

// forecast serves the turn under a dry-run policy (spec 3.1-3.5). The
// selection ignores live budgets and defers nothing for capacity. A
// block_ip pick is forecast against the session's model; another firewall
// kind ends as not_modelled; a challenge keeps its comparison preview.
// Nothing is reserved, charged or applied, and the engine is only read.
func (o *Owner) forecast() (err error) {
	if err = o.refuseDisabled(); err != nil {
		o.noteForecastError(forecastLedgerUnavailable)
		return err
	}
	if err = o.beginForecast(); err != nil {
		return err
	}
	// A turn that ends without naming another cause clears the error; one
	// that fails anywhere else could not use the ledger.
	o.forecastErr = ""
	defer func() {
		if err != nil && o.forecastErr == "" {
			o.noteForecastError(forecastLedgerUnavailable)
		}
	}()
	// Examples of committed endings are written even when a later pick
	// stops the turn.
	defer o.flushExamples()
	picks, err := previewLedger(o.ledger, o.answers())
	if err != nil {
		return fmt.Errorf("selecting dry-run work: %w", err)
	}
	var blocks []execPick
	for _, p := range picks {
		c, readErr := o.ledger.Candidate(p.ID)
		if readErr != nil {
			return fmt.Errorf("reading pick %s: %w", p.ID, readErr)
		}
		pick := execPick{pick: p, c: c}
		switch {
		case c.Key.Kind == admission.KindBlockIP:
			blocks = append(blocks, pick)
		case c.Key.Kind == admission.KindChallenge:
			// The selection passes over a challenge the live history
			// budget cannot pay for; one its reservation still cannot
			// take waits as a schedule defers it.
			err = o.preview(pick)
			if reason, refused := admission.ReasonOf(err); refused {
				err = o.endPick(pick, reason)
			} else if errors.Is(err, admission.ErrNotReady) || errors.Is(err, admission.ErrLaneIneligible) {
				err = nil
			}
		case o.degraded:
			// A degraded clock freezes every prediction.
			o.noteForecastError(forecastClockDegraded)
			err = o.endPick(pick, admission.ReasonEngineUnavailable)
		default:
			err = o.endForecast(pick, admission.PredictNotModelled, nil)
		}
		if err != nil {
			return err
		}
	}
	return o.forecastBlocks(blocks)
}

// forecastBlocks forecasts the turn's block_ip picks in scheduler order
// (spec 3.3). One read-only snapshot answers their local checks and the
// real temporary occupancy, with the real blocks of forecast addresses. A
// refused target ends or waits as a live check has it. A real block that
// already covers the address ends the pick as existing_actual, and a
// usable panel allow as verdict_allow, before any modelled capacity is
// judged. A covering or shorter forecast block, or a modelled set with
// neither a free slot in a partition the pick may occupy nor a strictly
// lower-tier block it may replace nor an equal-tier block it may rotate
// out, ends it without a call. The turn's picks share the modelled set
// as a live schedule cycle's queued work does.
// With the callback on, any other pick is asked about first (D8) and waits
// for its answer with no forecast change; then the forecast bound or the
// modelled ceiling can still end it. Only a capacity
// admission, with or without a replacement or rotation, changes the model. Without an engine, snapshot or sound clock
// the picks wait, with no call or forecast change.
func (o *Owner) forecastBlocks(picks []execPick) error {
	if len(picks) == 0 {
		return nil
	}
	engine := o.opts.Blocks()
	if o.degraded || engine == nil {
		cause := forecastEngineUnavailable
		if o.degraded {
			cause = forecastClockDegraded
		}
		o.noteForecastError(cause)
		o.shadow.adm = nil
		return o.deferBlocks(picks, admission.ReasonEngineUnavailable)
	}
	lease := engine.LeaseNow()
	o.shadow.expire(lease)
	members := make([]firewall.BlockMember, len(picks))
	for i, p := range picks {
		m, err := o.memberOf(p, lease)
		if err != nil {
			return err
		}
		// The session's own same-episode re-admission: a block returning
		// to an address whose forecast block it replaced lasts no longer
		// than that block would have.
		if until, ok := o.shadow.answered[m.IP]; ok && p.c.Attempts == 0 && until.Before(m.ExpiresAt) {
			m.ExpiresAt = until
		}
		members[i] = m
	}
	adm, err := engine.BlockAdmissionSnapshot(members, o.shadow.ips())
	if err != nil || !answersMatch(adm.Answers, members) {
		cause := forecastSnapshotMismatch
		if err != nil {
			cause = forecastEngineUnavailable
		}
		o.noteForecastError(cause)
		o.shadow.adm = nil
		return o.deferBlocks(picks, admission.ReasonEngineUnavailable)
	}
	occupancy := adm
	occupancy.Answers = nil
	o.shadow.adm = &occupancy
	o.shadow.share(adm, o.now, waitingOf(picks))
	for i, p := range picks {
		m, check := members[i], adm.Answers[i].BlockCheck
		if check.Refusal != "" && check.Refusal != firewall.BlockRefusedExisting {
			if _, err = o.endRefused(p, check); err != nil {
				return err
			}
			continue
		}
		rank := rankOf(p, m, false)
		r, answered := o.readyVerdict(p.pick.ID, p.c, m.IP, m.Reason)
		var change *shadowChange
		pred := o.shadow.covering(m.IP, m.ExpiresAt)
		switch {
		case check.Refusal == firewall.BlockRefusedExisting:
			pred = admission.PredictExistingActual
		case answered && r.Answer == answerAllow:
			if err = o.endAllowed(p, r); err != nil {
				return err
			}
			continue
		case pred == 0:
			// Existing coverage and a usable allow need no rotation proof.
			if rank.fresh, err = o.freshPick(p, m.IP); err != nil {
				return fmt.Errorf("reading the episode of pick %s: %w", p.pick.ID, err)
			}
			pred = o.shadow.wait(adm, lanesOf(p.pick), rank, o.now)
		}
		if pred == 0 {
			if o.policy.VerdictEnabled && !answered {
				o.askVerdict(p.pick.ID, p.c, m.IP, m.Reason)
				continue
			}
			if pred, change, err = o.shadow.admit(m.IP, p.c.Key.Kind, m.ExpiresAt, lanesOf(p.pick), o.now, adm, rank); err != nil {
				o.noteForecastError(forecastModelError)
				return fmt.Errorf("forecasting pick %s: %w", p.pick.ID, err)
			}
		}
		if err = o.endForecast(p, pred, change); err != nil {
			return err
		}
	}
	return nil
}

// rankOf ranks the forecast block of pick p, block member m, as a victim:
// the pick's tier, the action of its next attempt and its address, with
// its scope and whether it is fresh.
func rankOf(p execPick, m firewall.BlockMember, fresh bool) shadowRank {
	return shadowRank{tier: p.pick.Tier, action: admission.ActionID(m.Action), target: p.c.Key.Target, scope: p.c.Scope.Key(), fresh: fresh}
}

// freshPick reports whether forecast pick p for ip may rotate an
// equal-tier block (spec 5.2): its episode row says so, as a live
// schedule reads it, and no forecast block of ip left the model before
// that block's expiry, so its episode has had no forecast response.
func (o *Owner) freshPick(p execPick, ip string) (bool, error) {
	if _, answered := o.shadow.answered[ip]; answered {
		return false, nil
	}
	return freshLedger(o.ledger, p.c)
}

// waitingOf is the scopes of a turn's block picks by the partitions they
// may occupy, as a live schedule cycle counts its queued block work
// (spec 5.6): general, and reserved too for work with a reserved lane.
func waitingOf(picks []execPick) map[admission.Partition][]string {
	out := map[admission.Partition][]string{}
	for _, p := range picks {
		for _, lane := range lanesOf(p.pick) {
			part := admission.PartitionOf(lane)
			out[part] = append(out[part], p.c.Scope.Key())
		}
	}
	for part := range out {
		slices.Sort(out[part])
		out[part] = slices.Compact(out[part])
	}
	return out
}

// lanesOf is the order a forecast charges p: the lane the selection served
// it on, then the other allowance it is eligible for. General-only work
// never borrows reserved credit.
func lanesOf(p admission.Pick) []admission.Lane {
	switch {
	case p.Lane != admission.LaneGeneral:
		return []admission.Lane{p.Lane, admission.LaneGeneral}
	case p.Reserved != 0:
		return []admission.Lane{admission.LaneGeneral, p.Reserved}
	}
	return []admission.Lane{admission.LaneGeneral}
}

// endForecast ends p as a dry run with its prediction and installs the
// decision in the forecast and the comparison once the ending commits, so
// a retried ending never counts or charges twice (spec 3.5). A refusal the
// ending meets defers or ends p as a reservation would. A failed write
// stops the turn and leaves the forecast as it was.
func (o *Owner) endForecast(p execPick, pred admission.Prediction, change *shadowChange) error {
	_, changed, err := endDryRunLedger(o.ledger, p.pick.ID)
	if reason, refused := admission.ReasonOf(err); refused {
		return o.endPick(p, reason)
	}
	switch {
	case errors.Is(err, admission.ErrNotReady):
		return nil
	case err != nil:
		return fmt.Errorf("ending pick %s as a dry run: %w", p.pick.ID, err)
	case changed:
		delete(o.verdicts.ready, p.pick.ID)
		if change != nil {
			o.noteExample(p, change)
		}
		o.noteSummary(p, pred, change)
		o.shadow.commit(pred, change, monoNow())
		c := p.c
		o.compare.addAt(compareKey{entry: c.Entry, check: c.Check, kind: c.Key.Kind, decision: decisionDryRun, prediction: pred}, o.now)
	}
	return nil
}
