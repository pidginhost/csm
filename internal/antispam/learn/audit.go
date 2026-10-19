package learn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// AuditBatch is the number of targets one audit turn checks. Provisional
// until Plan C's benchmark records a measurement.
const AuditBatch = 50

// Retention is how long a cluster lives after its latest committed or
// reserved admission (spec 7.4).
const Retention = 90 * 24 * time.Hour

const (
	auditCursorKey  = "audit"
	repairCursorKey = "repair"
	watermarkKey    = "retire_watermark"
)

// AuditProgress reports one audit turn. Repaired counts targets scheduled
// for repair; OldestUnchecked is the start of the previous rotation, the
// latest time every target not yet checked in this one was checked.
type AuditProgress struct {
	Checked, Repaired int
	RotationDone      bool
	OldestUnchecked   time.Time
}

type auditCursor struct {
	After         Digest    `json:"after"`
	RotationStart time.Time `json:"rotation_start"`
	PrevStart     time.Time `json:"prev_start"`
}

// auditState is in memory on purpose: after a restart fresh matching waits
// for a complete rotation again.
type auditState struct {
	init         bool
	coverPending bool   // a full rotation is still owed
	coverFrom    Digest // cursor when the rotation became owed
	wrapped      bool
	coverReached bool
	covered      bool // fresh matching allowed
	rebuilding   bool
	drift        map[Digest]int
}

// FreshMatchingAllowed reports whether a full audit and repair rotation has
// completed since start or since anchors were found missing (spec 7.4).
func (p *Publisher) FreshMatchingAllowed() bool { return p.audit.covered }

// RebuildNeeded reports live anchors found missing and not yet restored by a
// full rotation (backend_rebuilding).
func (p *Publisher) RebuildNeeded() bool { return p.audit.rebuilding }

// RepeatedDrift counts digests found drifted more than once since start.
func (p *Publisher) RepeatedDrift() int {
	n := 0
	for _, c := range p.audit.drift {
		if c > 1 {
			n++
		}
	}
	return n
}

// owe makes fresh matching wait for a rotation that starts at from.
func (p *Publisher) owe(from Digest) {
	p.audit.coverPending, p.audit.coverFrom, p.audit.wrapped = true, from, false
	p.audit.coverReached, p.audit.covered = false, false
}

// AuditTurn checks the next batch of targets, live and zero, in a persisted
// round-robin order with one exact inspection. Drifted or unfinished
// targets become repair work; nothing is reset unconditionally.
func (p *Publisher) AuditTurn(ctx context.Context, batch int, now time.Time) (AuditProgress, error) {
	if batch <= 0 || batch > MaxExplicitDigests {
		batch = AuditBatch
	}
	var cur auditCursor
	var targets []Target
	err := p.ledger.View(func(v LedgerView) error {
		if _, err := v.get(store.LearnCursorBucket, []byte(auditCursorKey), &cur); err != nil {
			return err
		}
		return v.tx.Scan(store.LearnTargetsBucket, []byte(cur.After), func(_, data []byte) (bool, error) {
			var t Target
			if err := json.Unmarshal(data, &t); err != nil {
				return false, errors.New("learning ledger target is unreadable")
			}
			targets = append(targets, t)
			return len(targets) <= batch, nil
		})
	})
	if err != nil {
		return AuditProgress{}, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	if !p.audit.init {
		p.audit.init = true
		p.owe(cur.After)
	}
	more := len(targets) > batch
	if more {
		targets = targets[:batch]
	}
	if cur.RotationStart.IsZero() {
		cur.RotationStart = now
	}
	prog := AuditProgress{OldestUnchecked: cur.PrevStart, RotationDone: !more}
	if len(targets) > 0 {
		lost, err := p.check(ctx, targets, &prog)
		if err != nil {
			return AuditProgress{}, err
		}
		if lost {
			p.audit.rebuilding = true
			p.owe(cur.After)
		}
	}
	next := cur
	if more {
		next.After = targets[len(targets)-1].Digest
	} else {
		next = auditCursor{RotationStart: now, PrevStart: cur.RotationStart}
	}
	if err := p.ledger.Update(func(tx LedgerTx) error {
		return tx.put(store.LearnCursorBucket, []byte(auditCursorKey), next)
	}); err != nil {
		return AuditProgress{}, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	if p.audit.coverPending {
		switch {
		case !more && p.audit.coverFrom == "":
			p.audit.coverPending = false
		case !more:
			p.audit.wrapped = true
		case p.audit.wrapped && next.After >= p.audit.coverFrom:
			p.audit.coverPending = false
		}
		if !p.audit.coverPending {
			p.audit.coverReached = true
			if err := p.settle(); err != nil {
				return prog, err
			}
		}
	}
	return prog, nil
}

// check inspects targets exactly and marks the unclean ones for repair.
// lost reports a live anchor missing from storage.
func (p *Publisher) check(ctx context.Context, targets []Target, prog *AuditProgress) (lost bool, err error) {
	ds := make([]Digest, len(targets))
	for i, t := range targets {
		ds[i] = t.Digest
	}
	insp, err := p.client.InspectDigests(ctx, ds)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	for _, t := range targets {
		v, present, err := insp.ExactValue(t.Digest)
		if err != nil {
			return false, fmt.Errorf("%w: %w", ErrReadFailed, err)
		}
		prog.Checked++
		exact := t.T == 0 && !present || t.T > 0 && present && v == int64(t.T)
		if t.Phase == PhaseIdle && exact {
			continue
		}
		prog.Repaired++
		// Only an anchor already verified present can be lost; one being
		// reset or awaiting its first add is absent by design.
		lost = lost || t.Phase == PhaseIdle && t.T > 0 && !present
		if t.Phase != PhaseIdle {
			continue // already pending repair or publication
		}
		if p.audit.drift == nil {
			p.audit.drift = map[Digest]int{}
		}
		p.audit.drift[t.Digest]++
		if err := p.setPhase(t, PhaseRead, nil); err != nil {
			return false, err
		}
	}
	return lost, nil
}

// settle allows fresh matching once the owed rotation is over and no target
// is still pending.
func (p *Publisher) settle() error {
	pending, err := p.pending()
	if err != nil {
		return err
	}
	if p.audit.coverReached && len(pending) == 0 {
		p.audit.covered, p.audit.rebuilding = true, false
	}
	return nil
}

// pending lists targets not idle, in key order.
// ponytail: full scan per call; index pending digests if Plan C's benchmark
// shows the scan in the turn budget.
func (p *Publisher) pending() ([]Digest, error) {
	var out []Digest
	err := p.ledger.View(func(v LedgerView) error {
		return v.tx.ForEach(store.LearnTargetsBucket, func(_, data []byte) error {
			var t Target
			if err := json.Unmarshal(data, &t); err != nil {
				return errors.New("learning ledger target is unreadable")
			}
			if t.Phase != PhaseIdle {
				out = append(out, t.Digest)
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return out, nil
}

// RepairTurn runs one publication turn for up to max pending targets,
// continuing from a persisted cursor. It returns how many it turned.
func (p *Publisher) RepairTurn(ctx context.Context, max int) (int, error) {
	pending, err := p.pending()
	if err != nil {
		return 0, err
	}
	if len(pending) == 0 {
		return 0, p.settle()
	}
	var cur auditCursor
	if err := p.ledger.View(func(v LedgerView) error {
		_, err := v.get(store.LearnCursorBucket, []byte(repairCursorKey), &cur)
		return err
	}); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	start, _ := slices.BinarySearch(pending, cur.After+"\x00")
	order := slices.Concat(pending[start:], pending[:start])
	if len(order) > max {
		order = order[:max]
	}
	var errs []error
	for _, d := range order {
		if _, err := p.Turn(ctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	cur.After = order[len(order)-1]
	if err := p.ledger.Update(func(tx LedgerTx) error {
		return tx.put(store.LearnCursorBucket, []byte(repairCursorKey), cur)
	}); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrStateIO, err))
	}
	return len(order), errors.Join(errs...)
}

// RetireDue supersedes every cluster whose latest committed or reserved
// admission is Retention old with a zero target, removes its aliases, then
// unlinks its body and credits its charges. Storage TTLs play no part. A
// wall clock behind the persisted watermark retires nothing new.
func (p *Publisher) RetireDue(now time.Time) ([]uint64, error) {
	now = now.UTC()
	var retired []uint64
	err := p.ledger.Update(func(tx LedgerTx) error {
		var mark time.Time
		if _, err := tx.get(store.LearnMetaBucket, []byte(watermarkKey), &mark); err != nil {
			return err
		}
		if now.Before(mark) {
			return nil
		}
		if err := tx.put(store.LearnMetaBucket, []byte(watermarkKey), now); err != nil {
			return err
		}
		latest, err := reservedAdmissions(tx)
		if err != nil {
			return err
		}
		var due []Cluster
		if err := tx.tx.ForEach(store.LearnClustersBucket, func(_, data []byte) error {
			var c Cluster
			if err := json.Unmarshal(data, &c); err != nil {
				return errors.New("learning ledger cluster is unreadable")
			}
			last := c.LastReport
			if r := latest[c.ID]; r.After(last) {
				last = r
			}
			if !c.Retired && !now.Before(last.Add(Retention)) {
				due = append(due, c)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, c := range due {
			if err := supersede(tx, c, p.now().UTC()); err != nil {
				return err
			}
			retired = append(retired, c.ID)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return retired, p.cleanup()
}

// reservedAdmissions maps each cluster to its latest open reservation.
func reservedAdmissions(tx LedgerTx) (map[uint64]time.Time, error) {
	latest := map[uint64]time.Time{}
	err := tx.tx.ForEach(store.LearnIntentsBucket, func(_, data []byte) error {
		var i Intent
		if err := json.Unmarshal(data, &i); err != nil {
			return errors.New("learning ledger intent is unreadable")
		}
		if i.Done {
			return nil
		}
		for _, ic := range i.Clusters {
			if !ic.Done && i.Admitted.After(latest[ic.ClusterID]) {
				latest[ic.ClusterID] = i.Admitted
			}
		}
		return nil
	})
	return latest, err
}

// supersede durably gives a cluster's anchor a zero target under a new
// revision, drops its aliases and marks the record as a cleanup reference.
// Old intents no longer match the revision and cannot commit.
func supersede(tx LedgerTx, c Cluster, now time.Time) error {
	t, ok, err := tx.Target(c.Anchor)
	if err != nil {
		return err
	}
	if !ok {
		t = Target{Digest: c.Anchor, ClusterID: c.ID}
	}
	t.T, t.Revision, t.Phase, t.ResetPending, t.RestoreT, t.Updated = 0, t.Revision+1, PhaseRead, false, 0, now
	if err := tx.PutTarget(t); err != nil {
		return err
	}
	for _, a := range c.Aliases {
		if id, ok, err := tx.Alias(a); err != nil {
			return err
		} else if ok && id == c.ID {
			if err := tx.DeleteAlias(a); err != nil {
				return err
			}
		}
	}
	c.Retired = true
	return tx.PutCluster(c)
}

// cleanup finishes retired clusters: unlink and sync the body, then credit
// charges and drop the record. A crash in between repeats harmlessly.
func (p *Publisher) cleanup() error {
	var refs []Cluster
	if err := p.ledger.View(func(v LedgerView) error {
		return v.tx.ForEach(store.LearnClustersBucket, func(_, data []byte) error {
			var c Cluster
			if err := json.Unmarshal(data, &c); err != nil {
				return errors.New("learning ledger cluster is unreadable")
			}
			if c.Retired {
				refs = append(refs, c)
			}
			return nil
		})
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	for _, c := range refs {
		if err := p.bodies.Remove(c.ID); err != nil {
			return err
		}
		if err := p.ledger.Update(func(tx LedgerTx) error {
			for _, ch := range c.Charges {
				if err := tx.credit(ch); err != nil {
					return err
				}
			}
			return tx.DeleteCluster(c.ID)
		}); err != nil {
			return fmt.Errorf("%w: %w", ErrStateIO, err)
		}
	}
	return nil
}

// credit returns a charge, never below zero.
func (tx LedgerTx) credit(ch Charge) error {
	u, err := tx.Usage(ch.UID, ch.Operator)
	if err != nil {
		return err
	}
	u.BodyBytes = max(0, u.BodyBytes-ch.Usage.BodyBytes)
	u.Aliases = max(0, u.Aliases-ch.Usage.Aliases)
	return tx.put(store.LearnUsageBucket, usageKey(ch.UID, ch.Operator), u)
}
