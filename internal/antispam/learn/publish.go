package learn

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Publication limits (spec 7.4). Provisional until Plan C's benchmark
// records a measurement.
const (
	PublishTurnAttempts = 3
	VerifyPollEvery     = 100 * time.Millisecond
	VerifyDeadline      = 5 * time.Second
)

// Publication errors. ErrReadFailed: the exact value could not be read, so
// nothing was sent. ErrStateIO: the ledger could not record a phase, so
// nothing was sent.
var (
	ErrReadFailed = errors.New("cannot read the anchor's stored value")
	ErrStateIO    = errors.New("cannot record learning state")
)

// nativeClient is the subset of Client publication uses.
type nativeClient interface {
	Inspect(ctx context.Context, body []byte) (Inspection, error)
	InspectDigests(ctx context.Context, ds []Digest) (Inspection, error)
	Add(ctx context.Context, body []byte, w int32) error
	DeleteHash(ctx context.Context, d Digest) error
	Sync(ctx context.Context) error
}

// Publisher drives one target at a time toward its value through native
// calls, persisting the phase before every send (spec 7.4 "Publishing a
// target"). Only the engine goroutine uses it.
type Publisher struct {
	client   nativeClient
	ledger   *Ledger
	bodies   *Bodies
	now      func() time.Time
	poll     time.Duration
	deadline time.Duration
	attempts int
}

// NewPublisher returns a publisher with the spec's limits.
func NewPublisher(c nativeClient, l *Ledger, b *Bodies) *Publisher {
	return &Publisher{client: c, ledger: l, bodies: b, now: time.Now, poll: VerifyPollEvery, deadline: VerifyDeadline, attempts: PublishTurnAttempts}
}

// TurnResult reports where a target stands after one turn. Done: an exact
// check showed T (or absence for T=0) and the target is idle. Uncertain: a
// mutation's outcome is unknown; the next turn starts by reading.
type TurnResult struct {
	Done      bool
	Value     int64
	Phase     Phase
	Uncertain bool
}

// Turn runs at most the publisher's attempts of native mutations for d.
// It never computes an add from a value read before an unresolved send.
func (p *Publisher) Turn(ctx context.Context, d Digest) (TurnResult, error) {
	sends := 0
	for step := 0; step < 4*p.attempts; step++ {
		t, err := p.target(d)
		if err != nil {
			return TurnResult{}, err
		}
		res := TurnResult{Phase: t.Phase}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		v, present, err := p.read(ctx, d)
		if err != nil {
			return res, err
		}
		res.Value = v
		switch t.Phase {
		case PhaseDeletePending, PhaseDeleteSent:
			if !present {
				if t.T == 0 {
					return p.complete(t, 0)
				}
				if err = p.setPhase(t, PhaseAddPending, nil); err != nil {
					return res, err
				}
				continue
			}
		case PhaseAddPending:
			if present {
				// A late write arrived before the re-add: delete it first.
				if err = p.setPhase(t, PhaseDeletePending, nil); err != nil {
					return res, err
				}
				continue
			}
		default:
			reset := t.ResetPending || present && v <= 0
			switch {
			case t.T == 0 && !present:
				return p.complete(t, 0)
			case present && v == int64(t.T) && (!reset || t.Phase == PhaseAddSent && t.ResetPending):
				// A recorded reset add followed by exact T finishes the reset;
				// merely entering the reset phase does not.
				return p.complete(t, v)
			case t.T == 0 || reset || v > int64(t.T):
				if err = p.setPhase(t, PhaseDeletePending, func(t *Target) {
					t.ResetPending = t.ResetPending || present && v <= 0
					t.RestoreT = t.T
				}); err != nil {
					return res, err
				}
				continue
			}
		}
		if sends == p.attempts {
			return res, nil
		}
		sends++
		var verified bool
		if t.Phase == PhaseDeletePending || t.Phase == PhaseDeleteSent {
			verified, err = p.sendDelete(ctx, t)
		} else {
			// Idle, Read and AddSent with 0 <= V < T add T-V; AddPending
			// re-adds the whole target after verified absence.
			verified, err = p.sendAdd(ctx, t, v)
		}
		if err != nil || !verified {
			res, _ = p.result(d, res)
			res.Uncertain = err == nil || errors.Is(err, ErrUncertain)
			if res.Uncertain {
				err = nil
			}
			return res, err
		}
	}
	t, err := p.target(d)
	return TurnResult{Phase: t.Phase}, err
}

func (p *Publisher) result(d Digest, res TurnResult) (TurnResult, error) {
	t, err := p.target(d)
	if err == nil {
		res.Phase = t.Phase
	}
	return res, err
}

func (p *Publisher) target(d Digest) (Target, error) {
	var t Target
	var ok bool
	err := p.ledger.View(func(v LedgerView) error {
		var err error
		t, ok, err = v.Target(d)
		return err
	})
	if err != nil {
		return Target{}, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	if !ok {
		return Target{}, fmt.Errorf("%w: no target for digest", ErrStateMismatch)
	}
	return t, nil
}

// read returns d's exact stored value; a verified miss is absence.
func (p *Publisher) read(ctx context.Context, d Digest) (int64, bool, error) {
	insp, err := p.client.InspectDigests(ctx, []Digest{d})
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	v, present, err := insp.ExactValue(d)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return v, present, nil
}

// setPhase records a phase change, refusing if the target moved since it
// was read (a new revision or target supersedes this turn's plan).
func (p *Publisher) setPhase(seen Target, phase Phase, edit func(*Target)) error {
	err := p.ledger.Update(func(tx LedgerTx) error {
		cur, ok, err := tx.Target(seen.Digest)
		if err != nil {
			return err
		}
		if !ok || cur.Revision != seen.Revision || cur.T != seen.T || cur.Phase != seen.Phase {
			return errTargetMoved
		}
		cur.Phase, cur.Updated = phase, p.now().UTC()
		if edit != nil {
			edit(&cur)
		}
		return tx.PutTarget(cur)
	})
	if err != nil && !errors.Is(err, errTargetMoved) {
		return fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return err
}

var errTargetMoved = errors.New("target changed during the turn")

func (p *Publisher) complete(t Target, v int64) (TurnResult, error) {
	err := p.setPhase(t, PhaseIdle, func(t *Target) {
		t.ResetPending, t.RestoreT = false, 0
	})
	if err != nil {
		return TurnResult{Phase: t.Phase, Value: v}, err
	}
	return TurnResult{Done: true, Value: v, Phase: PhaseIdle}, nil
}

// sendDelete journals delete_sent, deletes by full digest, flushes and
// waits for exact absence.
func (p *Publisher) sendDelete(ctx context.Context, t Target) (bool, error) {
	if err := p.setPhase(t, PhaseDeleteSent, nil); err != nil {
		return false, err
	}
	if err := p.client.DeleteHash(ctx, t.Digest); err != nil {
		return false, err
	}
	return p.verify(ctx, t.Digest, func(_ int64, present bool) bool { return !present })
}

// sendAdd checks the anchor body, journals add_sent and sends one add: T-V
// on the plain path, the whole T after a verified deletion.
func (p *Publisher) sendAdd(ctx context.Context, t Target, v int64) (bool, error) {
	body, err := p.anchorBody(ctx, t)
	if err != nil {
		return false, err
	}
	weight := t.T - int32(v)
	resetAdd := t.Phase == PhaseAddPending
	if resetAdd {
		weight = t.T
	}
	if err := p.setPhase(t, PhaseAddSent, nil); err != nil {
		return false, err
	}
	sent := t
	sent.Phase = PhaseAddSent
	if err := p.client.Add(ctx, body, weight); err != nil {
		if errors.Is(err, ErrRejected) {
			// An observed backend write failure: rebuild the anchor rather
			// than trust whatever part of it storage kept.
			next := PhaseDeletePending
			if resetAdd {
				next = PhaseAddPending
			}
			if perr := p.setPhase(sent, next, func(t *Target) {
				t.ResetPending, t.RestoreT = true, t.T
			}); perr != nil {
				return false, errors.Join(err, perr)
			}
		}
		return false, err
	}
	return p.verify(ctx, t.Digest, func(v int64, present bool) bool { return present && v >= int64(t.T) })
}

// anchorBody returns the cluster's stored body after checking its length,
// hash and that the current hash generation still yields the anchor.
func (p *Publisher) anchorBody(ctx context.Context, t Target) ([]byte, error) {
	var c Cluster
	var ok bool
	if err := p.ledger.View(func(v LedgerView) error {
		var err error
		c, ok, err = v.Cluster(t.ClusterID)
		return err
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	if !ok || c.Anchor != t.Digest {
		return nil, fmt.Errorf("%w: target has no cluster for its anchor", ErrStateMismatch)
	}
	body, err := p.bodies.Read(c.ID, c.BodyLen, c.BodySHA)
	if err != nil {
		return nil, err
	}
	insp, err := p.client.Inspect(ctx, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	if insp.Distinct != 1 || insp.Results[0].Queried != t.Digest {
		return nil, fmt.Errorf("%w: the anchor body no longer hashes to its digest", ErrStateMismatch)
	}
	return body, nil
}

// verify flushes and polls exact checks until done reports true or the
// deadline passes. A failed flush or read leaves the outcome open.
func (p *Publisher) verify(ctx context.Context, d Digest, done func(v int64, present bool) bool) (bool, error) {
	if err := p.client.Sync(ctx); err != nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, p.deadline)
	defer cancel()
	for {
		if v, present, err := p.read(ctx, d); err == nil && done(v, present) {
			return true, nil
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-time.After(p.poll):
		}
	}
}
