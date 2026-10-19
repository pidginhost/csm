package learn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// CancelUnsent cancels uid's Spam folder reservations that sent nothing
// under their revision (spec 5: an observed opt-out cancels unsent work).
// Their targets return to what they replaced. Sent clusters keep
// publishing and committed ones keep their votes. Only the ledger changes,
// so it runs whatever the gate.
func (e *Engine) CancelUnsent(ctx context.Context, uid int) error {
	// Accounts with no cancellable work need no owner turn. In particular,
	// sent work must not hold up each opt-out pass on native request delays.
	ids, err := e.unsentReportIntents(ctx, uid)
	if err != nil || len(ids) == 0 {
		return err
	}
	var cancelErr error
	if err := e.do(ctx, func() { cancelErr = e.cancelUnsent(ids) }); err != nil {
		return err
	}
	return cancelErr
}

func (e *Engine) unsentReportIntents(ctx context.Context, uid int) ([]string, error) {
	candidates, lookupErr := e.cfg.Ledger.reportIntents(ctx, uid)
	if lookupErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateIO, lookupErr)
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	var ids []string
	err := e.cfg.Ledger.View(func(v LedgerView) error {
		for _, id := range candidates {
			if err := ctx.Err(); err != nil {
				return err
			}
			i, ok, err := v.Intent(id)
			if err != nil {
				return err
			}
			if ok {
				for _, ic := range i.Clusters {
					if ic.Done {
						continue
					}
					t, ok, err := v.Target(ic.Anchor)
					if err != nil {
						return err
					}
					if ok && unsentTarget(t, ic) {
						ids = append(ids, id)
						break
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return ids, nil
}

// ReportUIDs lists the accounts holding Spam folder reservations, sent or
// not, so the watcher can cancel those of removed accounts.
func (e *Engine) ReportUIDs(ctx context.Context) ([]int, error) {
	e.cfg.Ledger.intentsMu.Lock()
	defer e.cfg.Ledger.intentsMu.Unlock()
	ids, err := e.cfg.Ledger.reportIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return slices.Sorted(maps.Keys(ids)), nil
}

func (l *Ledger) reportIntents(ctx context.Context, uid int) ([]string, error) {
	l.intentsMu.Lock()
	defer l.intentsMu.Unlock()
	ids, err := l.reportIndex(ctx)
	return slices.Clone(ids[uid]), err
}

// reportIndex maps UIDs to their report intents; the caller holds
// intentsMu. It indexes only ownership. Targets are read again on every
// check and on the owner so a cached entry cannot authorize cancellation.
func (l *Ledger) reportIndex(ctx context.Context) (map[int][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if l.reportIDs == nil {
		ids := map[int][]string{}
		if err := l.View(func(v LedgerView) error {
			return v.tx.ForEach(store.LearnIntentsBucket, func(k, data []byte) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				var owner struct {
					Kind IntentKind `json:"kind"`
					UID  int        `json:"uid"`
				}
				if err := json.Unmarshal(data, &owner); err != nil {
					return errors.New("learning ledger intent is unreadable")
				}
				if owner.Kind == IntentReport {
					ids[owner.UID] = append(ids[owner.UID], string(k))
				}
				return nil
			})
		}); err != nil {
			return nil, err
		}
		l.reportIDs = ids
	}
	return l.reportIDs, nil
}

func unsentTarget(t Target, ic IntentCluster) bool {
	return t.ClusterID == ic.ClusterID && t.Revision == ic.Revision && t.SentRevision != t.Revision
}

// cancelUnsent runs on the owner, so no turn can send between its check
// and its restore.
func (e *Engine) cancelUnsent(ids []string) error {
	e.start()
	if e.bindErr != nil {
		return e.bindErr
	}
	now := e.cfg.Now().UTC()
	err := e.cfg.Ledger.Update(func(tx LedgerTx) error {
		for _, id := range ids {
			if err := cancelIntent(tx, id, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrStateIO, err)
		e.note(err)
	}
	return err
}

func cancelIntent(tx LedgerTx, id string, now time.Time) error {
	intent, ok, err := tx.Intent(id)
	if err != nil || !ok {
		return err
	}
	for k := range intent.Clusters {
		if intent.Clusters[k].Done {
			continue
		}
		cancelled, err := cancelCluster(tx, intent, k, now)
		if err != nil {
			return err
		}
		intent.Clusters[k].Done = cancelled
	}
	if !slices.ContainsFunc(intent.Clusters, func(ic IntentCluster) bool { return !ic.Done }) {
		return tx.DeleteIntent(id)
	}
	return tx.PutIntent(intent)
}

// cancelCluster restores the target that cluster k of intent replaced and
// returns its charge, unless a native write was sent under its revision.
func cancelCluster(tx LedgerTx, intent Intent, k int, now time.Time) (bool, error) {
	ic := intent.Clusters[k]
	t, ok, err := tx.Target(ic.Anchor)
	if err != nil {
		return false, err
	}
	// A superseded target ends the contribution when it is published.
	if !ok || !unsentTarget(t, ic) {
		return false, nil
	}
	seed := intent.Seed != nil && k == 0
	switch {
	case ic.Prior != nil:
		p := *ic.Prior
		// A new revision keeps the restored target apart from this intent;
		// a read verifies it before the next fresh match.
		p.Revision, p.Phase, p.Updated = t.Revision+1, PhaseRead, now
		p.ResetPending, p.RestoreT = t.ResetPending, 0
		if g := p.GuardCharge; seed && g != nil {
			// The seed returned the guard's charge; it is a guard again.
			if err = tx.AddUsage(g.UID, g.Operator, g.Usage); err != nil {
				return false, err
			}
		}
		err = tx.PutTarget(p)
	case seed:
		// Nothing was ever sent for a target the seed created.
		err = tx.DeleteTarget(ic.Anchor)
	default:
		return false, nil
	}
	if err != nil {
		return false, err
	}
	ch := Charge{UID: intent.UID, Usage: Usage{Aliases: len(ic.Aliases)}}
	if seed {
		ch.Usage.BodyBytes = intent.Seed.BodyLen
		// Cleanup unlinks the unpublished body and drops the record.
		c, found, err := tx.Cluster(ic.ClusterID)
		if err != nil {
			return false, err
		}
		if found {
			c.Retired = true
			if err = tx.PutCluster(c); err != nil {
				return false, err
			}
		}
	}
	return true, tx.credit(ch)
}
