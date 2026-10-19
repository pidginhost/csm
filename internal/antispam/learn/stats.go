package learn

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// Stats is the learner's state for metrics and health. Counts come from
// one ledger read; the audit fields from the engine's last turns.
type Stats struct {
	LiveClusters     int
	ZeroTargets      int
	UncertainIntents int
	BodyBytes        int64
	OldestUnchecked  time.Time
	AuditCompleted   time.Time
	// Reconstructed counts anchors scheduled for repair since the engine
	// started.
	Reconstructed uint64
}

// Stats reads the ledger counts and the engine's audit progress. It is
// safe from any goroutine.
func (e *Engine) Stats() (Stats, error) {
	e.mu.Lock()
	s := Stats{OldestUnchecked: e.statOldest, AuditCompleted: e.statAudit, Reconstructed: e.statRepaired}
	e.mu.Unlock()
	err := e.cfg.Ledger.View(func(v LedgerView) error {
		if err := v.tx.ForEach(store.LearnClustersBucket, func(_, raw []byte) error {
			var c Cluster
			if err := json.Unmarshal(raw, &c); err != nil {
				return err
			}
			if !c.Retired {
				s.LiveClusters++
			}
			s.BodyBytes += c.BodyLen
			return nil
		}); err != nil {
			return err
		}
		return v.tx.ForEach(store.LearnTargetsBucket, func(_, raw []byte) error {
			var t Target
			if err := json.Unmarshal(raw, &t); err != nil {
				return err
			}
			if t.T == 0 {
				s.ZeroTargets++
			}
			if t.Phase == PhaseAddSent || t.Phase == PhaseDeleteSent {
				s.UncertainIntents++
			}
			return nil
		})
	})
	if err != nil {
		return Stats{}, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return s, nil
}
