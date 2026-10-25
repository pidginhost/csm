package workerproc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

// PoolConfig describes a fixed set of worker slots.
type PoolConfig struct {
	Size int
	// Config gives slot 0..Size-1 its supervisor configuration.
	Config func(slot int) Config
}

// Pool is a fixed set of supervisors, one per slot. Callers own slots: a
// slot is used by one goroutine, so nobody waits on another caller's worker.
// Memory a worker hands back (memfds) stays charged to that worker's cgroup,
// so a caller that holds its last reply while it works must keep using the
// same slot, never one whose cgroup another caller is filling.
type Pool struct {
	slots []*Supervisor
}

// NewPool starts no worker; each slot's first Call does.
func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.Size < 1 {
		return nil, errors.New("workerproc: pool size must be positive")
	}
	p := &Pool{slots: make([]*Supervisor, cfg.Size)}
	for slot := range p.slots {
		s, err := New(cfg.Config(slot))
		if err != nil {
			return nil, fmt.Errorf("workerproc: pool slot %d: %w", slot, err)
		}
		p.slots[slot] = s
	}
	return p, nil
}

// Size is the number of slots.
func (p *Pool) Size() int { return len(p.slots) }

// Call runs req on slot's worker. slot must be in 0..Size-1.
func (p *Pool) Call(ctx context.Context, slot int, req Frame, fds []*os.File, check Check) (Frame, []*os.File, error) {
	return p.slots[slot].Call(ctx, req, fds, check)
}

// Stop stops every slot.
func (p *Pool) Stop() error {
	for _, s := range p.slots {
		_ = s.Stop()
	}
	return nil
}

// Stats is each slot's supervisor state, by slot.
func (p *Pool) Stats() []Stats {
	out := make([]Stats, len(p.slots))
	for slot, s := range p.slots {
		out[slot] = s.Stats()
	}
	return out
}

// QueueStatuses folds the slots into one requests row.
func (p *Pool) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	total := queuehealth.Status{Status: "ok", Capacity: len(p.slots)}
	for _, s := range p.slots {
		row := s.QueueStatuses(now)["requests"]
		total.Depth += row.Depth
		total.InFlight += row.InFlight
		total.DroppedTotal += row.DroppedTotal
		total.RecentDrops += row.RecentDrops
		total.DroppedLowerBound = total.DroppedLowerBound || row.DroppedLowerBound
		total.LagSeconds = max(total.LagSeconds, row.LagSeconds)
		total.ProcessingSeconds = max(total.ProcessingSeconds, row.ProcessingSeconds)
		if row.Status != "ok" && total.Status == "ok" {
			total.Status, total.Reason = row.Status, row.Reason
		}
	}
	return map[string]queuehealth.Status{"requests": total}
}
