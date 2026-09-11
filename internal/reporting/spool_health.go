package reporting

import (
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type spoolWork struct {
	ticket    queuehealth.Ticket
	evicted   bool
	delivered bool
}

type spoolHealth struct {
	stats   *queuehealth.Tracker
	pending map[string]*spoolWork // guarded by Spool.mutation
	active  *spoolWork

	enqueueFailed atomic.Bool
	readFailed    atomic.Bool
	removeFailed  atomic.Bool
	sendFailed    atomic.Bool
}

func newSpoolHealth(capacity int) spoolHealth {
	return spoolHealth{
		// Delivery normally runs once a minute. Allow a complete retry interval
		// before age alone declares the durable queue stalled.
		stats:   queuehealth.NewSharedCapacity(capacity, 2*time.Minute),
		pending: make(map[string]*spoolWork),
	}
}

// QueueStatuses uses memory only, including when a database write or sender
// stalls. Existing records are timed from open, not from an invented disk age.
func (s *Spool) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	status := s.health.stats.Snapshot(now)
	status.LagBasis = "observed_age"
	switch {
	case s.health.enqueueFailed.Load() || s.health.readFailed.Load() || s.health.removeFailed.Load():
		status.Status, status.Reason = "degraded", "spool_io"
	case s.health.sendFailed.Load():
		status.Status, status.Reason = "degraded", "delivery_failed"
	}
	return map[string]queuehealth.Status{"spool": status}
}

// applyEnqueue runs only after commit, under the mutation lock. An evicted
// record can still be owned by send; its outcome decides whether it was lost.
func (s *Spool) applyEnqueue(key string, ticket queuehealth.Ticket, evicted []string) {
	now := time.Now()
	ticket.Requeue(now)
	s.health.pending[key] = &spoolWork{ticket: ticket}
	for _, key := range evicted {
		work := s.health.pending[key]
		delete(s.health.pending, key)
		switch {
		case work == nil:
			// A record evicted from disk with no accounting cannot be
			// attributed to a caller; count the report it carried as lost.
			s.health.stats.Lose(now, 1)
		case work == s.health.active:
			work.evicted = true
		default:
			work.discard(now)
		}
	}
}

func (s *Spool) finishDelivery(work *spoolWork, sent, removed bool) {
	s.mutation.Lock()
	defer s.mutation.Unlock()
	if !sent {
		s.health.sendFailed.Store(true)
	}
	now := time.Now()
	// Database removal can fail after receipt. Later eviction or a failed
	// retry must not turn that earlier acknowledgement into a lost report.
	work.delivered = work.delivered || sent
	switch {
	case removed:
		work.ticket.Finish(now)
	case work.evicted:
		work.discard(now)
	default:
		work.ticket.Requeue(now)
	}
	s.health.active = nil
}

func (w *spoolWork) discard(now time.Time) {
	if w.delivered {
		w.ticket.Finish(now)
	} else {
		w.ticket.Reject(now)
	}
}
