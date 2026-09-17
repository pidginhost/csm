package alert

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type phpanelWork struct {
	ticket    queuehealth.Ticket
	evicted   bool
	delivered bool
}

type phpanelQueueHealth struct {
	stats   *queuehealth.Tracker
	pending map[string]*phpanelWork // guarded by phpanelQueue.mutation
	active  *phpanelWork

	enqueueFailed atomic.Bool
	readFailed    atomic.Bool
	removeFailed  atomic.Bool
	sendFailed    atomic.Bool
}

// Factory locking spans database open. This registry only publishes memory
// snapshots, so status remains available during a stalled open, write or send.
var phpanelHealth = struct {
	sync.RWMutex
	active map[*phpanelQueue]struct{}
	losses *queuehealth.Tracker
}{active: make(map[*phpanelQueue]struct{}), losses: queuehealth.New(0, time.Minute)}

// PhpanelQueueStatus includes cumulative loss from queues disabled or replaced
// during this process. It retains no retired queues or state-path labels.
func PhpanelQueueStatus(now time.Time) queuehealth.Status {
	phpanelHealth.RLock()
	queues := make([]*phpanelQueue, 0, len(phpanelHealth.active))
	for q := range phpanelHealth.active {
		queues = append(queues, q)
	}
	phpanelHealth.RUnlock()
	status := phpanelHealth.losses.Snapshot(now)
	for _, q := range queues {
		local := q.queueStatus(now)
		status.Depth += local.Depth
		status.InFlight += local.InFlight
		status.Capacity += local.Capacity
		status.LagSeconds = max(status.LagSeconds, local.LagSeconds)
		status.ProcessingSeconds = max(status.ProcessingSeconds, local.ProcessingSeconds)
		if phpanelReasonRank(local.Reason) > phpanelReasonRank(status.Reason) {
			status.Status, status.Reason = local.Status, local.Reason
		}
	}
	return status
}

func phpanelReasonRank(reason string) int {
	switch reason {
	case "spool_io":
		return 6
	case "delivery_failed":
		return 5
	case "backlog_lag":
		return 4
	case "processing_lag":
		return 3
	case "queue_full":
		return 2
	case "dropped_work":
		return 1
	default:
		return 0
	}
}

func (q *phpanelQueue) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"spool": q.queueStatus(now)}
}

func (q *phpanelQueue) queueStatus(now time.Time) queuehealth.Status {
	status := q.health.stats.Snapshot(now)
	switch {
	case q.health.enqueueFailed.Load() || q.health.readFailed.Load() || q.health.removeFailed.Load():
		status.Status, status.Reason = "degraded", "spool_io"
	case q.health.sendFailed.Load():
		status.Status, status.Reason = "degraded", "delivery_failed"
	}
	return status
}

func (q *phpanelQueue) discardWork(work *phpanelWork, now time.Time) {
	if work.delivered {
		work.ticket.Finish(now)
		return
	}
	work.ticket.Reject(now)
	phpanelHealth.losses.Lose(now, 1)
}

// The send owns an evicted record until its result is known. Evicting its
// durable copy is not a lost finding if the collector already received it.
func (q *phpanelQueue) finishDelivery(work *phpanelWork, sent, removed bool) {
	q.mutation.Lock()
	defer q.mutation.Unlock()
	now := time.Now()
	// An acknowledged send may remain queued after database removal fails.
	// Later retries cannot undo the collector's earlier receipt.
	work.delivered = work.delivered || sent
	switch {
	case removed:
		work.ticket.Finish(now)
	case work.evicted:
		q.discardWork(work, now)
	default:
		work.ticket.Requeue(now)
	}
	q.health.active = nil
}
