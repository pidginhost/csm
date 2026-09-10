package state

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

type pendingImage struct {
	count  int
	digest [sha256.Size]byte
	valid  bool
}

// Compare complete serialized batches, including duplicate occurrences. A
// finding's dedup key does not identify its persisted payload.
func pendingIdentity(findings []alert.Finding) pendingImage {
	if len(findings) == 0 {
		return pendingImage{valid: true}
	}
	data, err := json.Marshal(findings)
	return pendingImage{count: len(findings), digest: sha256.Sum256(data), valid: err == nil}
}

type pendingQueue struct {
	mu          sync.Mutex
	disk        pendingImage
	known       bool
	arrivals    []time.Time
	calls       map[*pendingCall]struct{}
	losses      *queuehealth.Tracker
	stateIO     bool
	lowerBound  bool
	uncertainAt time.Time
}

type pendingCall struct {
	queue                  *pendingQueue
	queued, progress       time.Time
	incoming, replay, lost int
	offered, settled       bool
}

func (s *Store) pendingHealth() *pendingQueue {
	s.pendingHealthOnce.Do(func() {
		s.pendingQueue = &pendingQueue{calls: make(map[*pendingCall]struct{}), losses: queuehealth.New(pendingFindingsMax, time.Minute)}
	})
	return s.pendingQueue
}

func (s *Store) observePendingQueue() {
	pending, err := s.readPendingLocked(nil)
	image := pendingIdentity(pending)
	q := s.pendingHealth()
	q.mu.Lock()
	defer q.mu.Unlock()
	if err != nil {
		q.unknown(true)
		return
	}
	q.setDisk(image)
}

func (q *pendingQueue) begin(count int) *pendingCall {
	c := &pendingCall{queue: q, queued: time.Now(), incoming: count}
	q.mu.Lock()
	q.calls[c] = struct{}{}
	q.mu.Unlock()
	return c
}

func (c *pendingCall) start() {
	c.queue.mu.Lock()
	c.progress = time.Now()
	c.queue.mu.Unlock()
}

func (q *pendingQueue) setDisk(next pendingImage) {
	if !q.known || !next.valid || q.disk != next {
		q.arrivals = make([]time.Time, next.count)
		now := time.Now()
		for i := range q.arrivals {
			q.arrivals[i] = now
		}
	}
	q.disk = next
	q.known = true
}

func (c *pendingCall) appendedAges(oldCount, kept int) []time.Time {
	q := c.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	ages := make([]time.Time, kept)
	start := oldCount + c.incoming - kept
	for i := range ages {
		if index := start + i; index < oldCount {
			ages[i] = q.arrivals[index]
		} else {
			ages[i] = c.queued
		}
	}
	return ages
}

func (q *pendingQueue) unknown(ioFailure bool) {
	q.known = false
	q.lowerBound = true
	q.stateIO = ioFailure
	q.uncertainAt = time.Now()
}

func (c *pendingCall) observe(image pendingImage) {
	q := c.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.known && q.disk != image {
		q.lowerBound = true
		q.uncertainAt = time.Now()
	}
	q.setDisk(image)
	c.progress = time.Now()
}

func (c *pendingCall) lose(count int) {
	if count > c.lost {
		c.queue.losses.Lose(time.Now(), uint64(count-c.lost)) // #nosec G115 -- the guarded positive difference is bounded by the finding batch lengths.
		c.lost = count
	}
}

// Incoming findings outside the retained suffix cannot survive either the old
// or the replacement file. Publish that known loss before attempting I/O.
func (c *pendingCall) offer(knownLoss int) {
	q := c.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	c.lose(knownLoss)
	c.offered = true
	c.progress = time.Now()
}

func (c *pendingCall) ioFailed() {
	c.queue.mu.Lock()
	c.queue.stateIO = true
	c.progress = time.Now()
	c.queue.mu.Unlock()
}

func (c *pendingCall) complete(image pendingImage, loss int, failed bool, arrivals []time.Time) {
	q := c.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	q.setDisk(image)
	if arrivals != nil {
		q.arrivals = arrivals
	}
	q.stateIO = failed
	c.lose(loss)
	c.incoming = 0
	c.settled = true
	c.progress = time.Now()
}

func (c *pendingCall) unreadable(loss int) {
	q := c.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	q.unknown(true)
	c.lose(loss)
	c.incoming = 0
	c.settled = true
	c.progress = time.Now()
}

func (c *pendingCall) failedRead() {
	if c == nil {
		return
	}
	loss := c.lost
	if !c.offered {
		loss = c.incoming
	}
	c.unreadable(loss)
}

// The state lock still belongs to this call. Settle an unreturned write or
// clear before a newer operation can publish its own confirmed disk state.
func (c *pendingCall) settleIO() {
	q := c.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if c.offered && !c.settled {
		q.unknown(false)
		c.incoming = 0
		c.settled = true
	}
}

func (c *pendingCall) detach(count int) {
	q := c.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	q.setDisk(pendingImage{valid: true})
	q.stateIO = false
	c.offered = false
	c.replay = count
	c.progress = time.Now()
}

func (c *pendingCall) finishReplay() {
	c.queue.mu.Lock()
	c.settled = true
	c.queue.mu.Unlock()
}

func (c *pendingCall) finish() {
	q := c.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if !c.settled {
		switch {
		case c.replay > 0:
			// Dispatch may have partially completed. Do not invent an exact loss or
			// requeue findings that the existing at-most-once policy already cleared.
			q.lowerBound = true
			q.uncertainAt = time.Now()
		default:
			c.lose(c.incoming)
		}
	}
	delete(q.calls, c)
}

// QueueStatuses uses metadata only, independently of state locks, file I/O and
// the replay callback. Waiting for the next restart has no processing deadline.
func (s *Store) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	q := s.pendingHealth()
	q.mu.Lock()
	defer q.mu.Unlock()
	row := q.losses.Snapshot(now)
	row.DepthUnit = "findings"
	row.LagBasis = "deferred_checkpoint"
	row.DepthUnavailable = !q.known
	if q.known {
		row.Depth = q.disk.count
	}
	row.DroppedLowerBound = q.lowerBound
	if row.Depth > 0 {
		row.LagSeconds = max(0, now.Sub(q.arrivals[0]).Seconds())
	}
	op := queuehealth.Status{Status: "ok", CapacityUnavailable: true, DepthUnit: "operations", LagBasis: "operation_progress"}
	for c := range q.calls {
		row.InFlight += c.incoming + c.replay
		if c.progress.IsZero() {
			op.Depth++
			op.LagSeconds = max(op.LagSeconds, now.Sub(c.queued).Seconds())
		} else {
			op.InFlight++
			op.ProcessingSeconds = max(op.ProcessingSeconds, now.Sub(c.progress).Seconds())
		}
	}
	switch {
	case q.stateIO:
		row.Status, row.Reason = "degraded", "state_io"
	case !q.known:
		row.Status, row.Reason = "degraded", "persistence_uncertain"
	case !q.uncertainAt.IsZero() && now.Sub(q.uncertainAt) < time.Minute:
		row.Status, row.Reason = "degraded", "persistence_uncertain"
	}
	switch {
	case op.LagSeconds >= time.Minute.Seconds():
		op.Status, op.Reason = "degraded", "backlog_lag"
	case op.ProcessingSeconds >= time.Minute.Seconds():
		op.Status, op.Reason = "degraded", "processing_lag"
	}
	return map[string]queuehealth.Status{"pending": row, "pending_operations": op}
}
