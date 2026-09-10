package incident

import (
	"sync"
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/queuehealth"
)

type queuedPersist struct {
	previous        <-chan struct{}
	done            chan struct{}
	snap            Incident
	persist         func(Incident) error
	at              time.Time
	running, failed bool
}

type persistQueue struct {
	mu        sync.Mutex
	tail      chan struct{}
	waiting   map[*queuedPersist]struct{}
	active    *queuedPersist
	idleSince time.Time
	// Deferred bookkeeping waits for the next mutation or explicit flush.
	// Its age is visibility, not a promised delivery deadline.
	deferred                map[string]time.Time
	waitingLoss, activeLoss *queuehealth.Tracker
}

func newPersistQueue() *persistQueue {
	tail := make(chan struct{})
	close(tail)
	return &persistQueue{
		tail:        tail,
		waiting:     make(map[*queuedPersist]struct{}),
		deferred:    make(map[string]time.Time),
		waitingLoss: queuehealth.New(0, time.Minute),
		activeLoss:  queuehealth.New(1, time.Minute),
	}
}

func (q *persistQueue) deferWrite(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, pending := q.deferred[id]; !pending {
		q.deferred[id] = time.Now()
	}
}

func (q *persistQueue) discardDeferred(id string) {
	q.mu.Lock()
	delete(q.deferred, id)
	q.mu.Unlock()
}

func (q *persistQueue) deferredIDs() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	ids := make([]string, 0, len(q.deferred))
	for id := range q.deferred {
		ids = append(ids, id)
	}
	return ids
}

// queuePersistLocked reserves this write's place in mutation order while
// c.mu is still held. The returned callback must run after c.mu is released.
func (c *Correlator) queuePersistLocked(snap Incident) (*queuedPersist, bool) {
	persist := c.cfg.Persist
	q := c.persistence
	if persist == nil {
		q.discardDeferred(snap.ID)
		return nil, false
	}
	req := &queuedPersist{snap: cloneIncident(snap), persist: persist, done: make(chan struct{}), at: time.Now()}
	q.mu.Lock()
	defer q.mu.Unlock()
	// A full immutable snapshot supersedes deferred bookkeeping atomically
	// with publication, so health cannot lose the owner during the transfer.
	delete(q.deferred, snap.ID)
	if q.active == nil && len(q.waiting) == 0 {
		q.idleSince = req.at
	}
	req.previous = q.tail
	q.tail = req.done
	q.waiting[req] = struct{}{}
	return req, true
}

func (q *persistQueue) loseLocked(req *queuedPersist) {
	if req.failed {
		return
	}
	req.failed = true
	tracker := q.waitingLoss
	if req.running {
		tracker = q.activeLoss
	}
	tracker.Lose(time.Now(), 1)
}

func (q *persistQueue) finish(req *queuedPersist, completed bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !completed {
		q.loseLocked(req)
	}
	if req.running {
		q.active = nil
		q.idleSince = time.Now()
	} else {
		delete(q.waiting, req)
	}
	// Publish completion with owner removal; a successor cannot become active
	// while health still attributes the slot to its predecessor.
	close(req.done)
}

func (c *Correlator) runQueuedPersist(req *queuedPersist) {
	q := c.persistence
	<-req.previous
	completed := false
	defer func() { q.finish(req, completed) }()
	q.mu.Lock()
	delete(q.waiting, req)
	q.active = req
	req.running = true
	req.at = time.Now()
	q.mu.Unlock()
	if err := req.persist(req.snap); err != nil {
		q.mu.Lock()
		q.loseLocked(req)
		q.mu.Unlock()
		// The in-memory transition has already advanced. Count failed durable
		// work before logging, which can itself wait on an output writer.
		csmlog.Warn("incident persist failed", "id", req.snap.ID, "kind", string(req.snap.Kind), "status", string(req.snap.Status), "err", err)
	}
	completed = true
}

func (c *Correlator) runQueuedPersists(batch []*queuedPersist) {
	next := 0
	defer func() {
		// The batch reserved contiguous ordering links under c.mu. The active
		// callback has finished its cleanup before this defer, so abandoning
		// its unstarted tail cannot overtake an executing predecessor.
		for _, req := range batch[next:] {
			c.persistence.finish(req, false)
		}
	}()
	for next < len(batch) {
		req := batch[next]
		next++
		c.runQueuedPersist(req)
	}
}

// QueueStatuses reads only queue memory, independently of correlator state and
// persistence callbacks. Waiting writes use progress of the shared writer.
func (c *Correlator) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	q := c.persistence
	q.mu.Lock()
	defer q.mu.Unlock()
	waiting := q.waitingLoss.Snapshot(now)
	waiting.CapacityUnavailable = true
	active := q.activeLoss.Snapshot(now)
	stalled := q.active == nil && !q.idleSince.IsZero() && now.Sub(q.idleSince) >= time.Minute
	if req := q.active; req != nil {
		active.InFlight = 1
		active.ProcessingSeconds = max(0, now.Sub(req.at).Seconds())
		if active.ProcessingSeconds >= time.Minute.Seconds() {
			active.Status, active.Reason = "degraded", "processing_lag"
			stalled = true
		}
	}
	for req := range q.waiting {
		waiting.Depth++
		waiting.LagSeconds = max(waiting.LagSeconds, now.Sub(req.at).Seconds())
		if stalled {
			waiting.Status, waiting.Reason = "degraded", "backlog_lag"
		}
	}
	deferred := queuehealth.Status{Status: "ok", CapacityUnavailable: true, LagBasis: "deferred_checkpoint"}
	for _, at := range q.deferred {
		deferred.Depth++
		deferred.LagSeconds = max(deferred.LagSeconds, now.Sub(at).Seconds())
	}
	return map[string]queuehealth.Status{"persist.waiting": waiting, "persist.active": active, "persist.deferred": deferred}
}
