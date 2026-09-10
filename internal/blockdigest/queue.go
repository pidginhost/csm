package blockdigest

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type digestQueues struct {
	mu       sync.Mutex
	arrivals []time.Time
	batches  map[*digestBatch]struct{}
	losses   *queuehealth.Tracker
	maxLag   time.Duration
	stopped  bool
	sinks    map[string]*digestSinkQueue
}

type digestBatch struct {
	queue    *digestQueues
	count    int
	progress time.Time
	finished bool
}

type digestSinkQueue struct {
	mu          sync.Mutex
	tracker     *queuehealth.Tracker
	uncertain   bool
	uncertainAt time.Time
}

type digestDelivery struct {
	queue                       *digestSinkQueue
	ticket                      queuehealth.Ticket
	offered, returned, finished bool
}

type digestDeliveryPlan struct{ email, webhook *digestDelivery }

func newDigestQueues(opts Options) *digestQueues {
	q := &digestQueues{batches: make(map[*digestBatch]struct{}), losses: queuehealth.New(maxBuffered, time.Minute), maxLag: max(time.Minute, opts.Interval+time.Minute), sinks: make(map[string]*digestSinkQueue)}
	if opts.EmailSink != nil {
		q.sinks["email"] = &digestSinkQueue{tracker: queuehealth.New(0, time.Minute)}
	}
	if opts.WebhookSink != nil {
		q.sinks["webhook"] = &digestSinkQueue{tracker: queuehealth.New(0, time.Minute)}
	}
	return q
}

// Admission and detach run under the collector lock alongside the actual
// buffer. Health never takes that lock or calls injected lookups or sinks.
func (q *digestQueues) admit() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.arrivals) == maxBuffered {
		q.arrivals = q.arrivals[1:]
		q.losses.Lose(time.Now(), 1)
	}
	q.arrivals = append(q.arrivals, time.Now())
}

func (q *digestQueues) detach() *digestBatch {
	q.mu.Lock()
	defer q.mu.Unlock()
	b := &digestBatch{queue: q, count: len(q.arrivals), progress: time.Now()}
	q.arrivals = nil
	q.batches[b] = struct{}{}
	return b
}

func (b *digestBatch) coalesce(count int) {
	b.queue.mu.Lock()
	b.count = count
	b.progress = time.Now()
	b.queue.mu.Unlock()
}

func (b *digestBatch) finish(completed bool) {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if b.finished {
		return
	}
	if !completed {
		q.losses.Lose(time.Now(), uint64(b.count)) // #nosec G115 -- batch count is a slice length bounded by maxBuffered; coalescing can only reduce it.
	}
	b.finished = true
	delete(q.batches, b)
}

func (q *digestQueues) setStopped(stopped bool) {
	q.mu.Lock()
	q.stopped = stopped
	q.mu.Unlock()
}

func (q *digestSinkQueue) begin() *digestDelivery {
	if q == nil {
		return nil
	}
	return &digestDelivery{queue: q, ticket: q.tracker.Begin(time.Now())}
}

func (c *Collector) beginDelivery() *digestDeliveryPlan {
	return &digestDeliveryPlan{email: c.queues.sinks["email"].begin(), webhook: c.queues.sinks["webhook"].begin()}
}

func (d *digestDelivery) start() { d.ticket.Start(time.Now()) }

func (d *digestDelivery) result(err error) {
	d.returned = true
	if err != nil {
		d.queue.tracker.Lose(time.Now(), 1)
	}
}

func (d *digestDelivery) finish() {
	if d == nil || d.finished {
		return
	}
	if !d.returned {
		if d.offered {
			d.queue.mu.Lock()
			d.queue.uncertain = true
			d.queue.uncertainAt = time.Now()
			d.queue.mu.Unlock()
		} else {
			d.queue.tracker.Lose(time.Now(), 1)
		}
	}
	d.ticket.Finish(time.Now())
	d.finished = true
}

func (p *digestDeliveryPlan) finish() { p.email.finish(); p.webhook.finish() }

func (q *digestQueues) recordStatus(now time.Time) queuehealth.Status {
	q.mu.Lock()
	defer q.mu.Unlock()
	row := q.losses.Snapshot(now)
	row.DepthUnit = "records"
	row.LagBasis = "operation_progress"
	row.Depth = len(q.arrivals)
	if row.Depth > 0 {
		row.LagSeconds = max(0, now.Sub(q.arrivals[0]).Seconds())
	}
	for b := range q.batches {
		row.InFlight += b.count
		row.ProcessingSeconds = max(row.ProcessingSeconds, now.Sub(b.progress).Seconds())
	}
	switch {
	case q.stopped && row.Depth > 0:
		row.Status, row.Reason = "degraded", "consumer_stopped"
	case row.LagSeconds >= q.maxLag.Seconds():
		row.Status, row.Reason = "degraded", "backlog_lag"
	case row.ProcessingSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "processing_lag"
	}
	return row
}

func (q *digestSinkQueue) snapshot(now time.Time) queuehealth.Status {
	q.mu.Lock()
	defer q.mu.Unlock()
	row := q.tracker.Snapshot(now)
	row.CapacityUnavailable = true
	row.DepthUnit = "notifications"
	row.DroppedLowerBound = q.uncertain
	if !q.uncertainAt.IsZero() && now.Sub(q.uncertainAt) < time.Minute {
		row.Status, row.Reason = "degraded", "delivery_uncertain"
	}
	return row
}

func (c *Collector) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	rows := map[string]queuehealth.Status{"records": c.queues.recordStatus(now)}
	for name, q := range c.queues.sinks {
		rows[name] = q.snapshot(now)
	}
	return rows
}
