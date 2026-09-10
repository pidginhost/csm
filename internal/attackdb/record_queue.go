package attackdb

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

type recordPhase uint8

const (
	recordQueued recordPhase = iota
	recordWriting
	recordSucceeded
	recordFailed
)

type recordDemand struct {
	arrival time.Time
	failed  bool
	phase   recordPhase
}

type recordQueue struct {
	mu          sync.Mutex
	waiting     map[string]recordDemand
	active      *recordBatch
	losses      *queuehealth.Tracker
	uncertain   bool
	uncertainAt time.Time
}

type recordBatch struct {
	queue    *recordQueue
	items    map[string]recordDemand
	progress time.Time
}

func (db *DB) recordHealth() *recordQueue {
	db.recordHealthOnce.Do(func() {
		db.recordQueue = &recordQueue{waiting: make(map[string]recordDemand), losses: queuehealth.New(0, time.Minute)}
	})
	return db.recordQueue
}

func (db *DB) queueRecordLocked(ip string) {
	if db.dbPath == "" && store.Global() == nil {
		return
	}
	q := db.recordHealth()
	q.mu.Lock()
	if _, exists := q.waiting[ip]; !exists {
		q.waiting[ip] = recordDemand{arrival: time.Now()}
	}
	q.mu.Unlock()
}

// The caller detaches the actual dirty and deletion snapshot under db.mu.
// Subsequent mutations then own a separate pending generation for the same IP.
func (db *DB) detachRecordsLocked() *recordBatch {
	q := db.recordHealth()
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.waiting) == 0 {
		return nil
	}
	for ip, demand := range q.waiting {
		demand.phase = recordQueued
		q.waiting[ip] = demand
	}
	b := &recordBatch{queue: q, items: q.waiting, progress: time.Now()}
	q.waiting = make(map[string]recordDemand)
	q.active = b
	return b
}

func (b *recordBatch) begin(ip string) {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	if demand, exists := b.items[ip]; exists {
		demand.phase = recordWriting
		b.items[ip] = demand
	}
	q.mu.Unlock()
}

func (b *recordBatch) beginAll() {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	for ip, demand := range b.items {
		demand.phase = recordWriting
		b.items[ip] = demand
	}
	q.mu.Unlock()
}

func (b *recordBatch) result(ip string, err error) {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	if demand, exists := b.items[ip]; exists {
		demand.failed = err != nil
		demand.phase = recordSucceeded
		if err != nil {
			demand.phase = recordFailed
		}
		b.items[ip] = demand
	}
	b.progress = time.Now()
	q.mu.Unlock()
}

func (b *recordBatch) resultAll(err error) {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	for ip, demand := range b.items {
		demand.failed = err != nil
		demand.phase = recordSucceeded
		if err != nil {
			demand.phase = recordFailed
		}
		b.items[ip] = demand
	}
	b.progress = time.Now()
	q.mu.Unlock()
}

// Reconcile at the real requeue boundary. An older successful delete may also
// satisfy a newer delete, while an intervening record mutation must stay queued.
func (b *recordBatch) finish(db *DB) {
	if b == nil {
		return
	}
	q := b.queue
	// Publish unreturned I/O before retry reconciliation can wait for db.mu.
	q.mu.Lock()
	for _, demand := range b.items {
		if demand.phase == recordWriting {
			q.uncertain = true
			q.uncertainAt = time.Now()
		}
	}
	q.mu.Unlock()
	db.mu.Lock()
	defer db.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	pending := func(ip string) bool {
		_, dirty := db.dirtyIPs[ip]
		_, deleted := db.deletedIPs[ip]
		return dirty || deleted
	}
	for ip := range q.waiting {
		if !pending(ip) {
			delete(q.waiting, ip)
		}
	}
	for ip, demand := range b.items {
		if !pending(ip) {
			if demand.phase == recordQueued || demand.phase == recordFailed {
				q.losses.Lose(time.Now(), 1)
			}
			continue
		}
		next, exists := q.waiting[ip]
		if !exists || demand.failed && demand.arrival.Before(next.arrival) {
			next.arrival = demand.arrival
		}
		next.failed = next.failed || demand.failed
		q.waiting[ip] = next
	}
	q.active = nil
}

func (q *recordQueue) snapshot(now time.Time) queuehealth.Status {
	q.mu.Lock()
	defer q.mu.Unlock()
	row := q.losses.Snapshot(now)
	row.CapacityUnavailable = true
	row.DepthUnit = "records"
	row.LagBasis = "operation_progress"
	row.Depth = len(q.waiting)
	row.DroppedLowerBound = q.uncertain
	failed := false
	for _, demand := range q.waiting {
		row.LagSeconds = max(row.LagSeconds, now.Sub(demand.arrival).Seconds())
		failed = failed || demand.failed
	}
	if b := q.active; b != nil {
		row.InFlight = len(b.items)
		row.ProcessingSeconds = max(0, now.Sub(b.progress).Seconds())
		for _, demand := range b.items {
			failed = failed || demand.failed
		}
	}
	switch {
	case !q.uncertainAt.IsZero() && now.Sub(q.uncertainAt) < time.Minute:
		row.Status, row.Reason = "degraded", "persistence_uncertain"
	case failed:
		row.Status, row.Reason = "degraded", "retry_failed"
	case row.LagSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "backlog_lag"
	case row.ProcessingSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "processing_lag"
	}
	return row
}

// QueueStatuses never acquires database state or filesystem locks.
func (db *DB) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"events": db.eventQueueStatus(now), "records": db.recordHealth().snapshot(now)}
}
