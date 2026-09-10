package attackdb

import (
	"bytes"
	"io"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

// Event batches are detached together under db.mu. Health keeps only their
// counts and oldest arrival, independently of state locks and persistence I/O.
type eventQueue struct {
	mu          sync.Mutex
	waiting     int
	oldest      time.Time
	active      *eventBatch
	losses      *queuehealth.Tracker
	uncertain   bool
	uncertainAt time.Time
}

type eventBatch struct {
	queue              *eventQueue
	count, saved, lost int
	progress           time.Time
}

func (db *DB) eventHealth() *eventQueue {
	db.eventHealthOnce.Do(func() { db.eventQueue = &eventQueue{losses: queuehealth.New(0, time.Minute)} })
	return db.eventQueue
}

func (db *DB) queueEventLocked(event Event) {
	db.pendingEvents = append(db.pendingEvents, event)
	if db.dbPath == "" && store.Global() == nil {
		return
	}
	q := db.eventHealth()
	q.mu.Lock()
	if q.waiting == 0 {
		q.oldest = time.Now()
	}
	q.waiting++
	q.mu.Unlock()
}

func (q *eventQueue) detach() *eventBatch {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.waiting == 0 {
		return nil
	}
	batch := &eventBatch{queue: q, count: q.waiting, progress: time.Now()}
	q.waiting = 0
	q.oldest = time.Time{}
	q.active = batch
	return batch
}

func (b *eventBatch) advance(saved, lost int) {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	b.saved += saved
	b.lost += lost
	now := time.Now()
	if lost > 0 {
		q.losses.Lose(now, uint64(lost))
	}
	b.progress = now
}

func (b *eventBatch) uncertainOutcome() {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	q.uncertain = true
	q.uncertainAt = time.Now()
	q.mu.Unlock()
}

func (b *eventBatch) discardRemaining() {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	remaining := b.count - b.saved - b.lost
	if remaining > 0 {
		q.losses.Lose(time.Now(), uint64(remaining))
		b.lost += remaining
	}
}

func (b *eventBatch) finish() {
	if b == nil {
		return
	}
	q := b.queue
	q.mu.Lock()
	// A panicking boundary may have accepted data without returning its result.
	// Count only confirmed losses; keep the remainder explicitly uncertain.
	if b.count > b.saved+b.lost {
		q.uncertain = true
		q.uncertainAt = time.Now()
	}
	q.active = nil
	q.mu.Unlock()
}

// QueueStatuses never acquires database state or filesystem locks.
func (db *DB) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	q := db.eventHealth()
	q.mu.Lock()
	defer q.mu.Unlock()
	row := q.losses.Snapshot(now)
	row.CapacityUnavailable = true
	row.DepthUnit = "events"
	row.LagBasis = "operation_progress"
	row.Depth = q.waiting
	row.DroppedLowerBound = q.uncertain
	if q.waiting > 0 {
		row.LagSeconds = max(0, now.Sub(q.oldest).Seconds())
	}
	if b := q.active; b != nil {
		row.InFlight = b.count
		row.ProcessingSeconds = max(0, now.Sub(b.progress).Seconds())
	}
	switch {
	case row.LagSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "backlog_lag"
	case row.ProcessingSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "processing_lag"
	case !q.uncertainAt.IsZero() && now.Sub(q.uncertainAt) < time.Minute:
		row.Status, row.Reason = "degraded", "persistence_uncertain"
	}
	return map[string]queuehealth.Status{"events": row}
}

// The encoder escapes embedded newlines. Only a complete JSONL delimiter
// accepted by the file writer counts as a persisted event; buffered bytes do not.
type eventWriter struct {
	writer io.Writer
	batch  *eventBatch
}

func (w eventWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.batch.advance(bytes.Count(p[:n], []byte{'\n'}), 0)
	return n, err
}
