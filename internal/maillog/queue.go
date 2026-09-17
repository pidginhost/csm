package maillog

import (
	"context"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

const queueCapacity = 64

// Queue retains delivery health across reader replacements and source changes.
// The supervisor finishes the old reader before starting its replacement.
type Queue struct {
	health  *queuehealth.Tracker
	journal journalSourceQueue
	file    fileSourceQueue
}

func NewQueue() *Queue {
	return &Queue{health: queuehealth.New(queueCapacity, time.Minute)}
}

func (q *Queue) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	rows := map[string]queuehealth.Status{"delivery": q.health.Snapshot(now)}
	if journal, seen := q.journal.snapshot(now); seen {
		rows["journal_source"] = journal
	}
	if file, seen := q.file.snapshot(now); seen {
		rows["file_source"] = file
	}
	return rows
}

func (q *Queue) channel() chan Line { return make(chan Line, queueCapacity) }

func (q *Queue) send(ctx context.Context, out chan<- Line, line Line) bool {
	line.ticket = q.health.Begin(time.Now())
	return q.sendTracked(ctx, out, line)
}

func (q *Queue) sendFile(ctx context.Context, out chan<- Line, line Line, source *fileSourceGeneration) bool {
	line.ticket = q.health.Begin(time.Now())
	q.file.complete(source)
	return q.sendTracked(ctx, out, line)
}

func (q *Queue) sendTracked(ctx context.Context, out chan<- Line, line Line) bool {
	select {
	case out <- line:
		return true
	case <-ctx.Done():
		line.reject()
		return false
	}
}

func (q *Queue) lose() { q.health.Lose(time.Now(), 1) }

func (line Line) reject() { line.ticket.Reject(time.Now()) }

// Process accounts for delivery through the entire consumer callback. False
// means delivery was abandoned. A panic is counted and continues to the owner.
func (line Line) Process(consume func(Line) bool) (completed bool) {
	ticket := line.ticket
	line.ticket = queuehealth.Ticket{}
	ticket.Start(time.Now())
	defer func() {
		if completed {
			ticket.Finish(time.Now())
		} else {
			ticket.Reject(time.Now())
		}
	}()
	return consume(line)
}
