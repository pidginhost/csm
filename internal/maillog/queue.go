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
	health *queuehealth.Tracker
}

func NewQueue() *Queue {
	return &Queue{health: queuehealth.New(queueCapacity, time.Minute)}
}

func (q *Queue) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"delivery": q.health.Snapshot(now)}
}

func (q *Queue) channel() chan Line { return make(chan Line, queueCapacity) }

func (q *Queue) send(ctx context.Context, out chan<- Line, line Line) bool {
	line.ticket = q.health.Begin(time.Now())
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
