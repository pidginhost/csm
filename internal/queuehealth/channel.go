package queuehealth

import "time"

// Work retains accounting after a channel receive. The consumer starts its
// ticket, then finishes or rejects it after processing, including error paths.
type Work[T any] struct {
	Value  T
	Ticket Ticket
}

// Process keeps filtered work accounted through the consumer's whole callback.
// A panicking consumer loses this item; the panic continues to its owner.
func (w Work[T]) Process(fn func(T)) {
	w.Ticket.Start(time.Now())
	completed := false
	defer func() {
		if completed {
			w.Ticket.Finish(time.Now())
		} else {
			w.Ticket.Reject(time.Now())
		}
	}()
	fn(w.Value)
	completed = true
}

// Channel accounts for bounded waiting work and its consumers. Its owner
// closes it after all producers have stopped; stopped consumers must leave
// queued work to DiscardPending instead of silently abandoning it.
type Channel[T any] struct {
	items   chan Work[T]
	tracker *Tracker
	now     func() time.Time
}

func NewChannel[T any](capacity int, maxLag time.Duration) *Channel[T] {
	return &Channel[T]{
		items: make(chan Work[T], capacity), tracker: New(capacity, maxLag), now: time.Now,
	}
}

func (q *Channel[T]) Items() <-chan Work[T] { return q.items }

func (q *Channel[T]) TrySend(value T) bool {
	work := Work[T]{Value: value, Ticket: q.tracker.Begin(q.now())}
	select {
	case q.items <- work:
		return true
	default:
		work.Ticket.Reject(q.now())
		return false
	}
}

func (q *Channel[T]) Send(value T, stop <-chan struct{}) bool {
	work := Work[T]{Value: value, Ticket: q.tracker.Begin(q.now())}
	select {
	case q.items <- work:
		return true
	case <-stop:
		work.Ticket.Reject(q.now())
		return false
	}
}

func (q *Channel[T]) Close() { close(q.items) }

// DiscardPending runs after Close and after consumers have stopped. A work
// item already received by a consumer still belongs to that consumer.
func (q *Channel[T]) DiscardPending() {
	for work := range q.items {
		work.Ticket.Reject(q.now())
	}
}

func (q *Channel[T]) Snapshot(now time.Time) Status { return q.tracker.Snapshot(now) }

// Lose counts work rejected before it could be represented by a queued item.
func (q *Channel[T]) Lose(count uint64) { q.tracker.Lose(q.now(), count) }
