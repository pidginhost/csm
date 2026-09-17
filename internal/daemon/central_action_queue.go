package daemon

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type centralActionConsumer struct {
	stop     <-chan struct{}
	interval time.Duration
	refresh  func(context.Context) error
	perform  func(centralQueuedAction) error
	queue    *queuehealth.Channel[centralQueuedAction]
	mu       sync.Mutex
	closed   bool
}

func newCentralActionConsumer(stop <-chan struct{}, capacity int, interval time.Duration, refresh func(context.Context) error, perform func(centralQueuedAction) error) *centralActionConsumer {
	return &centralActionConsumer{
		stop: stop, interval: interval, refresh: refresh, perform: perform,
		queue: queuehealth.NewChannel[centralQueuedAction](capacity, time.Minute),
	}
}

func (c *centralActionConsumer) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"actions": c.queue.Snapshot(now)}
}

func (c *centralActionConsumer) enqueue(a centralQueuedAction) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		c.queue.Lose(1)
		return false
	}
	select {
	case <-c.stop:
		c.queue.Lose(1)
		return false
	default:
		return c.queue.TrySend(a)
	}
}

func (c *centralActionConsumer) run() {
	ctx, cancel := context.WithCancel(context.Background())
	canceled := make(chan struct{})
	go func() {
		defer close(canceled)
		select {
		case <-c.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	var loggedLoss uint64
	defer func() {
		cancel()
		<-canceled
		// A dispatch may retain the old hook after it is uninstalled. Close
		// admission with the producer lock before discarding pending work.
		c.mu.Lock()
		c.closed = true
		c.queue.Close()
		c.mu.Unlock()
		c.queue.DiscardPending()
		c.logDropped(&loggedLoss)
	}()

	if err := c.refresh(ctx); err != nil {
		log.Printf("central-intel: initial pull failed: %v", err)
	}
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		select {
		case <-c.stop:
			return
		case work := <-c.queue.Items():
			select {
			case <-c.stop:
				work.Ticket.Reject(time.Now())
				return
			default:
			}
			c.process(work)
		case <-ticker.C:
			c.logDropped(&loggedLoss)
			if err := c.refresh(ctx); err != nil {
				log.Printf("central-intel: refresh failed: %v", err)
			}
		}
	}
}

func (c *centralActionConsumer) process(work queuehealth.Work[centralQueuedAction]) {
	work.Ticket.Start(time.Now())
	settled := false
	defer func() {
		if !settled {
			work.Ticket.Reject(time.Now())
		}
	}()
	err := c.perform(work.Value)
	if err != nil && !isCentralBlockRefusal(err) {
		work.Ticket.Reject(time.Now())
	} else {
		work.Ticket.Finish(time.Now())
	}
	settled = true
	if err != nil {
		logCentralBlockFailure(work.Value.ip, err)
	}
}

func (c *centralActionConsumer) logDropped(previous *uint64) {
	total := c.queue.Snapshot(time.Now()).DroppedTotal
	if n := total - *previous; n > 0 {
		log.Printf("central-intel: %d action(s) incomplete", n)
		*previous = total
	}
}
