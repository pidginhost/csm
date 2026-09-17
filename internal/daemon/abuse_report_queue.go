package daemon

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/reporting"
)

type abuseReportConsumer struct {
	stop     <-chan struct{}
	interval time.Duration
	persist  func(reporting.Report) error
	drain    func(context.Context)
	queue    *queuehealth.Channel[reporting.Report]
	mu       sync.Mutex
	closed   bool
}

func newAbuseReportConsumer(stop <-chan struct{}, capacity int, interval time.Duration, persist func(reporting.Report) error, drain func(context.Context)) *abuseReportConsumer {
	return &abuseReportConsumer{
		stop: stop, interval: interval, persist: persist, drain: drain,
		queue: queuehealth.NewChannel[reporting.Report](capacity, time.Minute),
	}
}

func (c *abuseReportConsumer) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"ingress": c.queue.Snapshot(now)}
}

func (c *abuseReportConsumer) enqueue(r reporting.Report) bool {
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
		return c.queue.TrySend(r)
	}
}

func (c *abuseReportConsumer) closeAdmission() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.queue.Close()
	}
}

func (c *abuseReportConsumer) run() {
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
		c.closeAdmission()
		c.queue.DiscardPending()
		c.logDropped(&loggedLoss)
	}()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			c.persistRemaining()
			return
		default:
		}
		select {
		case <-c.stop:
			c.persistRemaining()
			return
		case work := <-c.queue.Items():
			c.process(work)
		case <-ticker.C:
			c.logDropped(&loggedLoss)
			c.drain(ctx)
		}
	}
}

func (c *abuseReportConsumer) persistRemaining() {
	// Stop admission before draining: a captured report hook must not append
	// work after the final empty check or keep shutdown running indefinitely.
	c.closeAdmission()
	for work := range c.queue.Items() {
		c.process(work)
	}
}

func (c *abuseReportConsumer) process(work queuehealth.Work[reporting.Report]) {
	work.Ticket.Start(time.Now())
	settled := false
	defer func() {
		if !settled {
			work.Ticket.Reject(time.Now())
		}
	}()
	err := c.persist(work.Value)
	if err != nil {
		work.Ticket.Reject(time.Now())
	} else {
		work.Ticket.Finish(time.Now())
	}
	settled = true
	if err != nil {
		log.Printf("abuse-reporting: report persistence failed: %v", err)
	}
}

func (c *abuseReportConsumer) logDropped(previous *uint64) {
	total := c.queue.Snapshot(time.Now()).DroppedTotal
	if n := total - *previous; n > 0 {
		log.Printf("abuse-reporting: %d report(s) incomplete", n)
		*previous = total
	}
}
