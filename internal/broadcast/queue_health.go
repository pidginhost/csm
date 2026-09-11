package broadcast

import (
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// Subscription owns one bounded delivery buffer. Events must have one consumer.
type Subscription struct {
	events chan Delivery
	stats  *queuehealth.Tracker
}

func (s *Subscription) Events() <-chan Delivery { return s.events }

// Delivery retains queue ownership through encoding and writing to the client.
// Call Process exactly once for every received delivery, including failures.
type Delivery struct {
	finding alert.Finding
	total   queuehealth.Ticket
	local   queuehealth.Ticket
}

func (d Delivery) Process(fn func(alert.Finding) error) error {
	now := time.Now()
	d.total.Start(now)
	d.local.Start(now)
	failed := true
	defer func() { d.finish(failed) }()
	err := fn(d.finding)
	failed = err != nil
	return err
}

func (d Delivery) finish(failed bool) {
	now := time.Now()
	if failed {
		d.total.Reject(now)
		d.local.Reject(now)
	} else {
		d.total.Finish(now)
		d.local.Finish(now)
	}
}

// QueueStatuses aggregates subscriber work without retaining departed clients
// or exposing client identities. The total tracker keeps in-flight work and
// cumulative loss after removal; local trackers prevent an empty peer from
// hiding a full subscriber buffer. The row is advisory: a client that stops
// reading loses its own copy of findings that are already stored.
func (b *Bus) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	b.mu.RLock()
	defer b.mu.RUnlock()
	status := b.stats.Snapshot(now)
	status.Advisory = true
	for sub := range b.subscribers {
		local := sub.stats.Snapshot(now)
		status.Capacity += local.Capacity
		if local.Reason == "queue_full" && (status.Reason == "" || status.Reason == "dropped_work") {
			status.Status, status.Reason = "degraded", "queue_full"
		}
	}
	return map[string]queuehealth.Status{"deliveries": status}
}
