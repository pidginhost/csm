package actionlog

import (
	"log"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type writePool struct {
	slots chan struct{}
	stats *queuehealth.Tracker
}

// writeStallBudget is how long a sink write may run before the row reports a
// stall. The caller's own wait budget is far shorter, so a batch of actions
// serialising behind one file lock is normal rather than a degradation.
const writeStallBudget = time.Minute

var actionWrites = newWritePool(64)

func newWritePool(capacity int) *writePool {
	return &writePool{
		slots: make(chan struct{}, capacity),
		stats: queuehealth.NewSharedCapacity(capacity, writeStallBudget),
	}
}

// QueueStatus preserves process-wide work and loss across sink changes. A
// caller deadline does not discard a record that its sink may still write.
func QueueStatus(now time.Time) queuehealth.Status {
	return actionWrites.stats.Snapshot(now)
}

func (p *writePool) write(s Sink, r Record) {
	timer := time.NewTimer(writeTimeout)
	defer timer.Stop()
	select {
	case p.slots <- struct{}{}:
	case <-timer.C:
		p.stats.Lose(time.Now(), 1)
		return
	}
	ticket := p.stats.Begin(time.Now())
	ticket.Start(time.Now())
	done := make(chan struct{})
	go func() {
		failed := true
		defer func() {
			v := recover()
			if failed {
				p.stats.Lose(time.Now(), 1)
			}
			defer func() {
				<-p.slots
				ticket.Finish(time.Now())
				close(done)
			}()
			if v != nil {
				log.Printf("action log sink panicked: %v", v)
			}
		}()
		failed = s.Write(r) != nil
	}()
	select {
	case <-done:
	case <-timer.C:
	}
}
