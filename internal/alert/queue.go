package alert

import (
	"errors"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

var (
	ErrQueueTimeout = errors.New("finding queue deadline exceeded")
	ErrQueueStopped = errors.New("finding queue stopped")
)

var ingestQueues = struct {
	sync.RWMutex
	queues map[chan<- Finding]*queuehealth.Tracker
}{queues: make(map[chan<- Finding]*queuehealth.Tracker)}

// RegisterQueue attaches accounting to a daemon's ingest channel for its
// lifetime. Standalone consumers have no daemon health snapshot and continue
// to use the same watcher APIs without a registered ingest channel.
func RegisterQueue(ch chan<- Finding, q *queuehealth.Tracker) func() {
	ingestQueues.Lock()
	ingestQueues.queues[ch] = q
	ingestQueues.Unlock()
	return func() {
		ingestQueues.Lock()
		defer ingestQueues.Unlock()
		if ingestQueues.queues[ch] == q {
			delete(ingestQueues.queues, ch)
		}
	}
}

func queuedFinding(ch chan<- Finding, f Finding) Finding {
	f.queueTicket = queuehealth.Ticket{}
	ingestQueues.RLock()
	q := ingestQueues.queues[ch]
	ingestQueues.RUnlock()
	if q != nil {
		f.queueTicket = q.Begin(time.Now())
	}
	return f
}

// TryEnqueue preserves the realtime producers' nonblocking contract while
// counting every lost finding in the shared ingest queue's health evidence.
func TryEnqueue(ch chan<- Finding, f Finding) bool {
	f = queuedFinding(ch, f)
	select {
	case ch <- f:
		return true
	default:
		f.queueTicket.Reject(time.Now())
		return false
	}
}

// Enqueue waits for capacity or shutdown. Callers that cannot block use
// TryEnqueue; bounded queues must never spawn a goroutine for each send.
func Enqueue(ch chan<- Finding, f Finding, stop <-chan struct{}) bool {
	f = queuedFinding(ch, f)
	select {
	case ch <- f:
		return true
	case <-stop:
		f.queueTicket.Reject(time.Now())
		return false
	}
}

// EnqueueWithin admits one finding with a bounded wait. The initial full
// channel is backpressure, not loss: its ticket is rejected only if the
// deadline or shutdown wins before a send succeeds.
func EnqueueWithin(ch chan<- Finding, f Finding, stop <-chan struct{}, timeout time.Duration) error {
	f = queuedFinding(ch, f)
	select {
	case ch <- f:
		return nil
	default:
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ch <- f:
		return nil
	case <-stop:
		f.queueTicket.Reject(time.Now())
		return ErrQueueStopped
	case <-timer.C:
		f.queueTicket.Reject(time.Now())
		return ErrQueueTimeout
	}
}

// RecordQueueLoss covers work abandoned with the rest of a batch before
// individual tickets were created.
func RecordQueueLoss(ch chan<- Finding, count uint64) {
	ingestQueues.RLock()
	q := ingestQueues.queues[ch]
	ingestQueues.RUnlock()
	if q != nil {
		q.Lose(time.Now(), count)
	}
}

func RejectQueued(f Finding) { f.queueTicket.Reject(time.Now()) }

func StartQueued(f Finding) { f.queueTicket.Start(time.Now()) }

// FinishQueued receives the original input batch before filtering or
// deduplication, so discarded duplicates also release their queue tickets.
func FinishQueued(findings []Finding) {
	now := time.Now()
	for _, f := range findings {
		f.queueTicket.Finish(now)
	}
}
