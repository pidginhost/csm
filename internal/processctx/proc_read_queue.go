package processctx

import (
	"errors"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

var procReads = newProcReadPool(procReadConcurrency)

type procReadPool struct {
	slots chan struct{}
	stats *queuehealth.Tracker
}

func newProcReadPool(capacity int) *procReadPool {
	return &procReadPool{
		slots: make(chan struct{}, capacity),
		stats: queuehealth.NewSharedCapacity(capacity, time.Minute),
	}
}

type procReadWork struct {
	pool      *procReadPool
	ticket    queuehealth.Ticket
	remaining atomic.Int32
	failOnce  sync.Once
}

func (p *procReadPool) acquire() *procReadWork {
	ticket := p.stats.Begin(time.Now())
	select {
	case p.slots <- struct{}{}:
		work := &procReadWork{pool: p, ticket: ticket}
		work.remaining.Store(2)
		return work
	default:
		ticket.Reject(time.Now())
		return nil
	}
}

func (w *procReadWork) fail() {
	w.failOnce.Do(func() { w.pool.stats.Lose(time.Now(), 1) })
}

func (w *procReadWork) release() {
	// A timeout finishes the caller, not the syscall. Conversely, a returned
	// syscall still owns its result until the caller takes it or times out.
	if w.remaining.Add(-1) == 0 {
		w.ticket.Finish(time.Now())
		<-w.pool.slots
	}
}

type procReadResult[T any] struct {
	value T
	err   error
}

func executeProcRead[T any](work *procReadWork, fn func() (T, error), out chan<- procReadResult[T]) {
	work.ticket.Start(time.Now())
	completed := false
	defer func() {
		if !completed {
			work.fail()
		}
		work.release()
	}()
	value, err := fn()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		work.fail()
	}
	out <- procReadResult[T]{value: value, err: err}
	completed = true
}

func runProcReadWithDeadline[T any](pool *procReadPool, d time.Duration, fn func() (T, error)) (T, bool) {
	if d <= 0 {
		value, err := fn()
		return value, err == nil
	}
	var zero T
	work := pool.acquire()
	if work == nil {
		return zero, false
	}
	defer work.release()
	out := make(chan procReadResult[T], 1)
	go executeProcRead(work, fn, out)
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case result := <-out:
		if result.err != nil {
			return zero, false
		}
		return result.value, true
	case <-timer.C:
		work.fail()
		return zero, false
	}
}

func (*ProcReader) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"proc_reads": procReads.stats.Snapshot(now)}
}
