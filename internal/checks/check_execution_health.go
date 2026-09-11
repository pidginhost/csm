package checks

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

var checkExecutions = newCheckExecutionMonitor()

type checkExecutionMonitor struct {
	mu      sync.Mutex
	pending map[*checkExecution]struct{}
	losses  *queuehealth.Tracker
}

func newCheckExecutionMonitor() *checkExecutionMonitor {
	return &checkExecutionMonitor{
		pending: make(map[*checkExecution]struct{}),
		losses:  queuehealth.New(0, time.Minute),
	}
}

type checkExecution struct {
	monitor   *checkExecutionMonitor
	dispatch  *checkDispatch
	queued    time.Time
	started   time.Time // guarded by monitor.mu
	deadline  time.Time
	remaining atomic.Int32
	failOnce  sync.Once
	done      chan checkExecutionOutcome

	// Only the caller changes this; the function owns its separate release.
	callerSettled bool
}

func (m *checkExecutionMonitor) begin(deadline time.Time) *checkExecution {
	execution := &checkExecution{
		monitor: m, queued: time.Now(), deadline: deadline,
		done: make(chan checkExecutionOutcome, 1),
	}
	execution.remaining.Store(2)
	m.mu.Lock()
	m.pending[execution] = struct{}{}
	m.mu.Unlock()
	return execution
}

func (m *checkExecutionMonitor) execute(ctx context.Context, component string, fn func() []alert.Finding) *checkExecution {
	// Both runners construct a bounded per-check context before dispatch. A
	// caller without one is unbounded rather than already overdue.
	deadline, _ := ctx.Deadline()
	execution := m.begin(deadline)
	execution.dispatch = checkDispatchFrom(ctx)
	execution.dispatch.executing(ctx)
	go execution.run(component, fn)
	return execution
}

func (e *checkExecution) fail() {
	e.failOnce.Do(func() { e.monitor.losses.Lose(time.Now(), 1) })
}

func (e *checkExecution) received() {
	if !e.callerSettled {
		e.dispatch.returned()
		e.callerSettled = true
	}
}

func (e *checkExecution) withdraw(err error) {
	e.received()
	if errors.Is(err, context.DeadlineExceeded) {
		e.fail()
	}
}

func (e *checkExecution) finishCaller() {
	if !e.callerSettled {
		e.fail()
		e.dispatch.returned()
	}
	e.release()
}

func (e *checkExecution) release() {
	// A deadline can release the caller while the function still runs. A
	// finished function likewise retains its buffered result for the caller.
	if e.remaining.Add(-1) == 0 {
		e.monitor.mu.Lock()
		delete(e.monitor.pending, e)
		e.monitor.mu.Unlock()
	}
}

func (m *checkExecutionMonitor) QueueStatus(now time.Time) queuehealth.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.losses.Snapshot(now)
	status.CapacityUnavailable = true
	var waitingLate, runningLate bool
	for execution := range m.pending {
		if execution.started.IsZero() {
			status.Depth++
			status.LagSeconds = max(status.LagSeconds, now.Sub(execution.queued).Seconds())
			waitingLate = waitingLate || overdue(now, execution.deadline)
		} else {
			status.InFlight++
			status.ProcessingSeconds = max(status.ProcessingSeconds, now.Sub(execution.started).Seconds())
			runningLate = runningLate || overdue(now, execution.deadline)
		}
	}
	// Each call has its own deadline. A heavy check must not lend its longer
	// budget to an overdue short check, or get a fresh budget after dispatch.
	switch {
	case waitingLate:
		status.Reason = "backlog_lag"
	case runningLate:
		status.Reason = "processing_lag"
	}
	if status.Reason != "" {
		status.Status = "degraded"
	}
	return status
}

// CheckExecutionQueueStatus reads memory only, including after a runner exits.
func CheckExecutionQueueStatus(now time.Time) queuehealth.Status {
	return checkExecutions.QueueStatus(now)
}

// overdue reports whether a bounded deadline has passed. Work with no deadline
// has no bound to miss.
func overdue(now, deadline time.Time) bool {
	return !deadline.IsZero() && !now.Before(deadline)
}
