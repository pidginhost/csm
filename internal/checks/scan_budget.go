package checks

import (
	"context"
	"runtime"
	"sync/atomic"
)

const (
	// minScanParallelism keeps a single-core host making progress across the
	// check set instead of serialising a scan behind one slow filesystem walk.
	minScanParallelism = 2

	// maxScanParallelism is the ceiling every scan path used to apply
	// unconditionally. Checks walk account trees and hash file content, so
	// past this point they starve each other on I/O rather than finishing
	// sooner, and the Web UI stops answering.
	maxScanParallelism = 5
)

// hostScanBudget bounds how many CPU-heavy checks run at once across the whole
// daemon. The tier runner and the per-account scan used to carry separate
// fixed limits, so an operator-triggered account scan during a periodic tier
// ran nine checks together on a four-core host.
var hostScanBudget = newScanBudget(scanParallelismFor(runtime.NumCPU()))

type scanBudgetKey struct{}

// withScanBudget scopes a scan to its own budget. Production scans carry none
// and share the host budget; tests use this so one test's checks cannot hold
// slots another test is waiting for.
func withScanBudget(ctx context.Context, slots int) context.Context {
	return context.WithValue(ctx, scanBudgetKey{}, newScanBudget(slots))
}

// scanBudgetFrom returns the budget this scan draws from.
func scanBudgetFrom(ctx context.Context) *scanBudget {
	if ctx != nil {
		if budget, ok := ctx.Value(scanBudgetKey{}).(*scanBudget); ok && budget != nil {
			return budget
		}
	}
	return hostScanBudget
}

// scanParallelismFor sizes the budget from the host's core count, bounded at
// both ends.
func scanParallelismFor(cpus int) int {
	if cpus < minScanParallelism {
		return minScanParallelism
	}
	if cpus > maxScanParallelism {
		return maxScanParallelism
	}
	return cpus
}

// scanBudget is a counting semaphore. Callers acquire one slot per check and
// must not hold one while acquiring another: nothing in the scan paths nests,
// and a nested acquisition would deadlock against a full budget.
type scanBudget struct {
	slots chan struct{}
}

func newScanBudget(slots int) *scanBudget {
	if slots < 1 {
		slots = 1
	}
	return &scanBudget{slots: make(chan struct{}, slots)}
}

// acquire blocks until a slot is free or ctx is done. The runner and its
// asynchronous execution share ownership so cancellation cannot free a slot
// while a check that ignores its context is still consuming resources.
func (b *scanBudget) acquire(ctx context.Context) *scanSlot {
	select {
	case b.slots <- struct{}{}:
		slot := &scanSlot{budget: b}
		slot.owners.Store(1)
		return slot
	case <-ctx.Done():
		return nil
	}
}

func (b *scanBudget) size() int { return cap(b.slots) }

func (b *scanBudget) hasCapacity() bool { return len(b.slots) < b.size() }

type scanSlot struct {
	budget *scanBudget
	owners atomic.Int32
}

func (s *scanSlot) retain() {
	if s != nil {
		s.owners.Add(1)
	}
}

func (s *scanSlot) release() {
	if s != nil && s.owners.Add(-1) == 0 {
		<-s.budget.slots
	}
}
