package checks

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Two scan paths each carried their own fixed concurrency limit, neither of
// them aware of the host's core count or of the other. A periodic tier and an
// operator-triggered account scan could therefore run nine CPU-heavy checks at
// once on a four-core machine, on top of the realtime analyzer pool.

func TestScanParallelismFollowsTheCoreCount(t *testing.T) {
	for _, tc := range []struct {
		cpus int
		want int
	}{
		{0, minScanParallelism},
		{1, minScanParallelism},
		{2, 2},
		{4, 4},
		{5, 5},
		{8, maxScanParallelism},
		{64, maxScanParallelism},
	} {
		if got := scanParallelismFor(tc.cpus); got != tc.want {
			t.Errorf("scanParallelismFor(%d) = %d, want %d", tc.cpus, got, tc.want)
		}
	}
}

// peakTracker records the highest number of checks observed running together.
type peakTracker struct {
	running atomic.Int64
	peak    atomic.Int64
}

func (p *peakTracker) enter() {
	now := p.running.Add(1)
	for {
		peak := p.peak.Load()
		if now <= peak || p.peak.CompareAndSwap(peak, now) {
			return
		}
	}
}

func (p *peakTracker) leave() { p.running.Add(-1) }

func (p *peakTracker) checks(count int) []namedCheck {
	out := make([]namedCheck, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, namedCheck{
			name: "peak_probe",
			fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
				p.enter()
				defer p.leave()
				time.Sleep(20 * time.Millisecond)
				return nil
			},
		})
	}
	return out
}

// budgetCtx scopes a scan to its own budget so one test's blocked checks
// cannot hold slots another test is waiting for.
func budgetCtx(ctx context.Context, slots int) context.Context {
	return withScanBudget(ctx, slots)
}

func TestTierRunnerRespectsTheHostScanBudget(t *testing.T) {
	peak := &peakTracker{}
	ctx := budgetCtx(context.Background(), 2)

	runParallelWithContext(ctx, &config.Config{}, nil, peak.checks(8), "test", false)

	if got := peak.peak.Load(); got > 2 {
		t.Fatalf("%d checks ran together, want at most the budget of 2", got)
	}
}

func TestAccountScanRespectsTheHostScanBudget(t *testing.T) {
	peak := &peakTracker{}
	ctx := budgetCtx(context.Background(), 2)

	runAccountChecksBounded(ctx, &config.Config{}, nil, peak.checks(8))

	if got := peak.peak.Load(); got > 2 {
		t.Fatalf("%d account checks ran together, want at most the budget of 2", got)
	}
}

// The budget is the host's, not each scan path's: a tier scan and an account
// scan running at the same time share it rather than adding up.
func TestConcurrentScanPathsShareOneBudget(t *testing.T) {
	peak := &peakTracker{}
	// One budget, two scan paths: the same context carries it into both.
	ctx := budgetCtx(context.Background(), 2)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		runParallelWithContext(ctx, &config.Config{}, nil, peak.checks(8), "test", false)
	}()
	go func() {
		defer wg.Done()
		runAccountChecksBounded(ctx, &config.Config{}, nil, peak.checks(8))
	}()
	wg.Wait()

	if got := peak.peak.Load(); got > 2 {
		t.Fatalf("two scan paths ran %d checks together, want at most the shared budget of 2", got)
	}
}

func TestScanBudgetReleasesSlotsWhenTheScanIsCancelled(t *testing.T) {
	peak := &peakTracker{}
	budget := budgetCtx(context.Background(), 2)
	ctx, cancel := context.WithCancel(budget)
	cancel()

	runParallelWithContext(ctx, &config.Config{}, nil, peak.checks(4), "test", false)

	// A cancelled scan must hand every slot back, or the next scan starves.
	done := make(chan struct{})
	go func() {
		defer close(done)
		runParallelWithContext(budget, &config.Config{}, nil, peak.checks(2), "test", false)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a later scan could not acquire the budget a cancelled scan held")
	}
}
