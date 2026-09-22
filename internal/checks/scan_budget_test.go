package checks

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

func runBudgetTestChecks(ctx context.Context, host bool, list []namedCheck) []alert.Finding {
	if host {
		findings, _ := runParallelWithContext(ctx, &config.Config{}, nil, list, "test", true)
		return findings
	}
	return runAccountChecksBounded(ctx, &config.Config{}, nil, list)
}

func TestSharedScanBudgetHealthWhileAnotherRunnerIsBusy(t *testing.T) {
	for _, host := range []bool{false, true} {
		t.Run(map[bool]string{false: "account", true: "host"}[host], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				previous, oldTimeout := checkDispatches, timeoutForFunc
				checkDispatches = newCheckDispatchMonitor()
				timeoutForFunc = func(string) time.Duration { return 15 * time.Minute }
				defer func() { checkDispatches, timeoutForFunc = previous, oldTimeout }()
				ctx, cancel := context.WithCancel(withScanBudget(context.Background(), 1))
				defer cancel()
				list := []namedCheck{{name: "shared_budget", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
					<-ctx.Done()
					return nil
				}}}
				done := make(chan struct{}, 2)
				go func() { runBudgetTestChecks(ctx, host, list); done <- struct{}{} }()
				synctest.Wait()
				waitingCtx, progress := WithCheckDispatchProgress(ctx)
				go func() { runBudgetTestChecks(waitingCtx, !host, list); done <- struct{}{} }()
				synctest.Wait()
				time.Sleep(2 * time.Minute)
				status := checkDispatchStatus(t, checkDispatches)
				if status.Depth != 1 || status.InFlight != 1 || status.Status != "ok" {
					t.Errorf("another runner's occupied slot is not stalled dispatch: %+v", status)
				}
				if got := progress.Snapshot(time.Now()); !got.Active || got.Overdue {
					t.Errorf("waiting operation borrowed unavailable capacity: %+v", got)
				}
				cancel()
				<-done
				<-done
			})
		})
	}
}

func TestScanBudgetRetainsSlotUntilWithdrawnExecutionExits(t *testing.T) {
	for _, host := range []bool{false, true} {
		for _, timeout := range []bool{false, true} {
			name := map[bool]string{false: "account", true: "host"}[host] + "/" + map[bool]string{false: "cancel", true: "timeout"}[timeout]
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					previous, oldTimeout := checkDispatches, timeoutForFunc
					checkDispatches = newCheckDispatchMonitor()
					timeoutForFunc = func(name string) time.Duration {
						if timeout && name == "slow_budget" {
							return time.Second
						}
						return 15 * time.Minute
					}
					defer func() { checkDispatches, timeoutForFunc = previous, oldTimeout }()
					budget := withScanBudget(context.Background(), 1)
					ctx, cancel := context.WithCancel(budget)
					defer cancel()
					release := make(chan struct{})
					releaseCheck := sync.OnceFunc(func() { close(release) })
					defer releaseCheck()
					var running atomic.Int32
					oldDone := make(chan struct{})
					go func() {
						defer close(oldDone)
						runBudgetTestChecks(ctx, host, []namedCheck{{name: "slow_budget", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
							running.Add(1)
							defer running.Add(-1)
							<-release
							return nil
						}}})
					}()
					synctest.Wait()
					if running.Load() != 1 {
						t.Fatal("slow check never started")
					}
					if !timeout {
						cancel()
					}
					<-oldDone
					var started atomic.Int32
					nextCtx, progress := WithCheckDispatchProgress(budget)
					nextDone := make(chan struct{})
					go func() {
						defer close(nextDone)
						runBudgetTestChecks(nextCtx, !host, []namedCheck{{name: "next_budget", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
							started.Add(1)
							if got := running.Load(); got != 0 {
								t.Errorf("new check ran alongside %d withdrawn executions with only one slot", got)
							}
							return nil
						}}})
					}()
					synctest.Wait()
					time.Sleep(2 * time.Minute)
					if got := started.Load(); got != 0 {
						t.Errorf("started %d checks before the occupied slot was released", got)
					}
					if status := checkDispatchStatus(t, checkDispatches); status.Depth != 1 || status.Reason == "backlog_lag" {
						t.Errorf("withdrawn execution's slot was treated as free: %+v", status)
					}
					if got := progress.Snapshot(time.Now()); !got.Active || got.Overdue {
						t.Errorf("waiting behind a withdrawn execution: %+v", got)
					}
					releaseCheck()
					<-nextDone
					if got := started.Load(); got != 1 {
						t.Errorf("next check did not run after release: %d", got)
					}
				})
			})
		}
	}
}

func TestDefaultScanPathsShareHostBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := hostScanBudget
		hostScanBudget = newScanBudget(2)
		defer func() { hostScanBudget = previous }()
		release := make(chan struct{})
		releaseChecks := sync.OnceFunc(func() { close(release) })
		defer releaseChecks()
		var started atomic.Int32
		list := make([]namedCheck, 4)
		for i := range list {
			list[i] = namedCheck{name: "default_budget", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
				started.Add(1)
				<-release
				return nil
			}}
		}
		var wg sync.WaitGroup
		for _, host := range []bool{false, true} {
			wg.Go(func() {
				// Separate parent contexts, neither carrying a private budget.
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				runBudgetTestChecks(ctx, host, list)
			})
		}
		synctest.Wait()
		if got := started.Load(); got != 2 {
			t.Errorf("default paths started %d checks, want shared host capacity of 2", got)
		}
		releaseChecks()
		wg.Wait()
		synctest.Wait()
		if got := started.Load(); got != 8 {
			t.Errorf("default paths completed only %d checks, want 8", got)
		}
		if got := len(hostScanBudget.slots); got != 0 {
			t.Errorf("completed default paths retained %d slots", got)
		}
	})
}

func TestScanBudgetReleasesSlotsAfterPanics(t *testing.T) {
	for _, host := range []bool{false, true} {
		for _, inCheck := range []bool{false, true} {
			name := map[bool]string{false: "account", true: "host"}[host] + "/" + map[bool]string{false: "wrapper", true: "check"}[inCheck]
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx := withScanBudget(context.Background(), 1)
					oldTimeout := timeoutForFunc
					defer func() { timeoutForFunc = oldTimeout }()
					timeoutForFunc = func(string) time.Duration {
						if !inCheck {
							panic("controlled wrapper panic")
						}
						return time.Minute
					}
					findings := runBudgetTestChecks(ctx, host, []namedCheck{{name: "panic_budget", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
						panic("controlled check panic")
					}}})
					synctest.Wait()
					if inCheck && (len(findings) != 1 || findings[0].Check != "check_panic") {
						t.Errorf("check panic was not reported: %+v", findings)
					}
					if got := len(scanBudgetFrom(ctx).slots); got != 0 {
						t.Errorf("panic retained %d slots", got)
					}
					timeoutForFunc = oldTimeout
					var started atomic.Int32
					runBudgetTestChecks(ctx, !host, []namedCheck{{name: "after_panic", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
						started.Add(1)
						return nil
					}}})
					if got := started.Load(); got != 1 {
						t.Errorf("check after panic did not execute: %d", got)
					}
				})
			})
		}
	}
}
