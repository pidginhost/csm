package checks

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/state"
)

func checkExecutionStatus(t *testing.T, m *checkExecutionMonitor, now time.Time) queuehealth.Status {
	t.Helper()
	done := make(chan queuehealth.Status, 1)
	go func() { done <- m.QueueStatus(now) }()
	select {
	case status := <-done:
		if !status.CapacityUnavailable || status.Capacity != 0 {
			t.Fatalf("execution monitor invented a global cap: %+v", status)
		}
		return status
	case <-time.After(time.Second):
		t.Fatal("check execution status waited for a check or result receiver")
		return queuehealth.Status{}
	}
}

func TestCheckExecutionHealthRetainsTimedOutFunction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckExecutionMonitor()
		release := make(chan struct{})
		releaseFunction := sync.OnceFunc(func() { close(release) })
		defer releaseFunction()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		execution := m.execute(ctx, "check-health-test", func() []alert.Finding { <-release; return nil })
		synctest.Wait()
		status := checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 1 || status.DroppedTotal != 0 || status.Status != "ok" {
			t.Fatalf("started check = %+v", status)
		}
		time.Sleep(2 * time.Second)
		execution.withdraw(ctx.Err())
		execution.finishCaller()
		status = checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 1 || status.DroppedTotal != 1 || status.ProcessingSeconds != 2 || status.Reason != "processing_lag" {
			t.Fatalf("caller timeout concealed the actual check: %+v", status)
		}
		releaseFunction()
		synctest.Wait()
		status = checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 || status.Status != "ok" {
			t.Fatalf("late check did not release ownership: %+v", status)
		}
	})
}

func TestCheckExecutionHealthRetainsBufferedResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckExecutionMonitor()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		execution := m.execute(ctx, "check-health-test", func() []alert.Finding {
			return []alert.Finding{{Check: "integrity", Severity: alert.High}}
		})
		synctest.Wait()
		status := checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 1 || status.DroppedTotal != 0 || len(execution.done) != 1 {
			t.Fatalf("unconsumed check result disappeared: %+v buffered=%d", status, len(execution.done))
		}
		outcome := <-execution.done
		if outcome.panicErr != "" || len(outcome.findings) != 1 || outcome.findings[0].Check != "integrity" {
			t.Fatalf("check result changed: %+v", outcome)
		}
		execution.received()
		execution.finishCaller()
		status = checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Status != "ok" {
			t.Fatalf("consumed check result did not settle: %+v", status)
		}
	})
}

func TestCheckExecutionHealthUsesEachCallsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckExecutionMonitor()
		releaseShort, releaseLong := make(chan struct{}), make(chan struct{})
		finishShort := sync.OnceFunc(func() { close(releaseShort) })
		finishLong := sync.OnceFunc(func() { close(releaseLong) })
		defer finishShort()
		defer finishLong()
		shortCtx, cancelShort := context.WithTimeout(context.Background(), time.Second)
		defer cancelShort()
		longCtx, cancelLong := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancelLong()
		short := m.execute(shortCtx, "check-health-test", func() []alert.Finding { <-releaseShort; return nil })
		long := m.execute(longCtx, "check-health-test", func() []alert.Finding { <-releaseLong; return nil })
		synctest.Wait()
		time.Sleep(2 * time.Second)
		status := checkExecutionStatus(t, m, time.Now())
		if status.InFlight != 2 || status.ProcessingSeconds != 2 || status.Reason != "processing_lag" {
			t.Fatalf("long check budget hid an overdue short check: %+v", status)
		}
		short.withdraw(shortCtx.Err())
		short.finishCaller()
		finishShort()
		synctest.Wait()
		time.Sleep(6 * time.Minute)
		status = checkExecutionStatus(t, m, time.Now())
		if status.InFlight != 1 || status.DroppedTotal != 1 || status.ProcessingSeconds != 362 || status.Status != "ok" {
			t.Fatalf("legitimate heavy check was declared stalled: %+v", status)
		}
		finishLong()
		<-long.done
		long.received()
		long.finishCaller()
		synctest.Wait()
		status = checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 || status.Status != "ok" {
			t.Fatalf("mixed-budget work did not settle: %+v", status)
		}
	})
}

func TestCheckExecutionHealthStartDoesNotResetDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckExecutionMonitor()
		execution := m.begin(time.Now().Add(time.Second))
		release := make(chan struct{})
		releaseFunction := sync.OnceFunc(func() { close(release) })
		defer releaseFunction()
		time.Sleep(2 * time.Second)
		status := checkExecutionStatus(t, m, time.Now())
		if status.Depth != 1 || status.InFlight != 0 || status.LagSeconds != 2 || status.Reason != "backlog_lag" {
			t.Fatalf("unstarted execution was hidden: %+v", status)
		}
		go execution.run("check-health-test", func() []alert.Finding { <-release; return nil })
		synctest.Wait()
		status = checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 1 || status.ProcessingSeconds != 0 || status.Reason != "processing_lag" {
			t.Fatalf("late worker start reset its caller's deadline: %+v", status)
		}
		execution.withdraw(context.DeadlineExceeded)
		execution.finishCaller()
		releaseFunction()
		synctest.Wait()
	})
}

func TestCheckExecutionHealthCancellationAndPanicCountOnce(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		for _, panics := range []bool{false, true} {
			name := "cancel/normal"
			if deadline {
				name = "deadline/normal"
			}
			if panics {
				name += "/panic"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					m := newCheckExecutionMonitor()
					release := make(chan struct{})
					releaseFunction := sync.OnceFunc(func() { close(release) })
					defer releaseFunction()
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					execution := m.execute(ctx, "check-health-test", func() []alert.Finding {
						<-release
						if panics {
							panic("controlled check failure")
						}
						return nil
					})
					synctest.Wait()
					if deadline {
						<-ctx.Done()
					} else {
						cancel()
					}
					execution.withdraw(ctx.Err())
					execution.finishCaller()
					releaseFunction()
					synctest.Wait()
					wantLoss := uint64(0)
					if deadline || panics {
						wantLoss = 1
					}
					status := checkExecutionStatus(t, m, time.Now())
					if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != wantLoss {
						t.Fatalf("cancellation and late failure accounting: %+v", status)
					}
					outcome := <-execution.done
					if (outcome.panicErr != "") != panics {
						t.Fatalf("panic outcome was changed: %+v", outcome)
					}
				})
			})
		}
	}
}

func TestCheckExecutionHealthCountsAbandonedCaller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckExecutionMonitor()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for range 3 {
			execution := m.execute(ctx, "check-health-test", func() []alert.Finding { return nil })
			synctest.Wait()
			execution.finishCaller()
		}
		status := checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 3 || status.Reason != "dropped_work" {
			t.Fatalf("unhandled caller exits lost their evidence: %+v", status)
		}
		time.Sleep(time.Minute)
		status = checkExecutionStatus(t, m, time.Now())
		if status.Status != "ok" || status.DroppedTotal != 3 {
			t.Fatalf("abandoned-caller loss window did not recover: %+v", status)
		}
	})
}

func TestCheckExecutionHealthCountsAbnormalFunctionExit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckExecutionMonitor()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		execution := m.execute(ctx, "check-health-test", func() []alert.Finding { runtime.Goexit(); return nil })
		outcome := <-execution.done
		if outcome.panicErr != "" || len(outcome.findings) != 0 {
			t.Fatalf("abnormal exit outcome changed: %+v", outcome)
		}
		execution.received()
		execution.finishCaller()
		synctest.Wait()
		status := checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 {
			t.Fatalf("abnormal function exit lost its evidence: %+v", status)
		}
	})
}

func TestCheckExecutionHealthConcurrentCallersRetainFunctions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const count = 64
		m := newCheckExecutionMonitor()
		release := make(chan struct{})
		releaseFunctions := sync.OnceFunc(func() { close(release) })
		defer releaseFunctions()
		withdraw := make(chan struct{})
		withdrawCallers := sync.OnceFunc(func() { close(withdraw) })
		defer withdrawCallers()
		var callers sync.WaitGroup
		for i := range count {
			callers.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				execution := m.execute(ctx, "check-health-test", func() []alert.Finding { <-release; return nil })
				<-withdraw
				if i%2 == 0 {
					cancel()
				} else {
					<-ctx.Done()
				}
				execution.withdraw(ctx.Err())
				execution.finishCaller()
			})
		}
		synctest.Wait()
		status := checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != count || status.DroppedTotal != 0 || status.Status != "ok" {
			t.Fatalf("concurrent execution registration: %+v", status)
		}
		withdrawCallers()
		callers.Wait()
		status = checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != count || status.DroppedTotal != count/2 || status.Reason != "processing_lag" {
			t.Fatalf("concurrent withdrawals concealed live functions: %+v", status)
		}
		releaseFunctions()
		synctest.Wait()
		status = checkExecutionStatus(t, m, time.Now())
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != count/2 || status.Reason != "dropped_work" {
			t.Fatalf("concurrent function completion did not settle: %+v", status)
		}
		time.Sleep(time.Minute)
		status = checkExecutionStatus(t, m, time.Now())
		if status.Status != "ok" || status.DroppedTotal != count/2 {
			t.Fatalf("concurrent timeout loss window did not recover: %+v", status)
		}
	})
}

func TestCheckExecutionHealthTracksBothRunnersAfterTimeout(t *testing.T) {
	for _, host := range []bool{false, true} {
		name := "account"
		if host {
			name = "host"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				previous := checkExecutions
				checkExecutions = newCheckExecutionMonitor()
				defer func() { checkExecutions = previous }()
				previousTimeout := timeoutForFunc
				timeoutForFunc = func(string) time.Duration { return time.Second }
				defer func() { timeoutForFunc = previousTimeout }()
				release := make(chan struct{})
				releaseFunction := sync.OnceFunc(func() { close(release) })
				defer releaseFunction()
				nc := namedCheck{name: "check_health_control", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding { <-release; return nil }}
				var findings []alert.Finding
				if host {
					findings, _ = runParallel(&config.Config{}, nil, []namedCheck{nc}, string(TierDeep), true)
				} else {
					findings = runAccountScanCheck(context.Background(), nc, &config.Config{}, nil, time.Second)
				}
				if len(findings) != 1 || findings[0].Check != "check_timeout" {
					t.Fatalf("runner timeout result changed: %+v", findings)
				}
				status := CheckExecutionQueueStatus(time.Now())
				if status.Depth != 0 || status.InFlight != 1 || status.DroppedTotal != 1 || status.Reason != "processing_lag" {
					t.Fatalf("runner hid timed-out function: %+v", status)
				}
				releaseFunction()
				synctest.Wait()
				status = CheckExecutionQueueStatus(time.Now())
				if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 || status.Status != "ok" {
					t.Fatalf("runner did not settle after function exit: %+v", status)
				}
			})
		})
	}
}
