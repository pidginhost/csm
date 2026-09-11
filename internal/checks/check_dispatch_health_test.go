package checks

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/state"
)

func checkDispatchStatus(t *testing.T, m *checkDispatchMonitor) queuehealth.Status {
	t.Helper()
	done := make(chan queuehealth.Status, 1)
	go func() { done <- m.QueueStatus(time.Now()) }()
	select {
	case status := <-done:
		if !status.CapacityUnavailable || status.Capacity != 0 || status.LagBasis != "consumer_progress" {
			t.Fatalf("dispatch evidence invents a global capacity or waiting age: %+v", status)
		}
		return status
	case <-time.After(time.Second):
		t.Fatal("dispatch snapshot blocked behind a runner")
		return queuehealth.Status{}
	}
}

type checkDispatchBlockingContext struct {
	context.Context
	entered  chan struct{}
	release  <-chan struct{}
	deadline bool
}

func (c checkDispatchBlockingContext) Err() error {
	if !c.deadline {
		close(c.entered)
		<-c.release
	}
	return c.Context.Err()
}

func (c checkDispatchBlockingContext) Deadline() (time.Time, bool) {
	if c.deadline {
		close(c.entered)
		<-c.release
	}
	return c.Context.Deadline()
}

// Mutex waits do not advance synctest time, so this lock probe uses real time.
func TestCheckDispatchHealthSnapshotDoesNotWaitForContext(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "error"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			m := newCheckDispatchMonitor()
			task := m.begin(1, 1)[0]
			parent, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			releaseContext := sync.OnceFunc(func() { close(release) })
			defer releaseContext()
			ctx := checkDispatchBlockingContext{Context: parent, entered: entered, release: release, deadline: deadline}
			done := make(chan struct{})
			go func() {
				defer close(done)
				task.wrap(func() {
					task.admit()
					if deadline {
						task.executing(ctx)
					} else {
						task.withdraw(ctx)
					}
				})()
			}()
			<-entered
			status := checkDispatchStatus(t, m)
			if status.Depth != 0 || status.InFlight != 1 || status.DroppedTotal != 0 {
				t.Fatalf("context transition lost running ownership: %+v", status)
			}
			releaseContext()
			<-done
			status = checkDispatchStatus(t, m)
			if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 {
				t.Fatalf("context transition did not settle: %+v", status)
			}
		})
	}
}

func TestCheckDispatchHealthPendingAndControlPhases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckDispatchMonitor()
		tasks := m.begin(3, 2)
		status := checkDispatchStatus(t, m)
		if status.Depth != 3 || status.InFlight != 0 || status.Status != "ok" {
			t.Fatalf("batch was not registered before dispatch: %+v", status)
		}
		time.Sleep(time.Minute)
		status = checkDispatchStatus(t, m)
		if status.Depth != 3 || status.LagSeconds != 60 || status.Reason != "backlog_lag" {
			t.Fatalf("unused worker capacity concealed stuck dispatch: %+v", status)
		}
		tasks[0].admit()
		time.Sleep(time.Minute)
		status = checkDispatchStatus(t, m)
		if status.Depth != 2 || status.InFlight != 1 || status.ProcessingSeconds != 60 || status.Reason != "processing_lag" {
			t.Fatalf("pre-execution control work was hidden: %+v", status)
		}
		for _, task := range tasks {
			task.wrap(func() {})()
		}
		status = checkDispatchStatus(t, m)
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Status != "ok" {
			t.Fatalf("settled dispatch did not recover: %+v", status)
		}
	})
}

func TestCheckDispatchHealthUsesExecutionDeadlineThenControlBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckDispatchMonitor()
		tasks := m.begin(3, 2)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		for _, task := range tasks[:2] {
			task.admit()
			task.executing(ctx)
		}
		time.Sleep(6 * time.Minute)
		status := checkDispatchStatus(t, m)
		if status.Depth != 1 || status.InFlight != 2 || status.ProcessingSeconds != 360 || status.Status != "ok" {
			t.Fatalf("healthy heavy checks were declared stalled: %+v", status)
		}
		tasks[0].returned()
		time.Sleep(time.Minute)
		status = checkDispatchStatus(t, m)
		if status.Depth != 1 || status.InFlight != 2 || status.Reason != "processing_lag" {
			t.Fatalf("result handling borrowed the heavy check deadline: %+v", status)
		}
		tasks[0].wrap(func() {})()
		tasks[2].admit()
		tasks[2].executing(ctx)
		status = checkDispatchStatus(t, m)
		if status.Depth != 0 || status.InFlight != 2 || status.Status != "ok" {
			t.Fatalf("available worker did not resume dispatch: %+v", status)
		}
		for _, task := range tasks[1:] {
			task.wrap(func() {})()
		}
	})
}

func TestCheckDispatchHealthDoesNotHideFreeWorkerSlots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckDispatchMonitor()
		tasks := m.begin(3, 2)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		tasks[0].admit()
		tasks[0].executing(ctx)
		time.Sleep(time.Minute)
		status := checkDispatchStatus(t, m)
		if status.Depth != 2 || status.InFlight != 1 || status.Reason != "backlog_lag" {
			t.Fatalf("one heavy check hid an unused worker slot: %+v", status)
		}
		for _, task := range tasks {
			task.wrap(func() {})()
		}
	})
}

func TestCheckDispatchHealthCountsAbnormalWrappers(t *testing.T) {
	for _, panics := range []bool{false, true} {
		name := "goexit"
		if panics {
			name = "panic"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m := newCheckDispatchMonitor()
				tasks := m.begin(3, 3)
				var wg sync.WaitGroup
				var recovered atomic.Int32
				for _, task := range tasks {
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer func() {
							if recover() != nil {
								recovered.Add(1)
							}
						}()
						task.wrap(func() {
							task.admit()
							if panics {
								panic("controlled dispatch failure")
							}
							runtime.Goexit()
						})()
					}()
				}
				wg.Wait()
				wantRecovered := int32(0)
				if panics {
					wantRecovered = 3
				}
				if recovered.Load() != wantRecovered {
					t.Fatalf("wrapper changed panic propagation: got %d want %d", recovered.Load(), wantRecovered)
				}
				status := checkDispatchStatus(t, m)
				if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 3 || status.Reason != "dropped_work" {
					t.Fatalf("abnormal wrappers lost their evidence: %+v", status)
				}
				time.Sleep(time.Minute)
				status = checkDispatchStatus(t, m)
				if status.Status != "ok" || status.DroppedTotal != 3 {
					t.Fatalf("wrapper failure window did not recover: %+v", status)
				}
			})
		})
	}
}

func TestCheckDispatchHealthDeadlineBeforeExecutionCountsLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckDispatchMonitor()
		for _, deadline := range []bool{false, true} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			tasks := m.begin(3, 2)
			if deadline {
				<-ctx.Done()
			} else {
				cancel()
			}
			for _, task := range tasks {
				task.wrap(func() { task.withdraw(ctx) })()
			}
			cancel()
			wantLoss := uint64(0)
			if deadline {
				wantLoss = 3
			}
			status := checkDispatchStatus(t, m)
			if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != wantLoss {
				t.Fatalf("withdrawn pending work accounting: %+v", status)
			}
		}
	})
}

func TestCheckDispatchHealthLateDeadlineDoesNotUndoCompletedWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckDispatchMonitor()
		task := m.begin(1, 1)[0]
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		filtered := false
		task.wrap(func() {
			task.admit()
			// A throttle refusal completes the scheduling decision without
			// executing a check. Later cancellation cannot undo that decision.
			filtered = true
			<-ctx.Done()
		})()
		status := checkDispatchStatus(t, m)
		if !filtered || status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 {
			t.Fatalf("late parent deadline reclassified completed scheduling: %+v filtered=%v", status, filtered)
		}
	})
}

func TestCheckDispatchHealthTracksBothRunners(t *testing.T) {
	for _, host := range []bool{false, true} {
		name, parallel := "account", 4
		if host {
			name, parallel = "host", 5
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				previous, previousTimeout := checkDispatches, timeoutForFunc
				checkDispatches = newCheckDispatchMonitor()
				timeoutForFunc = func(string) time.Duration { return 15 * time.Minute }
				defer func() { checkDispatches, timeoutForFunc = previous, previousTimeout }()
				release := make(chan struct{})
				releaseChecks := sync.OnceFunc(func() { close(release) })
				defer releaseChecks()
				var started atomic.Int32
				var checks []namedCheck
				for range 12 {
					checks = append(checks, namedCheck{name: "dispatch_health_control", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
						started.Add(1)
						<-release
						return []alert.Finding{{Check: "dispatch_health_result", Severity: alert.Warning}}
					}})
				}
				done := make(chan []alert.Finding, 1)
				go func() {
					if host {
						findings, _ := runParallel(&config.Config{}, nil, checks, "test", true)
						done <- findings
					} else {
						done <- runAccountChecksBounded(context.Background(), &config.Config{}, nil, checks, parallel)
					}
				}()
				synctest.Wait()
				time.Sleep(6 * time.Minute)
				status := checkDispatchStatus(t, checkDispatches)
				if status.Depth != 12-parallel || status.InFlight != parallel || started.Load() != int32(parallel) || status.Status != "ok" {
					t.Fatalf("runner pending/active accounting: %+v started=%d", status, started.Load())
				}
				releaseChecks()
				findings := <-done
				if len(findings) != 12 || started.Load() != 12 {
					t.Fatalf("runner results changed: findings=%d started=%d", len(findings), started.Load())
				}
				for _, finding := range findings {
					if finding.Check != "dispatch_health_result" {
						t.Fatalf("runner returned unexpected finding: %s", finding.Check)
					}
				}
				synctest.Wait()
				status = checkDispatchStatus(t, checkDispatches)
				if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Status != "ok" {
					t.Fatalf("runner did not finish its batch: %+v", status)
				}
			})
		})
	}
}

func TestCheckDispatchHealthConcurrentBatchesCancelQueuedDemand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := checkDispatches
		checkDispatches = newCheckDispatchMonitor()
		defer func() { checkDispatches = previous }()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		release := make(chan struct{})
		releaseChecks := sync.OnceFunc(func() { close(release) })
		defer releaseChecks()
		var started atomic.Int32
		checks := make([]namedCheck, 8)
		for i := range checks {
			checks[i] = namedCheck{name: "dispatch_health_control", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
				started.Add(1)
				<-release
				return nil
			}}
		}
		done := make(chan []alert.Finding, 4)
		for range 4 {
			go func() { done <- runAccountChecksBounded(ctx, &config.Config{}, nil, checks, 2) }()
		}
		synctest.Wait()
		status := checkDispatchStatus(t, checkDispatches)
		if status.Depth != 24 || status.InFlight != 8 || started.Load() != 8 || status.DroppedTotal != 0 {
			t.Fatalf("concurrent batch registration: %+v started=%d", status, started.Load())
		}
		cancel()
		for range 4 {
			if findings := <-done; len(findings) != 0 {
				t.Fatalf("explicit cancellation produced findings: %d", len(findings))
			}
		}
		synctest.Wait()
		status = checkDispatchStatus(t, checkDispatches)
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || started.Load() != 8 {
			t.Fatalf("canceled demand was lost or launched: %+v started=%d", status, started.Load())
		}
		releaseChecks()
		synctest.Wait()
		status = checkDispatchStatus(t, checkDispatches)
		if status.Status != "ok" || status.DroppedTotal != 0 || status.Depth != 0 || status.InFlight != 0 {
			t.Fatalf("late check completion changed dispatch health: %+v", status)
		}
	})
}

func TestCheckDispatchHealthRunnerDeadlinePartitionsLoss(t *testing.T) {
	for _, host := range []bool{false, true} {
		name, parallel := "account", 4
		if host {
			name, parallel = "host", 5
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				previousDispatch, previousExecutions := checkDispatches, checkExecutions
				checkDispatches, checkExecutions = newCheckDispatchMonitor(), newCheckExecutionMonitor()
				defer func() { checkDispatches, checkExecutions = previousDispatch, previousExecutions }()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				release := make(chan struct{})
				releaseChecks := sync.OnceFunc(func() { close(release) })
				defer releaseChecks()
				var started atomic.Int32
				checks := make([]namedCheck, 12)
				for i := range checks {
					checks[i] = namedCheck{name: "dispatch_health_control", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
						started.Add(1)
						<-release
						return nil
					}}
				}
				var findings []alert.Finding
				if host {
					findings, _ = runParallelWithContext(ctx, &config.Config{}, nil, checks, "test", true)
				} else {
					findings = runAccountChecksBounded(ctx, &config.Config{}, nil, checks, parallel)
				}
				synctest.Wait()
				dispatch := checkDispatchStatus(t, checkDispatches)
				executions := CheckExecutionQueueStatus(time.Now())
				if len(findings) != 0 || started.Load() != int32(parallel) || dispatch.Depth != 0 || dispatch.InFlight != 0 || dispatch.DroppedTotal != uint64(12-parallel) || executions.InFlight != parallel || executions.DroppedTotal != uint64(parallel) {
					t.Fatalf("deadline accounting: dispatch=%+v executions=%+v findings=%d started=%d", dispatch, executions, len(findings), started.Load())
				}
				releaseChecks()
				synctest.Wait()
				dispatch = checkDispatchStatus(t, checkDispatches)
				executions = CheckExecutionQueueStatus(time.Now())
				if dispatch.DroppedTotal != uint64(12-parallel) || executions.InFlight != 0 || executions.DroppedTotal != uint64(parallel) {
					t.Fatalf("late function exit changed loss accounting: dispatch=%+v executions=%+v", dispatch, executions)
				}
			})
		})
	}
}

func TestCheckDispatchHealthProgressDoesNotHideOverduePeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckDispatchMonitor()
		held := m.begin(1, 1)[0]
		held.admit()
		for range 3 {
			peer := m.begin(1, 1)[0]
			peer.admit()
			time.Sleep(30 * time.Second)
			peer.wrap(func() {})()
		}
		status := checkDispatchStatus(t, m)
		if status.Depth != 0 || status.InFlight != 1 || status.ProcessingSeconds != 90 || status.Reason != "processing_lag" {
			t.Fatalf("other batches reset the overdue wrapper: %+v", status)
		}
		held.wrap(func() {})()
		status = checkDispatchStatus(t, m)
		if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Status != "ok" {
			t.Fatalf("overdue wrapper did not settle: %+v", status)
		}
	})
}

func TestCheckDispatchHealthWithoutADeadlineIsNotLate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newCheckDispatchMonitor()
		tasks := m.begin(1, 1)
		tasks[0].admit()
		tasks[0].executing(context.Background())
		time.Sleep(time.Hour)
		if status := checkDispatchStatus(t, m); status.Status != "ok" || status.InFlight != 1 {
			t.Fatalf("a check with no deadline was reported overdue: %+v", status)
		}
		tasks[0].wrap(func() {})()
	})
}
