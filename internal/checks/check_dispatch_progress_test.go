package checks

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestCheckDispatchProgressRealRunners(t *testing.T) {
	for _, host := range []bool{false, true} {
		t.Run(map[bool]string{false: "account", true: "host"}[host], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				oldTimeout := timeoutForFunc
				timeoutForFunc = func(string) time.Duration { return 15 * time.Minute }
				defer func() { timeoutForFunc = oldTimeout }()
				ctx, progress := WithCheckDispatchProgress(context.Background())
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				release := make(chan struct{})
				list := []namedCheck{{name: "progress_test", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
					<-release
					return nil
				}}}
				done := make(chan struct{})
				go func() {
					defer close(done)
					if host {
						runParallelWithContext(ctx, &config.Config{}, nil, list, "test", true)
					} else {
						runAccountChecksBounded(ctx, &config.Config{}, nil, list, 4)
					}
				}()
				synctest.Wait()
				time.Sleep(6 * time.Minute)
				got := progress.Snapshot(time.Now())
				if !got.Active || got.Overdue || got.LastProgress.IsZero() {
					t.Errorf("healthy heavy check: %+v", got)
				}
				cancel()
				<-done
				synctest.Wait()
				got = progress.Snapshot(time.Now())
				if got.Active || got.Overdue || !got.LastProgress.Equal(time.Now()) {
					t.Errorf("caller withdrawal: %+v", got)
				}
				_, next := WithCheckDispatchProgress(context.Background())
				before := next.Snapshot(time.Now())
				time.Sleep(time.Second)
				close(release)
				synctest.Wait()
				after := next.Snapshot(time.Now())
				if after != before {
					t.Errorf("late old execution changed next job: before=%+v after=%+v", before, after)
				}
			})
		})
	}
}

func TestCheckDispatchProgressKeepsOwnedDeadlines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, progress := WithCheckDispatchProgress(context.Background())
		_, unrelated := WithCheckDispatchProgress(context.Background())
		tasks := checkDispatches.begin(2, 2)
		checkDispatches.observe(ctx, tasks)
		for _, task := range tasks {
			task.admit()
		}
		heavy, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		tasks[0].executing(heavy)
		time.Sleep(61 * time.Second)
		tasks[0].executing(heavy)
		got := progress.Snapshot(time.Now())
		if !got.Active || !got.Overdue || !got.LastProgress.Equal(time.Now()) {
			t.Errorf("peer progress hid setup deadline: %+v", got)
		}
		if got := unrelated.Snapshot(time.Now()); got.Active || got.Overdue {
			t.Errorf("unrelated job inherited checks: %+v", got)
		}
		for _, task := range tasks {
			task.wrap(func() {})()
		}
		if got := progress.Snapshot(time.Now()); got.Active || got.Overdue || !got.LastProgress.Equal(time.Now()) {
			t.Errorf("batch completion: %+v", got)
		}
	})
}
