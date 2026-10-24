package workerproc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// For mail every request is hostile input and none can be skipped: requests
// that kill their worker must not get the next, unrelated request refused.
func TestBreakOnSpawnOnlyIgnoresWorkerFailures(t *testing.T) {
	s, err := New(Config{Name: "test worker", Launch: helperLauncher(t, "exit"), Timeout: 5 * time.Second,
		Limits: Limits{MaxFrameBytes: 1 << 20}, BreakOnSpawnOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	const calls = ConsecutiveFailureLimit + 2
	for i := range calls {
		if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); FailureReason(err) != ReasonCrash {
			t.Fatalf("call %d: %v (%q), want a crash", i, err, FailureReason(err))
		}
	}
	if st := s.Stats(); st.BreakerOpen || st.Spawns != calls || st.Kills[ReasonCrash] != calls {
		t.Fatalf("stats %+v, want every call on a fresh worker and every kill counted", st)
	}
}

// A worker that cannot start is the host's condition, not the input's, and
// still stops the spawn storm.
func TestBreakOnSpawnOnlyStillBreaksOnFailedStarts(t *testing.T) {
	launches := 0
	s, err := New(Config{Name: "test worker", Timeout: time.Second, Limits: Limits{MaxFrameBytes: 1 << 20}, BreakOnSpawnOnly: true,
		Launch: func(context.Context) (Process, error) { launches++; return nil, errors.New("systemd-run missing") }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	for range ConsecutiveFailureLimit {
		if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); !errors.Is(err, ErrSpawn) {
			t.Fatalf("err = %v, want ErrSpawn", err)
		}
	}
	if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); !errors.Is(err, ErrBreakerOpen) || launches != ConsecutiveFailureLimit {
		t.Fatalf("err = %v after %d launches, want the breaker open after %d", err, launches, ConsecutiveFailureLimit)
	}
}

// A successful start ends the run of failed starts even when hostile input
// then crashes that worker, including the first trial after a cooldown.
func TestBreakOnSpawnOnlySuccessfulStartResetsFailures(t *testing.T) {
	for _, failedStarts := range []int{ConsecutiveFailureLimit - 1, ConsecutiveFailureLimit} {
		t.Run(fmt.Sprint(failedStarts), func(t *testing.T) {
			failStart := true
			launch := helperLauncher(t, "exit")
			s, err := New(Config{Name: "test worker", Timeout: 5 * time.Second,
				Limits: Limits{MaxFrameBytes: 1 << 20}, BreakOnSpawnOnly: true,
				Launch: func(ctx context.Context) (Process, error) {
					if failStart {
						return nil, errors.New("unit start failed")
					}
					return launch(ctx)
				}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Stop() })
			now := time.Now()
			s.now = func() time.Time { return now }
			for range failedStarts {
				if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); !errors.Is(err, ErrSpawn) {
					t.Fatalf("failed start: %v", err)
				}
			}
			now = now.Add(BreakerCooldown)
			failStart = false
			if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); FailureReason(err) != ReasonCrash {
				t.Fatalf("started worker: %v, want crash", err)
			}
			if st := s.Stats(); st.ConsecutiveFailures != 0 || st.BreakerOpen || st.Kills[ReasonCrash] != 1 || st.Kills[ReasonSpawn] != uint64(failedStarts) {
				t.Fatalf("successful start retained failures or lost kill counts: %+v", st)
			}
			failStart = true
			if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); !errors.Is(err, ErrSpawn) {
				t.Fatalf("next start: %v", err)
			}
			if st := s.Stats(); st.ConsecutiveFailures != 1 || st.BreakerOpen {
				t.Fatalf("separate start failures accumulated: %+v", st)
			}
		})
	}
}
