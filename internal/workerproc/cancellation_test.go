package workerproc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCallLaunchCancellationDoesNotCountAsFailure(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		for _, trial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/trial=%t", cause, trial), func(t *testing.T) {
				attempts := 0
				s := newTestSupervisor(t, func(context.Context) (Process, error) {
					attempts++
					return nil, fmt.Errorf("launch: %w", cause)
				}, time.Second)
				clock := time.Now()
				s.now = func() time.Time { return clock }
				failures := 0
				if trial {
					failures = ConsecutiveFailureLimit
					s.consecutive = failures
					s.openedAt = clock.Add(-BreakerCooldown)
				}

				_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
				if !errors.Is(err, cause) || errors.Is(err, ErrSpawn) {
					t.Errorf("launch cancellation = %v, want %v without ErrSpawn", err, cause)
				}
				if st := s.Stats(); st.ConsecutiveFailures != failures || st.Spawns != 0 {
					t.Errorf("launch cancellation changed worker accounting: %+v", st)
				}
				if trial {
					if st := s.Stats(); !st.BreakerOpen || !st.BreakerOpenedAt.Equal(clock) {
						t.Errorf("canceled trial did not rearm cooldown: %+v", st)
					}
					_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
					if !errors.Is(err, ErrBreakerOpen) || attempts != 1 {
						t.Fatalf("canceled trial allowed another launch: attempts=%d err=%v", attempts, err)
					}
					waitWorkerQueueIdle(t, s, 1) // Only the breaker refusal is lost work.
				} else {
					waitWorkerQueueIdle(t, s, 0)
				}
			})
		}
	}
}
