package reporting

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestSpoolCursorPreservesTargetOrderAcrossEviction(t *testing.T) {
	for _, outcome := range []string{"accepted", "refused", "unavailable"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newSpool(t, 4)
				enqueue := func(target, body string) int {
					dropped, err := s.Enqueue(target, []byte(body))
					if err != nil {
						t.Fatal(err)
					}
					return dropped
				}
				enqueue("a", "a1")
				enqueue("b", "b1")
				enqueue("a", "a2")
				enqueue("b", "b2")
				release, done := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer func() { unblock(); <-done }()
				var sent []string
				var delivered int
				var drainErr error
				outage := errors.New("collector unavailable")
				go func() {
					defer close(done)
					delivered, drainErr = s.Drain(func(_ string, body []byte) error {
						sent = append(sent, string(body))
						if string(body) == "a1" {
							<-release
							switch outcome {
							case "refused":
								return ErrReportRefused
							case "unavailable":
								return outage
							}
						}
						return nil
					})
				}()
				synctest.Wait()
				if enqueue("a", "a3") != 1 || enqueue("b", "b3") != 1 {
					t.Fatal("expected eviction of a1 in flight and b1 waiting")
				}
				if got := s.QueueStatuses(time.Now())["spool"]; got.DroppedTotal != 1 || got.InFlight != 1 || got.Depth != 4 {
					t.Fatalf("active eviction settled too early: %+v", got)
				}
				unblock()
				<-done
				wantSent, wantN, wantDrops, wantDepth := []string{"a1", "a2", "b2", "a3", "b3"}, 5, uint64(1), 0
				var wantErr error
				switch outcome {
				case "refused":
					wantN, wantDrops, wantErr = 4, 2, ErrReportRefused
				case "unavailable":
					wantSent, wantN, wantDrops, wantDepth, wantErr = []string{"a1", "b2", "b3"}, 2, 2, 2, outage
				}
				if !slices.Equal(sent, wantSent) || delivered != wantN || !errors.Is(drainErr, wantErr) {
					t.Fatalf("sent=%v delivered=%d err=%v, want %v, %d, %v", sent, delivered, drainErr, wantSent, wantN, wantErr)
				}
				if got := s.QueueStatuses(time.Now())["spool"]; got.DroppedTotal != wantDrops || got.Depth != wantDepth || got.InFlight != 0 {
					t.Fatalf("evicted outcome miscounted: %+v", got)
				}
				if outcome == "unavailable" {
					sent = nil
					n, err := s.Drain(func(_ string, body []byte) error { sent = append(sent, string(body)); return nil })
					if n != 2 || err != nil || !slices.Equal(sent, []string{"a2", "a3"}) {
						t.Fatalf("paused target lost FIFO: sent=%v delivered=%d err=%v", sent, n, err)
					}
				}
			})
		})
	}
}
