package webui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/config"
)

type failedEventFlush struct {
	*deadlineRecorder
	flushCalls int
	failAt     int
}

func (r *failedEventFlush) FlushError() error {
	r.Flush()
	r.flushCalls++
	if r.flushCalls == r.failAt {
		return errors.New("client disconnected during flush")
	}
	return nil
}

func TestAPIEventsStopsAfterFailedFlush(t *testing.T) {
	for _, stage := range []string{"initial", "event", "keepalive"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bus := broadcast.NewBus(2)
				defer bus.Close()
				bus.SetMaxSubscribers(1)
				s := &Server{cfg: &config.Config{}}
				s.SetFindingBus(bus)
				ctx, cancel := context.WithCancel(context.Background())
				req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
				failAt := 2
				if stage == "initial" {
					failAt = 1
				}
				rec := &failedEventFlush{deadlineRecorder: newDeadlineRecorder(), failAt: failAt}
				done := make(chan struct{})
				go func() { defer close(done); s.apiEvents(rec, req) }()
				defer func() { cancel(); <-done }()
				synctest.Wait()
				switch stage {
				case "event":
					bus.Publish(alert.Finding{Check: "test"})
				case "keepalive":
					time.Sleep(25 * time.Second)
				}
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("event stream ignored a failed client flush")
				}
				if rec.flushCalls != failAt {
					t.Fatalf("flush calls = %d, want %d", rec.flushCalls, failAt)
				}
				if sub, ok := bus.TrySubscribe(); !ok {
					t.Fatal("failed stream retained its subscriber slot")
				} else {
					bus.Unsubscribe(sub)
				}
			})
		})
	}
}
