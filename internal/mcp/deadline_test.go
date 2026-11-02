package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type stalledDispatcher struct {
	Dispatcher
	release chan struct{}
	calls   atomic.Int32
}

type panickingDispatcher struct{ Dispatcher }

func (d panickingDispatcher) Dispatch(context.Context, string, url.Values, string) (int, string, []byte, error) {
	panic("test handler panic")
}

func TestCallPanicDoesNotEscapeWorker(t *testing.T) {
	s := newTestServer(t, panickingDispatcher{newFake()})
	result, err := s.runCall(context.Background(), toolsCallParams{Name: "csm_status"}, "agent", "203.0.113.9:4000")
	if err != nil || !result.IsError {
		t.Fatalf("panicking call: %+v, %v", result, err)
	}
	if got := len(s.calls); got != 0 {
		t.Errorf("panicking worker retained %d slots", got)
	}
}

func (d *stalledDispatcher) Dispatch(_ context.Context, _ string, _ url.Values, _ string) (int, string, []byte, error) {
	d.calls.Add(1)
	<-d.release
	return http.StatusOK, "application/json", []byte(`{}`), nil
}

func TestBatchDeadlineBoundsUncooperativeHandler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &stalledDispatcher{Dispatcher: newFake(), release: make(chan struct{})}
		s := newTestServer(t, d)
		defer func() {
			close(d.release)
			synctest.Wait()
			if got := len(s.calls); got != 0 {
				t.Errorf("completed worker retained %d slots", got)
			}
			if got := d.calls.Load(); got != 1 {
				t.Errorf("started %d reads; expired batch and composite must stop after the first", got)
			}
		}()
		body, err := json.Marshal([]any{
			rpc(1, "tools/call", map[string]any{"name": "csm_overview"}),
			rpc(2, "tools/call", map[string]any{"name": "csm_status"}),
			rpc(3, "tools/call", map[string]any{"name": "csm_health"}),
		})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			s.ServeMCP(w, r, "agent")
			close(done)
		}()
		synctest.Wait()
		time.Sleep(requestTimeout)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("request still waits on a handler after the deadline")
		}
		var responses []struct {
			ID     int        `json:"id"`
			Result toolResult `json:"result"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &responses); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || len(responses) != 3 {
			t.Fatalf("batch: %d %s", w.Code, w.Body)
		}
		for i, response := range responses {
			if response.ID != i+1 || !response.Result.IsError {
				t.Errorf("expired call %d: %+v", i+1, response)
			}
		}
		// Returning to the client must not let a still-running read escape
		// the concurrency cap. Only the worker may release its slot.
		if got := len(s.calls); got != 1 {
			t.Errorf("blocked worker occupies %d slots, want 1", got)
		}
	})
}

func TestExpiredCallNeverDispatches(t *testing.T) {
	s := newTestServer(t, newFake())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 32 {
		result, err := s.runCall(ctx, toolsCallParams{Name: "csm_status"}, "agent", "203.0.113.9:4000")
		if err != nil || !result.IsError {
			t.Fatalf("expired call: %+v, %v", result, err)
		}
	}
	if got := len(s.dispatcher.(*fakeDispatcher).calls); got != 0 {
		t.Errorf("dispatched %d expired calls", got)
	}
	if got := len(s.calls); got != 0 {
		t.Errorf("expired calls retained %d slots", got)
	}
}

func TestDeadlineReleasesCooperativeCallSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFake()
		fake.block = make(chan struct{})
		s := newTestServer(t, fake)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result, err := s.runCall(ctx, toolsCallParams{Name: "csm_status"}, "agent", "203.0.113.9:4000")
		if err != nil || !result.IsError {
			t.Fatalf("expired call: %+v, %v", result, err)
		}
		synctest.Wait()
		if got := len(s.calls); got != 0 {
			t.Errorf("cancelled worker retained %d slots", got)
		}
		close(fake.block)
		result, err = s.runCall(context.Background(), toolsCallParams{Name: "csm_status"}, "agent", "203.0.113.9:4000")
		if err != nil || result.IsError {
			t.Fatalf("next call: %+v, %v", result, err)
		}
	})
}
