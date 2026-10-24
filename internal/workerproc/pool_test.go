package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func testPool(t *testing.T, size int, timeout time.Duration, launch func(slot int) Launcher) *Pool {
	t.Helper()
	p, err := NewPool(PoolConfig{Size: size, Config: func(slot int) Config {
		return Config{Name: "pool worker", Launch: launch(slot), Timeout: timeout, Limits: Limits{MaxFrameBytes: 1 << 20, MaxFDs: 4}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop() })
	return p
}

func sleepFrame(ms int) Frame {
	payload, _ := json.Marshal(ms)
	return Frame{Op: "sleep", Payload: payload}
}

func TestPoolRunsSlotsInParallel(t *testing.T) {
	p := testPool(t, 3, 5*time.Second, func(int) Launcher { return pairLauncher(t, sleepHandler) })
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for slot := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[slot] = p.Call(context.Background(), slot, sleepFrame(200), nil, okCheck)
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatalf("three slots took %s; they did not run in parallel", took)
	}
	for slot, st := range p.Stats() {
		if errs[slot] != nil || st.Spawns != 1 {
			t.Fatalf("slot %d: err %v stats %+v", slot, errs[slot], st)
		}
	}
	if p.Size() != 3 {
		t.Fatalf("Size = %d", p.Size())
	}
}

func TestPoolSlotFailureIsolated(t *testing.T) {
	p := testPool(t, 3, 100*time.Millisecond, func(int) Launcher { return pairLauncher(t, sleepHandler) })
	if _, _, err := p.Call(context.Background(), 1, sleepFrame(1000), nil, okCheck); !errors.Is(err, ErrTimeout) {
		t.Fatalf("slot 1 = %v, want a timeout", err)
	}
	for _, slot := range []int{0, 2} {
		if _, _, err := p.Call(context.Background(), slot, sleepFrame(0), nil, okCheck); err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
	}
	st := p.Stats()
	if st[0].ConsecutiveFailures != 0 || st[2].ConsecutiveFailures != 0 || st[1].ConsecutiveFailures != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestPoolQueueStatusesAggregate(t *testing.T) {
	p := testPool(t, 2, 100*time.Millisecond, func(int) Launcher { return pairLauncher(t, sleepHandler) })
	for slot := range 2 {
		if _, _, err := p.Call(context.Background(), slot, sleepFrame(0), nil, okCheck); err != nil {
			t.Fatal(err)
		}
	}
	q, ok := p.QueueStatuses(time.Now())["requests"]
	if !ok || q.InFlight != 0 || q.Capacity != 2 || q.DroppedTotal != 0 {
		t.Fatalf("requests row = %+v (found %v)", q, ok)
	}
	_, _, _ = p.Call(context.Background(), 0, sleepFrame(1000), nil, okCheck)
	if q := p.QueueStatuses(time.Now())["requests"]; q.DroppedTotal != 1 {
		t.Fatalf("after a timeout: %+v", q)
	}
}

func TestPoolStopRefusesCalls(t *testing.T) {
	p := testPool(t, 2, time.Second, func(int) Launcher { return pairLauncher(t, sleepHandler) })
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	for slot := range 2 {
		if _, _, err := p.Call(context.Background(), slot, sleepFrame(0), nil, okCheck); !errors.Is(err, ErrStopped) {
			t.Fatalf("slot %d after Stop: %v", slot, err)
		}
	}
}
