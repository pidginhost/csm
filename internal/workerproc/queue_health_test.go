package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

// fakeTransport stands in for a worker connection. A nil onSend discards the
// request; a nil onClose succeeds.
type fakeTransport struct {
	onSend    func([]byte, []*os.File) error
	onReceive func() (Frame, []*os.File, error)
	onClose   func() error
}

func (f *fakeTransport) send(body []byte, fds []*os.File) error {
	if f.onSend == nil {
		return nil
	}
	return f.onSend(body, fds)
}

func (f *fakeTransport) receive() (Frame, []*os.File, error) { return f.onReceive() }

func (f *fakeTransport) close() error {
	if f.onClose == nil {
		return nil
	}
	return f.onClose()
}

type stubProcess struct{ done chan struct{} }

func (stubProcess) Conn() *net.UnixConn     { return nil }
func (stubProcess) Kill() error             { return nil }
func (p stubProcess) Done() <-chan struct{} { return p.done }
func (stubProcess) PID() int                { return 0 }

// exitedProcess is a Process that has already exited and been reaped.
func exitedProcess() Process {
	done := make(chan struct{})
	close(done)
	return stubProcess{done: done}
}

func isCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func workerQueue(t *testing.T, s *Supervisor, now time.Time) queuehealth.Status {
	t.Helper()
	source, ok := any(s).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("worker requests have no queue health source")
	}
	done := make(chan map[string]queuehealth.Status, 1)
	go func() { done <- source.QueueStatuses(now) }()
	select {
	case rows := <-done:
		status, exists := rows["requests"]
		if !exists || len(rows) != 1 {
			t.Fatalf("missing or unexpected worker queue rows: %+v", rows)
		}
		return status
	case <-time.After(time.Second):
		t.Fatal("health snapshot waited on the worker or its admission lock")
		return queuehealth.Status{}
	}
}

func TestWorkerQueueWaitingCallersCancelWithoutLoss(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), 2*time.Second)
	s.mu.Lock()
	unlock := sync.OnceFunc(s.mu.Unlock)
	defer unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 3)
	for range 3 {
		go func() {
			_, _, err := s.Call(ctx, Frame{Op: "work"}, nil, okCheck)
			results <- err
		}()
	}
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now().Add(61*time.Second))
		if q.Depth == 3 {
			if q.InFlight != 0 || q.Reason != "backlog_lag" || q.DroppedTotal != 0 || !q.CapacityUnavailable {
				t.Fatalf("blocked admission: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("callers did not publish before the lock: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	unlock()
	for range 3 {
		select {
		case err := <-results:
			if !isCanceled(err) {
				t.Fatalf("waiting cancellation became %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("waiting caller did not return after lock release")
		}
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" || s.Stats().Spawns != 0 {
		t.Fatalf("canceled callers retained work or spawned: %+v spawns=%d", q, s.Stats().Spawns)
	}
}

func installHeldReply(t *testing.T, s *Supervisor) (<-chan struct{}, func()) {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.child = &child{proc: exitedProcess(), conn: &fakeTransport{onReceive: func() (Frame, []*os.File, error) {
		once.Do(func() { close(entered) })
		<-release
		return Frame{Payload: json.RawMessage(`{}`)}, nil, nil
	}}}
	return entered, sync.OnceFunc(func() { close(release) })
}

func TestWorkerQueueRetainsRPCBeyondCallerCancellation(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), 2*time.Second)
	entered, release := installHeldReply(t, s)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := s.Call(ctx, Frame{Op: "work"}, nil, okCheck)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("RPC did not start")
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 1 || q.Status != "ok" || q.DroppedTotal != 0 {
		t.Fatalf("live RPC: %+v", q)
	}
	cancel()
	select {
	case err := <-done:
		if !isCanceled(err) {
			t.Fatalf("canceled RPC became %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller did not return after cancellation")
	}
	if q := workerQueue(t, s, time.Now().Add(3*time.Second)); q.Depth != 0 || q.InFlight != 1 || q.Reason != "processing_lag" || q.DroppedTotal != 0 {
		t.Fatalf("caller cancellation hid a socket operation: %+v", q)
	}
	release()
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now())
		if q.InFlight == 0 {
			if q.Depth != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
				t.Fatalf("late RPC completion: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("finished RPC kept ownership: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkerQueueTimeoutLossSurvivesLateReply(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), 20*time.Millisecond)
	_, release := installHeldReply(t, s)
	defer release()
	if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); !errors.Is(err, ErrTimeout) {
		t.Fatalf("timeout became %v", err)
	}
	if q := workerQueue(t, s, time.Now()); q.InFlight != 1 || q.Depth != 0 || q.DroppedTotal != 1 || q.Reason != "processing_lag" {
		t.Fatalf("timed-out RPC ownership: %+v", q)
	}
	release()
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now().Add(time.Minute))
		if q.InFlight == 0 {
			if q.Depth != 0 || q.DroppedTotal != 1 || q.RecentDrops != 0 || q.Status != "ok" {
				t.Fatalf("timeout recovery: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("late reply did not release ownership: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkerQueueKnownFailureDuringCleanup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	s, err := New(Config{
		Name:    "test worker",
		Launch:  helperLauncher(t, "hang"),
		Timeout: 100 * time.Millisecond,
		Limits:  Limits{MaxFrameBytes: 1 << 20},
		Log:     func(string, ...any) { close(entered); <-release },
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout did not reach cleanup")
	}
	if q := workerQueue(t, s, time.Now().Add(61*time.Second)); q.Depth != 0 || q.InFlight != 1 || q.DroppedTotal != 1 || q.Reason != "processing_lag" {
		t.Fatalf("cleanup hid a known timeout: %+v", q)
	}
	finish()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("cleanup changed timeout: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish")
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 1 {
		t.Fatalf("cleanup released the wrong work: %+v", q)
	}
}

func TestWorkerQueueHonorsLongConfiguredRPC(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), 5*time.Minute)
	entered, release := installHeldReply(t, s)
	defer func() { release(); _ = s.Stop() }()
	done := make(chan error, 1)
	go func() {
		_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("RPC did not start")
	}
	if q := workerQueue(t, s, time.Now().Add(61*time.Second)); q.InFlight != 1 || q.Depth != 0 || q.Status != "ok" || q.DroppedTotal != 0 {
		t.Fatalf("healthy RPC borrowed the setup budget: %+v", q)
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("valid reply changed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("valid reply was not consumed")
	}
	waitWorkerQueueIdle(t, s, 0)
}

func waitWorkerQueueIdle(t *testing.T, s *Supervisor, losses uint64) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now())
		if q.InFlight == 0 && q.Depth == 0 {
			if q.DroppedTotal != losses {
				t.Fatalf("settled request losses: %+v want=%d", q, losses)
			}
			return
		}
		if time.Now().After(until) {
			t.Fatalf("request did not release ownership: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
}

type heldWorkerContext struct {
	context.Context
	entered chan struct{}
	release <-chan struct{}
}

func (c heldWorkerContext) Done() <-chan struct{} {
	close(c.entered)
	<-c.release
	return c.Context.Done()
}

func TestWorkerQueueBufferedReplyHasIndependentBudget(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), 5*time.Minute)
	_, releaseReply := installHeldReply(t, s)
	releaseReply()
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer func() { finish(); _ = s.Stop() }()
	done := make(chan error, 1)
	go func() {
		_, _, err := s.Call(heldWorkerContext{context.Background(), entered, release}, Frame{Op: "work"}, nil, okCheck)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reply consumer did not reach context select")
	}
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now().Add(61*time.Second))
		if q.Reason == "processing_lag" {
			if q.InFlight != 1 || q.Depth != 0 || q.DroppedTotal != 0 {
				t.Fatalf("buffered reply ownership: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("buffered reply borrowed RPC budget: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
	finish()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("buffered reply changed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("buffered reply was not consumed")
	}
	waitWorkerQueueIdle(t, s, 0)
}

func TestWorkerQueueRPCExitCountsOnce(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), 20*time.Millisecond)
	s.child = &child{proc: exitedProcess(), conn: &fakeTransport{onReceive: func() (Frame, []*os.File, error) {
		runtime.Goexit()
		return Frame{}, nil, io.EOF
	}}}
	if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); !errors.Is(err, ErrTimeout) {
		t.Fatalf("missing RPC reply changed status: %v", err)
	}
	waitWorkerQueueIdle(t, s, 1)
}
