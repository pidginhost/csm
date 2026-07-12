//go:build linux && bpf

package bpf

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

type transientRingReader struct {
	mu     sync.Mutex
	reads  int
	closed chan struct{}
	once   sync.Once
}

func (f *transientRingReader) Read() (ringbuf.Record, error) {
	f.mu.Lock()
	f.reads++
	read := f.reads
	f.mu.Unlock()
	switch read {
	case 1:
		return ringbuf.Record{}, errors.New("temporary epoll failure")
	case 2:
		return ringbuf.Record{RawSample: []byte{42}}, nil
	default:
		<-f.closed
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
}

func (f *transientRingReader) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func TestReaderRecoversAfterTransientReadError(t *testing.T) {
	f := &transientRingReader{closed: make(chan struct{})}
	r := &Reader[int]{
		rb:     f,
		decode: func(data []byte) (int, error) { return int(data[0]), nil },
		out:    make(chan int, 1),
		errs:   make(chan error, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	select {
	case err := <-r.Errors():
		if err == nil || err.Error() != "temporary epoll failure" {
			t.Fatalf("reader error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("transient read error was not reported")
	}
	select {
	case event := <-r.Events():
		if event != 42 {
			t.Fatalf("event = %d, want 42", event)
		}
	case <-time.After(time.Second):
		t.Fatal("reader stopped instead of recovering")
	}
}

// fakeRingReader stands in for *ringbuf.Reader so the shutdown path can be
// tested without a privileged BPF map. Read blocks until Close unblocks it.
type fakeRingReader struct {
	closes atomic.Int64
	closed chan struct{}
	once   sync.Once
}

func (f *fakeRingReader) Read() (ringbuf.Record, error) {
	<-f.closed
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (f *fakeRingReader) Close() error {
	f.closes.Add(1)
	f.once.Do(func() { close(f.closed) })
	return nil
}

// The ctx watcher and an external Close() both drive shutdown; the underlying
// reader must be closed exactly once (a double close races cilium's teardown),
// Run must return, and the events channel must be closed.
func TestReaderCloseIsIdempotent(t *testing.T) {
	f := &fakeRingReader{closed: make(chan struct{})}
	r := &Reader[int]{
		rb:     f,
		decode: func([]byte) (int, error) { return 0, nil },
		out:    make(chan int, 1),
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { r.Run(ctx); close(runDone) }()

	// Race several shutdown triggers against each other.
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.Close() }()
	}
	cancel()
	wg.Wait()

	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}

	if _, ok := <-r.out; ok {
		t.Error("events channel should be closed when Run returns")
	}
	if got := f.closes.Load(); got != 1 {
		t.Fatalf("underlying reader Close called %d times, want exactly 1", got)
	}
}

// An external Close() with no ctx cancellation must still return Run and must
// not leak the ctx-watcher goroutine (it exits via the internal done channel).
func TestReaderCloseWithoutCtxCancel(t *testing.T) {
	f := &fakeRingReader{closed: make(chan struct{})}
	r := &Reader[int]{
		rb:     f,
		decode: func([]byte) (int, error) { return 0, nil },
		out:    make(chan int, 1),
	}

	runDone := make(chan struct{})
	go func() { r.Run(context.Background()); close(runDone) }()

	_ = r.Close()

	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after external Close")
	}
	if got := f.closes.Load(); got != 1 {
		t.Fatalf("underlying reader Close called %d times, want exactly 1", got)
	}
}
