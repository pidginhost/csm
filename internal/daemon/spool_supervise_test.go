package daemon

import (
	"sync"
	"testing"
	"time"
)

// A crash-restart can swap a fresh SpoolWatcher (with its own stopCh) into
// runSpoolWatcherLoop. The external shutdown path only stops the instance
// registered via setSpoolWatcher, so it can miss the live instance, leaving
// its Run() blocked forever and hanging wg.Wait(). superviseWatcherRun must
// stop whatever instance it is given the moment d.stopCh closes.
func TestSuperviseWatcherRunStopsLiveInstanceOnShutdown(t *testing.T) {
	daemonStop := make(chan struct{})

	runReturned := make(chan struct{})
	instanceStop := make(chan struct{})
	var stopCalls int32
	var mu sync.Mutex

	run := func() {
		// Models SpoolWatcher.Run: blocks until this instance's own stop
		// is invoked, exactly like blocking on sw.stopCh.
		<-instanceStop
		close(runReturned)
	}
	stop := func() {
		mu.Lock()
		stopCalls++
		mu.Unlock()
		// Idempotent close, matching stopOnce semantics.
		select {
		case <-instanceStop:
		default:
			close(instanceStop)
		}
	}

	done := make(chan struct{})
	go func() {
		superviseWatcherRun(daemonStop, run, stop)
		close(done)
	}()

	// Shutdown fires. Even though nothing external stopped this instance,
	// the supervisor must call stop() so run() can return.
	close(daemonStop)

	select {
	case <-runReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("run() never returned: supervisor failed to stop the live instance on shutdown")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("superviseWatcherRun did not return after run() finished")
	}
	mu.Lock()
	if stopCalls == 0 {
		t.Fatal("stop() was never called on the live instance")
	}
	mu.Unlock()
}

// When the watcher exits on its own (a crash, not shutdown), the supervisor
// must return and must not leak its helper goroutine or call stop().
func TestSuperviseWatcherRunReapsHelperOnNormalExit(t *testing.T) {
	daemonStop := make(chan struct{})
	defer close(daemonStop)

	var stopCalls int32
	run := func() {} // returns immediately, as on a crash
	stop := func() { stopCalls++ }

	done := make(chan struct{})
	go func() {
		superviseWatcherRun(daemonStop, run, stop)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("superviseWatcherRun did not return after run() exited on its own")
	}
	if stopCalls != 0 {
		t.Fatalf("stop() must not be called when run() exits on its own, got %d calls", stopCalls)
	}
}
