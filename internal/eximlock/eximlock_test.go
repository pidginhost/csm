package eximlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWithRejectsConcurrentTransaction(t *testing.T) {
	dir := t.TempDir()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { finished <- With(dir, func() error { close(entered); <-release; return nil }) }()
	<-entered
	calls := 0
	err := With(dir, func() error { calls++; return nil })
	close(release)
	firstErr := <-finished
	if !errors.Is(err, ErrBusy) || firstErr != nil || calls != 0 {
		t.Fatalf("concurrent=%v first=%v calls=%d", err, firstErr, calls)
	}
	failure := errors.New("mutation failed")
	if err := With(dir, func() error { return failure }); !errors.Is(err, failure) || errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := With(dir, func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("lock not released: %v calls=%d", err, calls)
	}
}

// A lock that cannot be created is a failure to report, not a busy lock to
// retry.
func TestWithSeparatesSetupFailureFromBusy(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := With(file, func() error { calls++; return nil })
	if err == nil || errors.Is(err, ErrBusy) || calls != 0 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestWithKeepsTheLockFile(t *testing.T) {
	dir := t.TempDir()
	if err := With(dir, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "mutation.lock"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v %v", info, err)
	}
}

// holdFor holds the lock in dir until release closes, after entered closes.
func holdFor(t *testing.T, dir string) (release func()) {
	t.Helper()
	entered, done, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { finished <- With(dir, func() error { close(entered); <-done; return nil }) }()
	<-entered
	return func() {
		close(done)
		if err := <-finished; err != nil {
			t.Error(err)
		}
	}
}

// The daemon's own record writes hold the lock for microseconds. Two of them
// started by one reload must wait for each other, not report busy.
func TestWithRetryWaitsOutABriefHolder(t *testing.T) {
	dir := t.TempDir()
	release := holdFor(t, dir)
	time.AfterFunc(50*time.Millisecond, release)
	calls := 0
	if err := WithRetry(dir, time.Second, func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

// A worker transaction holds the lock for seconds or minutes: past the wait
// it still reads as busy, and mutate never runs.
func TestWithRetryReportsALongHolderBusy(t *testing.T) {
	dir := t.TempDir()
	release := holdFor(t, dir)
	defer release()
	calls := 0
	start := time.Now()
	err := WithRetry(dir, 100*time.Millisecond, func() error { calls++; return nil })
	if !errors.Is(err, ErrBusy) || calls != 0 || time.Since(start) < 100*time.Millisecond {
		t.Fatalf("err=%v calls=%d after %v", err, calls, time.Since(start))
	}
}
