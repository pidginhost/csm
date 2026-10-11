package eximlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
