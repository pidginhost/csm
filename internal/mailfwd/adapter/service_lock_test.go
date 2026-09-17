package adapter

import (
	"errors"
	"testing"
)

func TestEximMutationRejectsConcurrentTransaction(t *testing.T) {
	dir := t.TempDir()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { finished <- withEximMutationLock(dir, func() error { close(entered); <-release; return nil }) }()
	<-entered
	calls := 0
	err := withEximMutationLock(dir, func() error { calls++; return nil })
	close(release)
	firstErr := <-finished
	if err == nil || firstErr != nil || calls != 0 {
		t.Fatalf("concurrent=%v first=%v calls=%d", err, firstErr, calls)
	}
	failure := errors.New("mutation failed")
	if err := withEximMutationLock(dir, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := withEximMutationLock(dir, func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("lock not released: %v calls=%d", err, calls)
	}
}
