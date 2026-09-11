//go:build linux

package checks

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A returned engine error is already known while the final state write and its
// error log can still block. The active owner must retain that evidence.
func TestAutoBlockQueueCountsFailureBeforeBlockedCleanup(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := unix.Write(fd, make([]byte, 4096))
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Keep the descriptor nonblocking so os.File's poller can wait for space.
	originalStderr := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = originalStderr }()
	failure := errors.New("synthetic engine error before blocked cleanup")
	reached := make(chan struct{})
	var statePath string
	cfg := autoBlockQueueFixture(t, func() error {
		if err := os.Mkdir(filepath.Join(statePath, blockStateFile), 0700); err != nil {
			return err
		}
		close(reached)
		return failure
	})
	statePath = cfg.StatePath
	done := make(chan error, 1)
	go func() { done <- autoBlockQueueCall(cfg, "direct", nil) }()
	defer func() {
		drained := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, reader); close(drained) }()
		select {
		case err := <-done:
			assertAutoBlockQueueDrained(t, 1)
			if !errors.Is(err, failure) {
				t.Errorf("returned engine error changed: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("state cleanup did not drain")
		}
		_ = writer.Close()
		<-drained
	}()
	select {
	case <-reached:
	case <-time.After(3 * time.Second):
		t.Fatal("engine not reached")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		row := AutoBlockQueueStatuses(time.Now())["active"]
		if row.DroppedTotal == 1 {
			if row.InFlight != 1 {
				t.Fatalf("failed work released before cleanup: %+v", row)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("known engine failure hidden by state cleanup: %+v", row)
		}
		time.Sleep(time.Millisecond)
	}
}
