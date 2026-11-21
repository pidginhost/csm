package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestLogWatcherDrainLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewLogWatcher(path, &config.Config{}, func(string, *config.Config) []alert.Finding { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	if w.Drain(time.Millisecond) {
		t.Fatal("drain succeeded before Run")
	}
	w.Stop()
	// Stop must wake drain callers even if Run never owned this watcher.
	select {
	case <-w.done:
	default:
		t.Fatal("Stop left drain callers waiting for their timeout")
	}
	if w.Drain(time.Second) {
		t.Fatal("drain succeeded after Stop")
	}
}

func TestLogWatcherDrainTimeoutDoesNotStallRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	w, err := NewLogWatcher(path, &config.Config{}, func(string, *config.Config) []alert.Finding {
		close(entered)
		<-release
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { w.Run(stop); close(done) }()
	t.Cleanup(func() { close(stop); <-done })
	appendLine(t, path, "record")
	result := make(chan bool, 1)
	go func() { result <- w.Drain(100 * time.Millisecond) }()
	<-entered
	if <-result {
		t.Error("drain succeeded while handler was blocked")
	}
	close(release)
	if !w.Drain(time.Second) {
		t.Fatal("abandoned drain stalled the next read")
	}
}
