//go:build linux

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSpoolWatcher_DetectsNewHFile(t *testing.T) {
	// inotify works for non-root on tmpfs and the user's own dirs;
	// CI runs as a regular user. Keep the test enabled regardless of euid.
	_ = os.Geteuid()
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	received := make(chan string, 4)
	w, err := newSpoolWatcher(spoolRoot, func(path string) {
		received <- path
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	time.Sleep(50 * time.Millisecond) // let watcher arm

	target := filepath.Join(sub, "1abc-H")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-received:
		if got != target {
			t.Errorf("watcher saw %q, want %q", got, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for inotify event")
	}
}
