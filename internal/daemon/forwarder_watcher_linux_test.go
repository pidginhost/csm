//go:build linux

package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewForwarderWatcherLinuxNilAlert(t *testing.T) {
	// A missing forwarder directory is an error, not a watcher on nothing.
	withValiasesDir(t, filepath.Join(t.TempDir(), "missing"))
	fw, err := NewForwarderWatcher(nil, nil)
	if err == nil || fw != nil {
		t.Fatalf("missing directory: watcher = %v, err = %v; want an error", fw, err)
	}
	if !strings.Contains(err.Error(), "inotify_add_watch") {
		t.Fatalf("error = %v, want it to name the failed watch", err)
	}

	// A nil alert channel is accepted: the watcher is built and owns a
	// descriptor.
	withValiasesDir(t, t.TempDir())
	fw, err = NewForwarderWatcher(nil, nil)
	if err != nil || fw == nil {
		t.Fatalf("nil alert channel: watcher = %v, err = %v; want a watcher", fw, err)
	}
	if err := unix.Close(fw.inotifyFd); err != nil {
		t.Fatalf("watcher holds no open descriptor: %v", err)
	}
}
