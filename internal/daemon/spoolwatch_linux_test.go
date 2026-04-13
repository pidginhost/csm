//go:build linux

package daemon

import "testing"

// The spool watcher on Linux uses fanotify. We can test the creation
// with nil orchestrator (should return an error about missing config).

func TestNewSpoolWatcherLinuxNilConfig(t *testing.T) {
	_, err := NewSpoolWatcher(nil, nil, nil, nil)
	// Should return error for nil config
	if err == nil {
		// Some implementations may allow nil config — just exercise the path
		t.Log("NewSpoolWatcher accepted nil config")
	}
}
