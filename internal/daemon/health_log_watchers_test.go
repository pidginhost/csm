package daemon

import "testing"

// The web UI reads the watcher count on every health request; a watcher added
// by a late retry must show up.
func TestLogWatcherCountIncludesLateWatchers(t *testing.T) {
	d := &Daemon{}
	if got := d.LogWatcherCount(); got != 0 {
		t.Fatalf("LogWatcherCount() = %d, want 0", got)
	}
	d.logWatchersMu.Lock()
	d.logWatchers = append(d.logWatchers, &LogWatcher{}, &LogWatcher{})
	d.logWatchersMu.Unlock()
	if got := d.LogWatcherCount(); got != 2 {
		t.Fatalf("LogWatcherCount() = %d, want 2", got)
	}
}

func TestFanotifyActiveFollowsTheFileMonitor(t *testing.T) {
	d := &Daemon{}
	if d.FanotifyActive() {
		t.Fatal("FanotifyActive() = true with no file monitor")
	}
	d.fileMonitorMu.Lock()
	d.fileMonitor = &FileMonitor{}
	d.fileMonitorMu.Unlock()
	if !d.FanotifyActive() {
		t.Fatal("FanotifyActive() = false with a file monitor")
	}
}
