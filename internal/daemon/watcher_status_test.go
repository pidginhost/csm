package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestMarkWatcher_StoreAndRead(t *testing.T) {
	d := &Daemon{}
	d.MarkWatcher("fanotify", true)
	d.MarkWatcher("audit", false)

	got := d.WatcherStatuses()
	if got["fanotify"] != true {
		t.Errorf("fanotify: expected true, got %v", got["fanotify"])
	}
	if got["audit"] != false {
		t.Errorf("audit: expected false, got %v", got["audit"])
	}
}

func TestWatcherStatuses_ReturnsCopy(t *testing.T) {
	d := &Daemon{}
	d.MarkWatcher("fanotify", true)
	got := d.WatcherStatuses()
	got["fanotify"] = false // mutate the copy
	again := d.WatcherStatuses()
	if again["fanotify"] != true {
		t.Fatal("WatcherStatuses returned a shared map; expected a copy")
	}
}

func TestWatcherStatuses_EmptyByDefault(t *testing.T) {
	d := &Daemon{}
	got := d.WatcherStatuses()
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %v", got)
	}
}

func TestStartPHPRelay_NotApplicableDoesNotRegisterFailedWatcher(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelNone
	platform.SetOverrides(platform.Overrides{
		Panel: &panel,
	})

	d := New(&config.Config{}, nil, nil, "")
	d.startPHPRelay()

	if got := d.WatcherStatuses(); len(got) != 0 {
		t.Fatalf("non-cPanel phprelay should be absent from watcher health, got %v", got)
	}
}
