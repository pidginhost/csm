package daemon

import "testing"

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
