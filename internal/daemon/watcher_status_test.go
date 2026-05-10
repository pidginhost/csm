package daemon

import (
	"testing"
	"time"

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

func TestMarkWatcher_StampsChangedOnTransitionsOnly(t *testing.T) {
	d := &Daemon{}

	d.MarkWatcher("modsec", true)
	first := d.WatcherChangedAt()["modsec"]
	if first.IsZero() {
		t.Fatal("first MarkWatcher call should stamp ChangedAt")
	}

	// Same state: must NOT advance the timestamp.
	time.Sleep(2 * time.Millisecond)
	d.MarkWatcher("modsec", true)
	if got := d.WatcherChangedAt()["modsec"]; !got.Equal(first) {
		t.Fatalf("idempotent MarkWatcher must not stamp; got %v want %v", got, first)
	}

	// State transition: timestamp moves.
	time.Sleep(2 * time.Millisecond)
	d.MarkWatcher("modsec", false)
	if got := d.WatcherChangedAt()["modsec"]; !got.After(first) {
		t.Fatalf("state transition must advance ChangedAt; got %v not after %v", got, first)
	}
}

func TestWatcherChangedAt_ReturnsCopy(t *testing.T) {
	d := &Daemon{}
	d.MarkWatcher("fanotify", true)
	got := d.WatcherChangedAt()
	got["fanotify"] = time.Time{}
	again := d.WatcherChangedAt()
	if again["fanotify"].IsZero() {
		t.Fatal("WatcherChangedAt returned a shared map; expected a copy")
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
