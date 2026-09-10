package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func TestDaemonReportsActualAttackEventQueue(t *testing.T) {
	previous := store.Global()
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(sdb)
	t.Cleanup(func() { store.SetGlobal(previous); _ = sdb.Close() })
	d := New(&config.Config{StatePath: t.TempDir()}, nil, nil, "")
	if _, ok := d.QueueStatuses()["attackdb.events"]; ok {
		t.Fatal("uninitialized attack database published a queue")
	}
	db := attackdb.NewForTest(nil)
	d.prepareAttackDatabase(db)
	for i := 0; i < 3; i++ {
		db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23"})
	}
	if s, ok := d.QueueStatuses()["attackdb.events"]; !ok || s.Depth != 3 || s.InFlight != 0 || !s.CapacityUnavailable {
		t.Fatalf("actual event queue missing: found=%v status=%+v", ok, s)
	}
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	db.Stop()
	s, ok := d.QueueStatuses()["attackdb.events"]
	if !ok || s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 3 || s.RecentDrops != 3 || s.Status != "degraded" {
		t.Fatalf("shutdown loss missing: found=%v status=%+v", ok, s)
	}
	if source := db.QueueStatuses(time.Now())["events"]; source != s {
		t.Fatalf("daemon and source rows differ: daemon=%+v source=%+v", s, source)
	}
}
