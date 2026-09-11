package daemon

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestFindingBusPublishesQueueHealth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := alert.FindingBus
		defer func() { alert.FindingBus = previous }()
		d := &Daemon{}
		d.installFindingBus()
		defer d.closeFindingBus()
		bus := d.FindingBus()
		if bus == nil || alert.FindingBus != bus {
			t.Fatal("daemon and dispatch do not share the installed bus")
		}
		sub := bus.Subscribe()
		for range 67 {
			alert.FindingBus.Publish(alert.Finding{})
		}
		q, ok := d.QueueStatuses()["events.deliveries"]
		if !ok || q.Capacity != 64 || q.Depth != 64 || q.DroppedTotal != 3 || q.Reason != "dropped_work" {
			t.Fatalf("daemon hides event delivery pressure: %+v", q)
		}
		bus.Unsubscribe(sub)
		q = d.QueueStatuses()["events.deliveries"]
		if q.Capacity != 0 || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 {
			t.Fatalf("departed subscriber evidence = %+v", q)
		}
		time.Sleep(time.Minute)
		q = d.QueueStatuses()["events.deliveries"]
		if q.Status != "ok" || q.RecentDrops != 0 || q.DroppedTotal != 3 {
			t.Fatalf("daemon queue recovery = %+v", q)
		}
	})
}
