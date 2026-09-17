package daemon

import "testing"

func TestDaemonReportsPluginInventoryQueue(t *testing.T) {
	d := &Daemon{}
	q, ok := d.QueueStatuses()["checks.plugin_inventory"]
	if !ok || q.Status != "ok" || !q.CapacityUnavailable || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("plugin inventory queue is missing or nonempty: found=%v status=%+v", ok, q)
	}
}
