package daemon

import "testing"

func TestDaemonReportsWPCoreQueue(t *testing.T) {
	d := &Daemon{}
	q, ok := d.QueueStatuses()["checks.wordpress_core"]
	if !ok || q.Status != "ok" || !q.CapacityUnavailable || q.DepthUnit != "installations" || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("WordPress checksum queue is missing or nonempty: found=%v status=%+v", ok, q)
	}
}
