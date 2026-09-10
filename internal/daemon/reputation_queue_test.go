package daemon

import "testing"

func TestDaemonReportsReputationQueryQueue(t *testing.T) {
	d := &Daemon{}
	q, ok := d.QueueStatuses()["checks.reputation_queries"]
	if !ok || q.Status != "ok" || !q.CapacityUnavailable || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("reputation query queue is missing or nonempty: found=%v status=%+v", ok, q)
	}
}
