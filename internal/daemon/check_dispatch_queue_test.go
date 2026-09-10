package daemon

import "testing"

func TestDaemonPublishesCheckDispatchQueue(t *testing.T) {
	d := &Daemon{}
	status, ok := d.QueueStatuses()["checks.dispatch"]
	if !ok || !status.CapacityUnavailable || status.Capacity != 0 || status.LagBasis != "consumer_progress" {
		t.Fatalf("pending check dispatch must report progress and per-run capacity limits: present=%v status=%+v", ok, status)
	}
}
