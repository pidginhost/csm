package daemon

import "testing"

func TestDaemonPublishesCheckExecutionQueue(t *testing.T) {
	d := &Daemon{}
	status, ok := d.QueueStatuses()["checks.executions"]
	if !ok || !status.CapacityUnavailable || status.Capacity != 0 {
		t.Fatalf("check execution health must not invent a global concurrency cap: present=%v status=%+v", ok, status)
	}
}
