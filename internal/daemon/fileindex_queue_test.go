package daemon

import "testing"

func TestDaemonReportsFileIndexQueues(t *testing.T) {
	rows := (&Daemon{}).QueueStatuses()
	waiting, waitingOK := rows["checks.file_index.waiting"]
	active, activeOK := rows["checks.file_index.active"]
	if !waitingOK || waiting.Status != "ok" || !waiting.CapacityUnavailable || waiting.Depth != 0 || waiting.InFlight != 0 || waiting.DroppedTotal != 0 {
		t.Fatalf("file-index waiting queue missing or nonempty: found=%v status=%+v", waitingOK, waiting)
	}
	if !activeOK || active.Status != "ok" || active.CapacityUnavailable || active.Capacity != 1 || active.Depth != 0 || active.InFlight != 0 || active.DroppedTotal != 0 {
		t.Fatalf("file-index active slot missing or nonempty: found=%v status=%+v", activeOK, active)
	}
}
