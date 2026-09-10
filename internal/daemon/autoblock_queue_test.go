package daemon

import "testing"

func TestDaemonReportsAutoBlockAdmissionQueues(t *testing.T) {
	rows := (&Daemon{}).QueueStatuses()
	for _, name := range []string{"waiting", "active"} {
		q, ok := rows["auto_block."+name]
		if !ok || q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 {
			t.Fatalf("auto-block %s missing or not idle: found=%v status=%+v", name, ok, q)
		}
		if name == "active" {
			if q.Capacity != 1 || q.CapacityUnavailable {
				t.Fatalf("actual state slot capacity missing: %+v", q)
			}
		} else if !q.CapacityUnavailable {
			t.Fatalf("invented fixed waiting capacity: %+v", q)
		}
	}
}
