package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/incident"
)

func TestDaemonReportsIncidentPersistenceQueues(t *testing.T) {
	previous := incidentCorrelator
	defer func() { incidentCorrelator = previous }()
	incidentCorrelator = nil
	for name := range (&Daemon{}).QueueStatuses() {
		if strings.HasPrefix(name, "incident.") {
			t.Fatalf("uninitialized correlator published %s", name)
		}
	}
	if incidentCorrelator != nil {
		t.Fatal("health initialized the correlator")
	}
	incidentCorrelator = incident.NewCorrelator(incident.CorrelatorConfig{})
	rows := (&Daemon{}).QueueStatuses()
	for _, name := range []string{"waiting", "active", "deferred"} {
		q, ok := rows["incident.persist."+name]
		if !ok || q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
			t.Fatalf("incident %s queue missing or nonempty: found=%v status=%+v", name, ok, q)
		}
		if name == "active" {
			if q.Capacity != 1 || q.CapacityUnavailable {
				t.Fatalf("actual writer capacity missing: %+v", q)
			}
		} else if !q.CapacityUnavailable {
			t.Fatalf("%s queue invented a fixed capacity: %+v", name, q)
		}
	}
}
