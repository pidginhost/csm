package incident

import (
	"strconv"
	"testing"
	"time"
)

// The first failures from one IP open an ordinary per-IP incident under the
// RemoteIP key. When the same IP then trips the spray threshold, the spray
// incident used to be created under that same key, stealing the key index
// and leaving the earlier incident Open with nothing able to merge into or
// close it. The existing incident is promoted in place instead.
func TestSprayTripPromotesExistingPerIPIncident(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	var persisted []Incident
	c.cfg.Persist = func(inc Incident) { persisted = append(persisted, inc) }
	now := time.Unix(1_700_000_000, 0)
	const ip = "192.0.2.9"

	var firstID string
	for i := 0; i < 3; i++ { // threshold=3 in tests
		mb := "user" + strconv.Itoa(i) + "@example.com"
		id, created, err := c.OnFinding(sprayFinding(mb, ip, now))
		if err != nil {
			t.Fatalf("OnFinding: %v", err)
		}
		if i == 0 {
			firstID = id
		} else if created {
			t.Fatalf("finding %d reported a new incident although the original was promoted in place", i+1)
		}
	}
	if firstID == "" {
		t.Fatal("first failure did not open a per-IP incident")
	}

	var active []Incident
	for _, inc := range c.Snapshot() {
		if inc.CorrelationKey.RemoteIP == ip && incidentStatusActive(inc.Status) {
			active = append(active, inc)
		}
	}
	if len(active) != 1 {
		t.Fatalf("%d active incidents for %s after the spray trip, want exactly 1 (the earlier one orphaned)", len(active), ip)
	}
	if active[0].ID != firstID {
		t.Fatalf("active incident %s is not the promoted original %s", active[0].ID, firstID)
	}
	if active[0].Kind != KindCredentialSpray {
		t.Fatalf("promoted incident kind = %s, want %s", active[0].Kind, KindCredentialSpray)
	}
	if len(active[0].Timeline) != 3 {
		t.Fatalf("promoted incident timeline has %d findings, want all 3", len(active[0].Timeline))
	}
	if len(persisted) != 2 || persisted[1].ID != firstID || persisted[1].Kind != KindCredentialSpray || len(persisted[1].Timeline) != 3 {
		t.Fatalf("promotion was not persisted with its full timeline: %+v", persisted)
	}
	if got := c.spray.IncidentForIP(ip); got != firstID {
		t.Fatalf("spray detector bound to %q, want the promoted incident %s", got, firstID)
	}
}
