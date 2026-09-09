package health

import (
	"encoding/json"
	"testing"

	"github.com/pidginhost/csm/internal/queuehealth"
)

// Status consumers must see protection loss even when the saturated alert
// channel cannot deliver the finding that would announce it.
func TestSnapshotQueueDegradationSurvivesWireRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name, queueStatus, want string
	}{
		{"stalled", "degraded", "degraded"},
		{"recovered", "ok", "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := `{"started_at":"2026-09-09T12:00:00Z","store_healthy":true,"watchers":{"fanotify":true},"queues":{"fanotify.analyzer":{"status":"` + tc.queueStatus + `","depth":4,"capacity":4,"dropped_total":7,"lag_seconds":75}}}`
			var snap Snapshot
			if err := json.Unmarshal([]byte(wire), &snap); err != nil {
				t.Fatal(err)
			}
			if got := snap.OverallStatus(); got != tc.want {
				t.Fatalf("overall status = %q, want %q", got, tc.want)
			}
			encoded, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			var out struct {
				Queues map[string]struct {
					Depth    int     `json:"depth"`
					Capacity int     `json:"capacity"`
					Dropped  uint64  `json:"dropped_total"`
					Lag      float64 `json:"lag_seconds"`
				} `json:"queues"`
			}
			if err := json.Unmarshal(encoded, &out); err != nil {
				t.Fatal(err)
			}
			q := out.Queues["fanotify.analyzer"]
			if q.Depth != 4 || q.Capacity != 4 || q.Dropped != 7 || q.Lag != 75 {
				t.Fatalf("queue evidence lost in status response: %+v", q)
			}
		})
	}
}

func TestBuildCopiesQueueEvidenceFromProvider(t *testing.T) {
	p := &fakeProvider{queues: map[string]queuehealth.Status{"fanotify.analyzer": {Status: "degraded", Depth: 4, Capacity: 4}}}
	snap := Build(p, "test", nil)
	if got := snap.Queues["fanotify.analyzer"]; got.Status != "degraded" || got.Depth != 4 {
		t.Fatalf("provider queue evidence absent: %+v", snap.Queues)
	}
	delete(p.queues, "fanotify.analyzer")
	if len(snap.Queues) != 1 {
		t.Fatal("provider mutation changed an already built snapshot")
	}
}
