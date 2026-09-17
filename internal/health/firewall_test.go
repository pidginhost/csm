package health

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSnapshotFirewallManagementAffectsOverallHealth(t *testing.T) {
	for _, tc := range []struct {
		name             string
		enabled, managed bool
		want             string
	}{
		{"failed startup", true, false, "degraded"},
		{"recovered", true, true, "ok"},
		{"disabled", false, false, "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := Build(&fakeProvider{started: time.Now(), storeOK: true, watchers: map[string]bool{"file": true}, automation: AutomationStatus{FirewallEnabled: tc.enabled, FirewallManaged: tc.managed}}, "test", nil)
			// Both HTTP and the control socket carry this snapshot.
			encoded, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Snapshot
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if got := decoded.OverallStatus(); got != tc.want {
				t.Fatalf("overall health = %q; want %q", got, tc.want)
			}
		})
	}
}
