package health

import (
	"encoding/json"
	"testing"
	"time"
)

// Automatic termination that the kernel cannot perform safely is a silent loss
// of an enabled protection, so it must reach the aggregate status.
func TestSnapshotProcessSignalSupportAffectsOverallHealth(t *testing.T) {
	for _, tc := range []struct {
		name               string
		enabled, supported bool
		want               string
	}{
		{"unsupported kernel with kill enabled", true, false, "degraded"},
		{"supported kernel with kill enabled", true, true, "ok"},
		{"kill disabled on unsupported kernel", false, false, "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			automation := AutomationStatus{ProcessKillEnabled: tc.enabled, ProcessSignalSupported: tc.supported}
			if !tc.supported {
				automation.ProcessSignalError = "safe process signaling requires kernel pidfd support"
			}
			snap := Build(&fakeProvider{started: time.Now(), storeOK: true, watchers: map[string]bool{"file": true}, automation: automation}, "test", nil)
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
			if decoded.Automation.ProcessSignalError != automation.ProcessSignalError {
				t.Fatalf("cause lost across transport: %q", decoded.Automation.ProcessSignalError)
			}
		})
	}
}
