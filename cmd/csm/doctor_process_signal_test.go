package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

// Automatic termination is configured per host but depends on the kernel.
// An operator must learn that it cannot run before an incident needs it.
func TestDoctorReportsUnsupportedProcessSignaling(t *testing.T) {
	for _, tc := range []struct {
		name               string
		enabled, supported bool
		wantChecks         int
	}{
		{"unsupported kernel", true, false, 1},
		{"supported kernel", true, true, 1},
		{"termination disabled", false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			automation := health.AutomationStatus{ProcessKillEnabled: tc.enabled, ProcessSignalSupported: tc.supported}
			if !tc.supported {
				automation.ProcessSignalError = "pidfd_send_signal: safe process signaling requires kernel pidfd support"
			}
			payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
				StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true}, Automation: automation,
			}})
			if err != nil {
				t.Fatal(err)
			}
			report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
			found := 0
			for _, check := range report.Checks {
				if check.Name != "process termination supported" {
					continue
				}
				found++
				if tc.supported && check.Status != "ok" {
					t.Fatalf("supported kernel reported %q", check.Status)
				}
				if !tc.supported {
					if check.Status != "fail" || !strings.Contains(check.Message, "pidfd_send_signal") || check.Fix == "" {
						t.Fatalf("unsupported kernel lacks diagnosis and operator action: %+v", check)
					}
				}
			}
			if found != tc.wantChecks {
				t.Fatalf("doctor reported %d termination checks; want %d", found, tc.wantChecks)
			}
			// An inoperative configured protection must fail the report, not warn.
			if failed := report.OverallStatus == "fail"; failed != (tc.enabled && !tc.supported) {
				t.Fatalf("overall status = %q for enabled=%t supported=%t", report.OverallStatus, tc.enabled, tc.supported)
			}
		})
	}
}
