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

func TestDoctorReportsUnmanagedConfiguredFirewall(t *testing.T) {
	for _, managed := range []bool{false, true} {
		payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
			StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true},
			Automation: health.AutomationStatus{FirewallEnabled: true, FirewallManaged: managed, FirewallStartupError: "fixture apply failure"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
		found := 0
		for _, check := range report.Checks {
			if check.Name != "firewall managed" {
				continue
			}
			found++
			if managed {
				if check.Status != "ok" {
					t.Fatalf("recovered firewall reported %q", check.Status)
				}
			} else if check.Status != "fail" || !strings.Contains(check.Fix, "restart") || !strings.Contains(check.Message, "fixture apply failure") || report.OverallStatus != "fail" {
				t.Fatalf("firewall failure lacks diagnosis and recovery action: %+v", check)
			}
		}
		if found != 1 {
			t.Fatalf("doctor reported %d firewall checks; want one", found)
		}
	}
}
