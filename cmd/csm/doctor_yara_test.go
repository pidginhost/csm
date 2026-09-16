package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

func TestDoctorReportsYaraWorkerStartupAndRecovery(t *testing.T) {
	for _, attached := range []bool{false, true} {
		snapshot := &health.Snapshot{
			StartedAt: time.Now(), StoreHealthy: true,
			Watchers: map[string]bool{"fanotify": true, "yara_worker": attached},
		}
		wire, err := json.Marshal(control.StatusResult{Snapshot: snapshot})
		if err != nil {
			t.Fatal(err)
		}
		report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return wire, nil }, integrityOK)
		found := false
		for _, check := range report.Checks {
			if check.Name != "watcher: yara_worker" {
				continue
			}
			found = true
			if attached {
				if check.Status != "ok" || report.OverallStatus == "fail" {
					t.Fatalf("recovered worker still failing: %+v", report)
				}
			} else if check.Status != "fail" || check.Fix == "" || report.OverallStatus != "fail" {
				t.Fatalf("worker outage did not fail doctor with recovery guidance: %+v", report)
			}
		}
		if !found {
			t.Fatal("YARA worker missing from doctor report")
		}
	}
}
