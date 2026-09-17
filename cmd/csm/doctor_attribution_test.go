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

func doctorReportForSnapshot(t *testing.T, snap *health.Snapshot) DoctorReport {
	t.Helper()
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	return buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return payload, nil },
		integrityOK,
	)
}

func doctorCheckNamed(report DoctorReport, name string) (DoctorCheck, bool) {
	for _, c := range report.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return DoctorCheck{}, false
}

// Checks that are losing attribution right now are named with their row
// counts; the cumulative history is reported but does not fail the check.
func TestBuildDoctorReport_CorrelationAttributionWarnsWithNames(t *testing.T) {
	report := doctorReportForSnapshot(t, &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
		CorrelationAttribution: &health.CorrelationAttribution{
			Current:          map[string]int{"db_rogue_admin": 2, "db_options_injection": 1},
			Cumulative:       map[string]int{"db_rogue_admin": 7, "db_options_injection": 1},
			ActiveSetUpdates: 3,
			Since:            time.Now().Add(-time.Hour),
		},
	})
	check, ok := doctorCheckNamed(report, "correlation attribution")
	if !ok || check.Status != "warn" {
		t.Fatalf("check = %+v, want warn", check)
	}
	for _, want := range []string{"db_options_injection=1", "db_rogue_admin=2"} {
		if !strings.Contains(check.Message, want) {
			t.Errorf("message %q does not name %s", check.Message, want)
		}
	}
	if !strings.Contains(check.Message, "8 rows since start") {
		t.Errorf("message %q lacks the cumulative history", check.Message)
	}
	if !strings.Contains(check.Fix, "incidents") {
		t.Errorf("fix %q should point at the incidents documentation", check.Fix)
	}
	if report.OverallStatus != "warn" {
		t.Errorf("overall = %q, want warn", report.OverallStatus)
	}
}

// A clean active set is OK even when earlier merges lost attribution; the
// history is still shown so a recovered producer is visible as recovered.
func TestBuildDoctorReport_CorrelationAttributionOKAfterRecovery(t *testing.T) {
	report := doctorReportForSnapshot(t, &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
		CorrelationAttribution: &health.CorrelationAttribution{
			Current:          map[string]int{},
			Cumulative:       map[string]int{"db_rogue_admin": 7},
			ActiveSetUpdates: 4,
			Since:            time.Now().Add(-time.Hour),
		},
	})
	check, ok := doctorCheckNamed(report, "correlation attribution")
	if !ok || check.Status != "ok" {
		t.Fatalf("check = %+v, want ok", check)
	}
	if !strings.Contains(check.Message, "7 rows since start") {
		t.Errorf("message %q should still show the history", check.Message)
	}
}

// Before the first merge, or on a daemon that predates the block, there is
// nothing to judge and the check says so without failing.
func TestBuildDoctorReport_CorrelationAttributionAbsent(t *testing.T) {
	report := doctorReportForSnapshot(t, &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
	})
	check, ok := doctorCheckNamed(report, "correlation attribution")
	if !ok || check.Status != "ok" || !strings.Contains(check.Message, "no active set") {
		t.Fatalf("check = %+v, want ok with a no-active-set note", check)
	}
}
