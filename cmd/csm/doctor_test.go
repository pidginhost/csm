package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

func TestDoctor_FormatHumanIncludesSuggestions(t *testing.T) {
	d := DoctorReport{
		Checks: []DoctorCheck{
			{Name: "config valid", Status: "fail", Message: "missing infra_ips", Fix: "add infra_ips: [...] under csm.yaml"},
			{Name: "watchers attached", Status: "ok"},
		},
	}
	out := d.Human()
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "Fix:") {
		t.Fatalf("expected FAIL and Fix: in human output, got %s", out)
	}
}

func TestDoctor_CollapseFails(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "warn"},
		{Name: "c", Status: "fail"},
	}
	if got := collapseDoctor(checks); got != "fail" {
		t.Fatalf("expected fail, got %s", got)
	}
}

func TestDoctor_CollapseWarn(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "warn"},
	}
	if got := collapseDoctor(checks); got != "warn" {
		t.Fatalf("expected warn, got %s", got)
	}
}

func TestDoctor_CollapseOK(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "ok"},
	}
	if got := collapseDoctor(checks); got != "ok" {
		t.Fatalf("expected ok, got %s", got)
	}
}

func TestBuildDoctorReport_ConfigErrorIsJSONFriendly(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return nil, errors.New("bad yaml") },
		func() ([]byte, error) {
			t.Fatal("status should not be read when config is invalid")
			return nil, nil
		},
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if len(report.Checks) != 1 || report.Checks[0].Name != "config valid" || report.Checks[0].Status != "fail" {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
	if _, err := json.Marshal(report); err != nil {
		t.Fatalf("report must remain JSON-encodable: %v", err)
	}
}

func TestBuildDoctorReport_InvalidStatusJSONFails(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return &config.Config{}, nil },
		func() ([]byte, error) { return []byte("{"), nil },
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if !strings.Contains(report.Human(), "health snapshot available") {
		t.Fatalf("expected health snapshot failure, got %s", report.Human())
	}
}

func TestBuildDoctorReport_MissingSnapshotFails(t *testing.T) {
	payload, err := json.Marshal(control.StatusResult{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	report := buildDoctorReport(
		func() (*config.Config, error) { return &config.Config{}, nil },
		func() ([]byte, error) { return payload, nil },
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
}

func TestBuildDoctorReport_EmptyWatcherRegistryFails(t *testing.T) {
	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	report := buildDoctorReport(
		func() (*config.Config, error) { return &config.Config{}, nil },
		func() ([]byte, error) { return payload, nil },
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if !strings.Contains(report.Human(), "watchers registered") {
		t.Fatalf("expected watcher registry failure, got %s", report.Human())
	}
}
