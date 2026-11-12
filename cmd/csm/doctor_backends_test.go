package main

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestDoctorReportsLiveBackends(t *testing.T) {
	wire := `{"snapshot":{"started_at":"2026-09-09T12:00:00Z","store_healthy":true,"watchers":{"fanotify":true},"backends":{"placement":"none","sensitive_files":"bpf"}}}`
	report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return []byte(wire), nil }, integrityOK)
	checks := map[string]DoctorCheck{}
	for _, c := range report.Checks {
		checks[c.Name] = c
	}
	bpfCheck, ok := checks["backend: sensitive_files"]
	if !ok || bpfCheck.Status != "ok" || bpfCheck.Message != "bpf" {
		t.Errorf("bpf backend check %+v, found %v", bpfCheck, ok)
	}
	none, ok := checks["backend: placement"]
	if !ok || none.Status != "warn" || !strings.Contains(none.Fix, "detection.placement_backend") {
		t.Errorf("none backend check %+v, found %v; want a warning naming the key", none, ok)
	}
	if report.OverallStatus == "fail" {
		t.Errorf("a monitor without a live backend must not fail doctor: %+v", report.Checks)
	}
}
