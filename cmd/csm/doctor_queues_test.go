package main

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestDoctorReportsQueueOverloadAndEvidence(t *testing.T) {
	for _, state := range []string{"degraded", "ok"} {
		t.Run(state, func(t *testing.T) {
			wire := `{"snapshot":{"started_at":"2026-09-09T12:00:00Z","store_healthy":true,"watchers":{"fanotify":true},"queues":{"fanotify.analyzer":{"status":"` + state + `","reason":"backlog_lag","depth":3,"capacity":4,"in_flight":1,"dropped_total":7,"lag_seconds":75,"processing_seconds":12}}}}`
			report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return []byte(wire), nil }, integrityOK)
			var count int
			for _, c := range report.Checks {
				if c.Name != "queue: fanotify.analyzer" {
					continue
				}
				count++
				want := "ok"
				if state == "degraded" {
					want = "fail"
					if c.Fix == "" || report.OverallStatus != "fail" {
						t.Fatalf("overload has no failure or recovery guidance: %+v", report)
					}
				}
				if c.Status != want {
					t.Errorf("queue check status = %q, want %q", c.Status, want)
				}
				for _, evidence := range []string{"3/4", "running=1", "dropped=7", "lag=75s", "processing=12s"} {
					if !strings.Contains(c.Message, evidence) {
						t.Errorf("missing %q from queue evidence %q", evidence, c.Message)
					}
				}
			}
			if count != 1 {
				t.Fatalf("got %d queue checks, want exactly one", count)
			}
		})
	}
}

func TestDoctorReportsKernelQueueMeasurements(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		want         []string
		absent       []string
	}{
		{"measured", `"depth":4032,"capacity":4096,"depth_unit":"bytes","lag_basis":"consumer_progress","lag_seconds":61`, []string{"depth=4032/4096 bytes", "consumer_stall=61s", "dropped=65"}, []string{"lag=61s"}},
		{"closed", `"depth":0,"capacity":4096,"depth_unit":"bytes","depth_unavailable":true,"lag_basis":"unavailable","dropped_lower_bound":true`, []string{"depth=unknown/4096 bytes", "lag=unavailable", "dropped>=65"}, []string{"depth=0/", "lag=0s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := `{"snapshot":{"started_at":"2026-09-09T12:00:00Z","store_healthy":true,"watchers":{"connection":true},"queues":{"bpf.connection.kernel":{"status":"degraded","reason":"consumer_stalled","dropped_total":65,` + tc.fields + `}}}}`
			report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return []byte(wire), nil }, integrityOK)
			count := 0
			for _, check := range report.Checks {
				if check.Name != "queue: bpf.connection.kernel" {
					continue
				}
				count++
				if check.Status != "fail" {
					t.Errorf("kernel queue did not fail doctor: %+v", check)
				}
				for _, want := range tc.want {
					if !strings.Contains(check.Message, want) {
						t.Errorf("missing %q from %q", want, check.Message)
					}
				}
				for _, absent := range tc.absent {
					if strings.Contains(check.Message, absent) {
						t.Errorf("invented measurement %q in %q", absent, check.Message)
					}
				}
			}
			if count != 1 {
				t.Fatalf("got %d kernel checks, want one", count)
			}
		})
	}
}
