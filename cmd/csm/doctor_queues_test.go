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
