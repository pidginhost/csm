package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

func TestDoctorReportsRunningModeBeforeRestart(t *testing.T) {
	for _, live := range []string{config.ModeEnforce, config.ModeObserve, ""} {
		t.Run("live="+live, func(t *testing.T) {
			cfg := validDoctorConfig()
			cfg.Mode = config.ModeObserve
			cfg.AutoResponse.DisableEnforceAFAlg = true
			payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{Mode: live, Watchers: map[string]bool{"audit": true}, StoreHealthy: true}})
			if err != nil {
				t.Fatal(err)
			}
			report := buildDoctorReport(func() (*config.Config, error) { return cfg, nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
			for _, check := range report.Checks {
				if check.Name != "operating mode" {
					continue
				}
				if live == config.ModeObserve {
					if check.Status != "ok" || !strings.Contains(check.Message, "no host changes") {
						t.Fatalf("live observe check = %+v", check)
					}
				} else {
					if check.Status != "warn" || strings.Contains(check.Message, "no host changes") || check.Fix == "" {
						t.Fatalf("unconfirmed observe check = %+v", check)
					}
					if live != "" && !strings.Contains(check.Message, "running enforce") {
						t.Fatalf("running posture hidden: %+v", check)
					}
				}
				return
			}
			t.Fatal("operating mode missing")
		})
	}
}

// An operator evaluating CSM has to be able to confirm the posture from the
// same command they already run for diagnostics, without reading csm.yaml.
func TestDoctorModeCheckReportsObservePosture(t *testing.T) {
	check := doctorModeCheck(&config.Config{Mode: config.ModeObserve})
	if check.Status != "ok" {
		t.Fatalf("status = %q, want ok", check.Status)
	}
	if !strings.Contains(check.Message, config.ModeObserve) {
		t.Fatalf("message does not name the mode: %q", check.Message)
	}
	if check.Name != "configured mode" || strings.Contains(check.Message, "no host changes") {
		t.Fatalf("offline check claims an active posture: %+v", check)
	}
}

func TestDoctorModeCheckReportsEnforcePosture(t *testing.T) {
	check := doctorModeCheck(&config.Config{Mode: config.ModeEnforce})
	if check.Status != "ok" {
		t.Fatalf("status = %q, want ok", check.Status)
	}
	if !strings.Contains(check.Message, config.ModeEnforce) {
		t.Fatalf("message does not name the mode: %q", check.Message)
	}
}
