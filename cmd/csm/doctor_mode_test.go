package main

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

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
	if !strings.Contains(check.Message, "no host changes") {
		t.Fatalf("message does not say what observe mode guarantees: %q", check.Message)
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
