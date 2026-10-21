package main

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestDoctorWebUIExposureWarningIsNonfatal(t *testing.T) {
	cfg := validDoctorConfig()
	cfg.WebUI.Enabled = true
	cfg.WebUI.Listen = "0.0.0.0:9443"
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "ops", Token: strings.Repeat("a", 32), Scope: "admin"}}
	checks, failed := doctorConfigValidation(cfg)
	if failed || collapseDoctor(checks) != "warn" {
		t.Fatalf("exposure must be a nonfatal warning: failed=%v, checks=%+v", failed, checks)
	}
	for _, check := range checks {
		if check.Name == "config: webui.listen" && check.Status == "warn" {
			return
		}
	}
	t.Fatalf("doctor omitted the exposure warning: %+v", checks)
}
