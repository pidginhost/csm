package config

import (
	"slices"
	"testing"
)

func TestLoginUpgradeEmailConfig(t *testing.T) {
	cfg, err := LoadBytes([]byte("alerts:\n  email:\n    disabled_checks: [ssh_login_realtime, ftp_login_realtime]\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh_login_unknown_ip", "ftp_login"}
	if !slices.Equal(cfg.Alerts.Email.DisabledChecks, want) {
		t.Fatalf("effective email exclusions = %v, want %v", cfg.Alerts.Email.DisabledChecks, want)
	}
}
