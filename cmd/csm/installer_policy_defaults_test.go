package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// A CLI install must start with the packaged policy, not the built-in
// defaults it got while it omitted these keys. With firewall.ipv6 false every
// IPv6 packet bypasses the firewall, which the shipped config exists to avoid.
func TestInstallerUsesPackagedPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := deployDefaultConfig(path); err != nil {
		t.Fatal(err)
	}
	installed, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "build", "packaging", "csm.yaml.default"))
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := config.LoadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if !installed.Firewall.IPv6 {
		t.Error("CLI install leaves IPv6 unfiltered")
	}
	if installed.Alerts.MaxPerHour != packaged.Alerts.MaxPerHour {
		t.Errorf("alert limit = %d, packaged %d", installed.Alerts.MaxPerHour, packaged.Alerts.MaxPerHour)
	}
	if installed.Thresholds.HTTPDistributedMinIPs != packaged.Thresholds.HTTPDistributedMinIPs {
		t.Errorf("distributed HTTP threshold = %d, packaged %d", installed.Thresholds.HTTPDistributedMinIPs, packaged.Thresholds.HTTPDistributedMinIPs)
	}
	if installed.Incidents.SpraySuppression.DryRun != packaged.Incidents.SpraySuppression.DryRun {
		t.Error("credential-spray dry run differs from the packaged config")
	}
}

func TestPackagedInstallPolicyDefaultsStayUnchanged(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "build", "packaging", "csm.yaml.default"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Alerts.MaxPerHour != 10 {
		t.Errorf("packaged alert limit = %d, want 10", cfg.Alerts.MaxPerHour)
	}
	if cfg.Thresholds.HTTPDistributedMinIPs != 10 {
		t.Errorf("packaged distributed HTTP detection = %d, want 10", cfg.Thresholds.HTTPDistributedMinIPs)
	}
	if !cfg.Firewall.IPv6 {
		t.Error("packaged IPv6 filtering disabled")
	}
	if !cfg.Incidents.SpraySuppression.DryRun {
		t.Error("packaged credential-spray dry run disabled")
	}
}
