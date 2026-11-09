package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// CLI installs previously omitted these keys and used runtime defaults.
// Adopting the packaged template must not change their effective policies.
func TestInstallerPreservesRuntimePolicyDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := deployDefaultConfig(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Alerts.MaxPerHour != 30 {
		t.Errorf("alert limit = %d, want 30", cfg.Alerts.MaxPerHour)
	}
	if cfg.Thresholds.HTTPDistributedMinIPs != 0 {
		t.Errorf("distributed HTTP detection = %d, want disabled", cfg.Thresholds.HTTPDistributedMinIPs)
	}
	if cfg.Firewall.IPv6 {
		t.Error("IPv6 filtering enabled without operator opt-in")
	}
	if cfg.Incidents.SpraySuppression.DryRun {
		t.Error("credential-spray dry run enabled without operator opt-in")
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
