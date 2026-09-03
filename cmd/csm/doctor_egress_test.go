package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
)

// doctor is where an operator looks before enabling the firewall, so the
// egress warning has to reach the report the same way the inbound ones do.
func TestBuildDoctorReportIncludesEgressLockoutWarning(t *testing.T) {
	defer config.SetSSHDConfigPath(filepath.Join(t.TempDir(), "absent"))()

	cfg := validDoctorConfig()
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://panel.example.com:8443/api/csm/findings"
	cfg.Firewall = &firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{22, 443},
		TCPOut:        []int{443},
		ConnRateLimit: 200,
	}

	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}

	report := buildDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func() ([]byte, error) { return payload, nil },
	)
	for _, check := range report.Checks {
		if check.Name == "config: firewall.tcp_out" && check.Status == "warn" &&
			strings.Contains(check.Message, "alerts.webhook.url") && strings.Contains(check.Message, "8443") {
			return
		}
	}
	t.Fatalf("doctor omitted the egress lockout warning: %+v", report.Checks)
}
