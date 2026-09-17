package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
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

	report := buildDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func() ([]byte, error) { return healthyStatusPayload(t), nil },
		integrityOK,
	)
	for _, check := range report.Checks {
		if check.Name == "config: firewall.tcp_out" && check.Status == "warn" &&
			strings.Contains(check.Message, "alerts.webhook.url") && strings.Contains(check.Message, "8443") {
			return
		}
	}
	t.Fatalf("doctor omitted the egress lockout warning: %+v", report.Checks)
}
