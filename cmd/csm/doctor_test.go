package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
)

func validDoctorConfig() *config.Config {
	cfg := &config.Config{Hostname: "host.example.com"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"admin@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.MaxPerHour = 10
	cfg.InfraIPs = []string{"198.51.100.10"}
	return cfg
}

func TestDoctor_FormatHumanIncludesSuggestions(t *testing.T) {
	d := DoctorReport{
		Checks: []DoctorCheck{
			{Name: "config valid", Status: "fail", Message: "missing infra_ips", Fix: "add infra_ips: [...] under csm.yaml"},
			{Name: "watchers attached", Status: "ok"},
		},
	}
	out := d.Human()
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "Fix:") {
		t.Fatalf("expected FAIL and Fix: in human output, got %s", out)
	}
}

func TestDoctor_CollapseFails(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "warn"},
		{Name: "c", Status: "fail"},
	}
	if got := collapseDoctor(checks); got != "fail" {
		t.Fatalf("expected fail, got %s", got)
	}
}

func TestDoctor_CollapseWarn(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "warn"},
	}
	if got := collapseDoctor(checks); got != "warn" {
		t.Fatalf("expected warn, got %s", got)
	}
}

func TestDoctor_CollapseOK(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "ok"},
	}
	if got := collapseDoctor(checks); got != "ok" {
		t.Fatalf("expected ok, got %s", got)
	}
}

func TestBuildDoctorReport_ConfigErrorIsJSONFriendly(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return nil, errors.New("bad yaml") },
		func() ([]byte, error) {
			t.Fatal("status should not be read when config is invalid")
			return nil, nil
		},
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if len(report.Checks) != 1 || report.Checks[0].Name != "config valid" || report.Checks[0].Status != "fail" {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
	if _, err := json.Marshal(report); err != nil {
		t.Fatalf("report must remain JSON-encodable: %v", err)
	}
}

func TestBuildDoctorReport_InvalidStatusJSONFails(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return []byte("{"), nil },
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if !strings.Contains(report.Human(), "health snapshot available") {
		t.Fatalf("expected health snapshot failure, got %s", report.Human())
	}
}

func TestBuildDoctorReport_MissingSnapshotFails(t *testing.T) {
	payload, err := json.Marshal(control.StatusResult{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return payload, nil },
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
}

func TestBuildDoctorReport_EmptyWatcherRegistryFails(t *testing.T) {
	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return payload, nil },
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if !strings.Contains(report.Human(), "watchers registered") {
		t.Fatalf("expected watcher registry failure, got %s", report.Human())
	}
}

func TestBuildDoctorReportIncludesConfigWarnings(t *testing.T) {
	cfg := validDoctorConfig()
	cfg.WebUI.Enabled = true
	cfg.WebUI.Listen = "0.0.0.0:9443"
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "operator", Token: "secret", Scope: "admin"}}
	cfg.Firewall = &firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{22, 443},
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
	if report.OverallStatus != "warn" {
		t.Fatalf("OverallStatus = %q, want warn\n%s", report.OverallStatus, report.Human())
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "config: firewall.tcp_in" && check.Status == "warn" && strings.Contains(check.Message, "9443") {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor omitted firewall lockout warning: %+v", report.Checks)
	}
}

func TestBuildDoctorReportStopsOnConfigValidationError(t *testing.T) {
	cfg := validDoctorConfig()
	cfg.Hostname = ""
	report := buildDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func() ([]byte, error) {
			t.Fatal("daemon status must not be read after config validation fails")
			return nil, nil
		},
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "config: hostname" && check.Status == "fail" {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor omitted validation error: %+v", report.Checks)
	}
}

func TestBuildChallengeDoctorReport_DisabledWarnsWithoutLiveChecks(t *testing.T) {
	called := false
	report := buildChallengeDoctorReport(
		func() (*config.Config, error) { return &config.Config{}, nil },
		func(*config.Config) []DoctorCheck {
			called = true
			return nil
		},
		func(*config.Config) DoctorCheck {
			called = true
			return DoctorCheck{}
		},
	)
	if called {
		t.Fatal("disabled challenge should not probe webserver or gate")
	}
	if report.OverallStatus != "warn" {
		t.Fatalf("OverallStatus = %q, want warn", report.OverallStatus)
	}
}

func TestBuildChallengeDoctorReport_OK(t *testing.T) {
	cert := writeDoctorTempFile(t, "cert.pem")
	key := writeDoctorTempFile(t, "key.pem")
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PublicURL = "https://server.example.com:8439/challenge"
	cfg.Challenge.TLSCert = cert
	cfg.Challenge.TLSKey = key
	cfg.Challenge.PortGate.Enabled = true

	report := buildChallengeDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func(*config.Config) []DoctorCheck {
			return []DoctorCheck{
				{Name: "challenge webserver snippet", Status: "ok"},
				{Name: "challenge webserver configtest", Status: "ok"},
			}
		},
		func(*config.Config) DoctorCheck {
			return DoctorCheck{Name: "challenge gate endpoint", Status: "ok"}
		},
	)
	if report.OverallStatus != "ok" {
		t.Fatalf("OverallStatus = %q, want ok\n%s", report.OverallStatus, report.Human())
	}
}

func TestBuildChallengeDoctorReport_PublicURLFailureIsFatal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.PortGate.Enabled = true

	report := buildChallengeDoctorReport(
		func() (*config.Config, error) { return cfg, nil },
		func(*config.Config) []DoctorCheck { return nil },
		func(*config.Config) DoctorCheck { return DoctorCheck{Name: "challenge gate endpoint", Status: "ok"} },
	)
	if report.OverallStatus != "fail" {
		t.Fatalf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if !strings.Contains(report.Human(), "challenge public URL") {
		t.Fatalf("expected public URL failure, got %s", report.Human())
	}
}

func TestChallengeGateProbeURLUsesConfiguredTLS(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.ListenAddr = "::"
	cfg.Challenge.ListenPort = 8439
	cfg.Challenge.TLSCert = "/tmp/cert.pem"
	cfg.Challenge.TLSKey = "/tmp/key.pem"

	got, err := challengeGateProbeURL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://[::1]:8439/challenge/gate" {
		t.Fatalf("probe URL = %q, want https://[::1]:8439/challenge/gate", got)
	}
}

func TestChallengeGateProbeURLIgnoresWebUITLSOnLoopback(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.ListenAddr = "127.0.0.1"
	cfg.Challenge.ListenPort = 8439
	cfg.WebUI.TLSCert = "/tmp/webui-cert.pem"
	cfg.WebUI.TLSKey = "/tmp/webui-key.pem"

	got, err := challengeGateProbeURL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:8439/challenge/gate" {
		t.Fatalf("probe URL = %q, want http://127.0.0.1:8439/challenge/gate", got)
	}
}

func writeDoctorTempFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
