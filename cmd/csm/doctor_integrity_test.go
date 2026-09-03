package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/integrity"
)

// integrityOK stands in for a host whose stored hashes match.
func integrityOK(*config.Config) error { return nil }

func healthyStatusPayload(t *testing.T) []byte {
	t.Helper()
	snap := &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func findDoctorCheck(report DoctorReport, name string) (DoctorCheck, bool) {
	for _, c := range report.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return DoctorCheck{}, false
}

// The daemon keeps running on the old hashes after a drop-in changes; only
// the next restart fails. Doctor is where that pending outage has to show
// up, with the remedy spelled out, while the daemon is still reachable.
func TestBuildDoctorReportReportsConfdHashMismatchBeforeRestart(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return healthyStatusPayload(t), nil },
		func(*config.Config) error {
			return fmt.Errorf("%w: a drop-in under /etc/csm/conf.d changed", integrity.ErrConfdHashMismatch)
		},
	)
	check, ok := findDoctorCheck(report, "integrity baseline")
	if !ok {
		t.Fatalf("doctor omitted the integrity check: %+v", report.Checks)
	}
	if check.Status != "fail" {
		t.Errorf("status = %q, want fail", check.Status)
	}
	if !strings.Contains(check.Message, "conf.d hash mismatch") {
		t.Errorf("message %q should carry the verify error", check.Message)
	}
	for _, want := range []string{"csm rehash", "integrity_exempt"} {
		if !strings.Contains(check.Fix, want) {
			t.Errorf("fix %q should mention %q", check.Fix, want)
		}
	}
	if report.OverallStatus != "fail" {
		t.Errorf("OverallStatus = %q, want fail", report.OverallStatus)
	}
	if _, ok := findDoctorCheck(report, "daemon reachable"); !ok {
		t.Errorf("doctor must keep going after an integrity failure; checks=%+v", report.Checks)
	}
}

func TestBuildDoctorReportIntegrityFixNamesRehashForConfigEdit(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return healthyStatusPayload(t), nil },
		func(*config.Config) error {
			return fmt.Errorf("%w: expected a, got b", integrity.ErrConfigHashMismatch)
		},
	)
	check, ok := findDoctorCheck(report, "integrity baseline")
	if !ok || check.Status != "fail" {
		t.Fatalf("want failing integrity check, got %+v", check)
	}
	if !strings.Contains(check.Fix, "csm rehash") {
		t.Errorf("fix %q should name csm rehash", check.Fix)
	}
}

func TestBuildDoctorReportIntegrityBinaryMismatchWarnsOfTamper(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return healthyStatusPayload(t), nil },
		func(*config.Config) error {
			return fmt.Errorf("%w: expected a, got b", integrity.ErrBinaryHashMismatch)
		},
	)
	check, ok := findDoctorCheck(report, "integrity baseline")
	if !ok || check.Status != "fail" {
		t.Fatalf("want failing integrity check, got %+v", check)
	}
	if !strings.Contains(check.Fix, "csm rehash") || !strings.Contains(check.Fix, "tamper") {
		t.Errorf("fix %q should name csm rehash for a deliberate upgrade and tampering otherwise", check.Fix)
	}
}

func TestBuildDoctorReportIntegrityOKWhenHashesMatch(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return healthyStatusPayload(t), nil },
		integrityOK,
	)
	check, ok := findDoctorCheck(report, "integrity baseline")
	if !ok {
		t.Fatalf("doctor omitted the integrity check: %+v", report.Checks)
	}
	if check.Status != "ok" {
		t.Errorf("status = %q, want ok", check.Status)
	}
}

// A host that already refuses to start is exactly where the integrity
// remedy is needed, so the check runs before daemon reachability.
func TestBuildDoctorReportIntegrityRunsWhenDaemonIsDown(t *testing.T) {
	report := buildDoctorReport(
		func() (*config.Config, error) { return validDoctorConfig(), nil },
		func() ([]byte, error) { return nil, errors.New("dial unix /run/csm.sock: no such file") },
		func(*config.Config) error {
			return fmt.Errorf("%w: a drop-in changed", integrity.ErrConfdHashMismatch)
		},
	)
	check, ok := findDoctorCheck(report, "integrity baseline")
	if !ok || check.Status != "fail" {
		t.Fatalf("integrity check must run before the daemon probe, got %+v", report.Checks)
	}
	if !strings.Contains(check.Fix, "csm rehash") {
		t.Errorf("fix %q should name csm rehash", check.Fix)
	}
}

// Every command the dispatcher accepts has to be discoverable from --help.
// rehash was missing for years and only a source comment named it.
func TestUsageListsEveryDispatchedCommand(t *testing.T) {
	var buf bytes.Buffer
	writeUsage(&buf)
	usage := buf.String()
	for _, cmd := range []string{
		"daemon", "install", "uninstall", "run", "run-critical", "run-deep",
		"check", "check-critical", "check-deep", "status", "baseline", "rehash",
		"validate", "verify", "update-rules", "update-geoip", "update-bot-ranges",
		"clean", "db-clean", "scan", "firewall", "harden", "incidents", "enable",
		"disable", "config", "store", "export", "phprelay", "doctor", "backup",
		"forensic-snapshot", "restore", "webserver-integration", "pam", "report",
		"virtual-patch", "version",
	} {
		if !strings.Contains(usage, "\n  "+cmd) {
			t.Errorf("csm --help does not list %q", cmd)
		}
	}
}
