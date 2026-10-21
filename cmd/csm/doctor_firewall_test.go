package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

func TestDoctorReportsUnmanagedConfiguredFirewall(t *testing.T) {
	for _, managed := range []bool{false, true} {
		payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
			StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true},
			Automation: health.AutomationStatus{FirewallEnabled: true, FirewallManaged: managed, FirewallStartupError: "fixture apply failure"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
		found := 0
		for _, check := range report.Checks {
			if check.Name != "firewall managed" {
				continue
			}
			found++
			if managed {
				if check.Status != "ok" {
					t.Fatalf("recovered firewall reported %q", check.Status)
				}
			} else if check.Status != "fail" || !strings.Contains(check.Fix, "restart") || !strings.Contains(check.Message, "fixture apply failure") || report.OverallStatus != "fail" {
				t.Fatalf("firewall failure lacks diagnosis and recovery action: %+v", check)
			}
		}
		if found != 1 {
			t.Fatalf("doctor reported %d firewall checks; want one", found)
		}
	}
}

// A state file kept aside at startup is a failure the operator must act
// on: the firewall runs without the entries it held.
func TestDoctorReportsFirewallStateSetAside(t *testing.T) {
	const kept = "/var/lib/csm/firewall/state.json.unreadable-20260301T120000Z"
	for _, aside := range []string{"", kept} {
		payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
			StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true},
			Automation: health.AutomationStatus{FirewallEnabled: true, FirewallManaged: true, FirewallStateSetAside: aside},
		}})
		if err != nil {
			t.Fatal(err)
		}
		report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
		var rows []DoctorCheck
		for _, check := range report.Checks {
			if check.Name == "firewall state" {
				rows = append(rows, check)
			}
		}
		if aside == "" {
			if len(rows) != 0 {
				t.Fatalf("readable state reported %+v", rows)
			}
			continue
		}
		if len(rows) != 1 || rows[0].Status != "fail" || !strings.Contains(rows[0].Message, kept) || rows[0].Fix == "" || report.OverallStatus != "fail" {
			t.Fatalf("kept state file not reported as a failure: %+v (overall %s)", rows, report.OverallStatus)
		}
	}
}

// Without a readable ledger when the firewall started, the automatic rows
// it restored carry no proof: a warning until a restart reads it.
func TestDoctorWarnsFirewallLedgerUnreadable(t *testing.T) {
	for _, ledgerErr := range []string{"", "fixture ledger damage"} {
		payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
			StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true},
			Automation: health.AutomationStatus{FirewallEnabled: true, FirewallManaged: true, FirewallLedgerError: ledgerErr},
		}})
		if err != nil {
			t.Fatal(err)
		}
		report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
		var rows []DoctorCheck
		for _, check := range report.Checks {
			if check.Name == "firewall automatic blocks" {
				rows = append(rows, check)
			}
		}
		if ledgerErr == "" {
			if len(rows) != 0 {
				t.Fatalf("readable ledger reported %+v", rows)
			}
			continue
		}
		if len(rows) != 1 || rows[0].Status != "warn" || !strings.Contains(rows[0].Message, ledgerErr) || rows[0].Fix == "" {
			t.Fatalf("unreadable ledger not reported as a warning: %+v", rows)
		}
	}
}

// Operator ruling 6: doctor shows a pending CLI confirmation window. One
// whose rollback is scheduled warns with its deadline; one that cannot
// settle by itself fails and names why, and confirmation is the fix.
func TestDoctorReportsAPendingFirewallConfirmation(t *testing.T) {
	deadline := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		window  *health.FirewallConfirmation
		status  string
		message string
		enabled bool
	}{
		{"none", nil, "", "", true},
		{"scheduled", &health.FirewallConfirmation{Deadline: deadline}, "warn", "2026-10-20T12:00:00Z", true},
		{"stuck", &health.FirewallConfirmation{Deadline: deadline, Error: "fixture reason"}, "fail", "fixture reason", true},
		{"disabled with pending window", &health.FirewallConfirmation{Deadline: deadline, Error: "fixture reason"}, "fail", "fixture reason", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
				StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true},
				Automation: health.AutomationStatus{FirewallEnabled: tc.enabled, FirewallManaged: tc.enabled, FirewallConfirmation: tc.window},
			}})
			if err != nil {
				t.Fatal(err)
			}
			report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
			var rows []DoctorCheck
			for _, check := range report.Checks {
				if check.Name == "firewall confirmation" {
					rows = append(rows, check)
				}
			}
			if tc.window == nil {
				if len(rows) != 0 {
					t.Fatalf("no window reported %+v", rows)
				}
				return
			}
			if len(rows) != 1 || rows[0].Status != tc.status || !strings.Contains(rows[0].Message, tc.message) || !strings.Contains(rows[0].Fix, "csm firewall confirm") {
				t.Fatalf("rows = %+v", rows)
			}
		})
	}
}

// `csm status` prints a pending CLI confirmation window apart from the
// Web UI rollback timer.
func TestStatusPrintsAPendingFirewallConfirmation(t *testing.T) {
	deadline := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		window *health.FirewallConfirmation
		want   string
	}{
		{nil, "firewall confirm: none\n"},
		{&health.FirewallConfirmation{Deadline: deadline}, "firewall confirm: pending (rolls back at 2026-10-20T12:00:00Z)\n"},
		{&health.FirewallConfirmation{Deadline: deadline, Error: "fixture reason"}, "firewall confirm: pending (fixture reason)\n"},
	} {
		out := captureStdout(t, func() { printAutomationStatusHuman(health.AutomationStatus{FirewallConfirmation: tc.window}) })
		if !strings.Contains(out, tc.want) {
			t.Errorf("status output = %q, want %q", out, tc.want)
		}
	}
}
