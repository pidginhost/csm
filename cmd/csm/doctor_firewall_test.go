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
