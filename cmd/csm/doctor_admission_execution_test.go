package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

// Once admission executes automatic blocks, the owner's outages stop
// them: a ledger that is not running, a refused clock reading and
// discarded responses fail. A failed inventory read still warns. Every
// admission row closes with ExecutionAffected and none says existing
// blocking is unaffected or that the state database is kept for it.
func TestDoctorFailsAdmissionOutagesWhileExecuting(t *testing.T) {
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	ledger := &admission.LedgerStatus{Storage: admission.StorageStatus{RecoveryRoom: admission.RecoveryReserveBytes}}
	ledger.Ceiling.Limit = 2000
	report := doctorReportForSnapshot(t, admissionSnapshot(&health.AdmissionStatus{
		CheckedAt: at, Ledger: ledger, Ingress: &admission.IngressHealth{Admitting: true},
		Owner: &health.AdmissionOwner{
			Executing: true, Error: "fixture owner stop", TickError: "fixture clock refusal", CeilingSource: "default",
			InventoryError: "fixture registry unreadable", DamageError: "fixture damaged record", Import: &health.AdmissionImport{Units: 2, At: at},
		},
	}))
	for name, status := range map[string]string{
		"admission owner": "fail", "admission clock": "fail", "admission ledger damage": "fail",
		"admission inventory": "warn", "admission ceiling": "ok", "admission legacy import": "ok", "admission ledger": "ok",
	} {
		row, ok := doctorCheckNamed(report, name)
		if !ok || row.Status != status || !strings.HasSuffix(row.Message, admission.ExecutionAffected) {
			t.Errorf("%s = %+v (%v), want %s", name, row, ok, status)
		}
		if strings.Contains(row.Message+row.Fix, "unaffected") || strings.Contains(row.Fix, "existing blocking") {
			t.Errorf("%s still speaks of previews: %+v", name, row)
		}
	}
	if report.OverallStatus != "fail" {
		t.Fatalf("overall = %q", report.OverallStatus)
	}
}

// 1.5c-1 ruling 7: once admission executes, a ledger the firewall could
// not read at start fails, since the automatic blocks it restored carry no
// proof and admission decides new ones.
func TestDoctorFailsFirewallLedgerUnreadableWhileExecuting(t *testing.T) {
	for _, executing := range []bool{false, true} {
		payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
			StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true},
			Automation: health.AutomationStatus{FirewallEnabled: true, FirewallManaged: true, FirewallLedgerError: "fixture ledger damage"},
			Admission:  &health.AdmissionStatus{CheckedAt: time.Now(), Owner: &health.AdmissionOwner{Executing: executing}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
		row, ok := doctorCheckNamed(report, "firewall automatic blocks")
		status, closing := "warn", admission.PreviewUnaffected
		if executing {
			status, closing = "fail", admission.ExecutionAffected
		}
		want := DoctorCheck{
			Name: "firewall automatic blocks", Status: status,
			Message: "the admission ledger could not be read when the firewall started: fixture ledger damage; the automatic blocks it wrote were restored without proof of their outcome and none is evicted until a restart reads it; " + closing,
			Fix:     "resolve the ledger error the admission checks report, then restart csm.service",
		}
		if !ok || row != want {
			t.Fatalf("executing %t: firewall automatic blocks = %+v (%v), want %+v", executing, row, ok, want)
		}
	}
}
func TestDoctorReportsAppliedConsumerFailure(t *testing.T) {
	for _, executing := range []bool{false, true} {
		a := &health.AdmissionStatus{Owner: &health.AdmissionOwner{
			Executing: executing, AuditError: "recording applied threat batch: disk full",
		}}
		r, ok := doctorCheckNamed(DoctorReport{Checks: ownerDoctorChecks(a)}, "admission audit delivery")
		closing, _ := admission.DoctorImpact(executing)
		if !ok || r.Status != "warn" || !strings.Contains(r.Message, a.Owner.AuditError) || !strings.HasSuffix(r.Message, closing) || !strings.Contains(r.Fix, "pending") {
			t.Fatalf("delivery diagnostic = %+v, found %t", r, ok)
		}
		a.Owner.AuditError = ""
		if _, ok = doctorCheckNamed(DoctorReport{Checks: ownerDoctorChecks(a)}, "admission audit delivery"); ok {
			t.Fatal("recovered delivery still warns")
		}
	}
}
