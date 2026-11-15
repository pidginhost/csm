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
			Executing: true, Settled: true, Error: "fixture owner stop", TickError: "fixture clock refusal", CeilingSource: "default",
			TurnError: "fixture turn failure", RetirementError: "fixture retirement fault",
			InventoryError: "fixture registry unreadable", DamageError: "fixture damaged record", Import: &health.AdmissionImport{Units: 2, At: at},
		},
	}))
	for name, status := range map[string]string{
		"admission owner": "fail", "admission clock": "fail", "admission ledger damage": "fail",
		"admission turns": "fail", "admission retirement": "warn",
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

// The check that follows an upgrade runs seconds after the start, and a
// failure there rolls the binary back to one that refuses a ledger this
// one started live. Until the owner's first turn of the process completes,
// an executing owner's outages only warn, and each such row says so. The
// grace is bounded: an owner still without a turn two minutes after the
// daemon started fails as a settled one does.
func TestDoctorWarnsAdmissionOutagesUntilTheFirstTurn(t *testing.T) {
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	ledger := &admission.LedgerStatus{Storage: admission.StorageStatus{RecoveryRoom: admission.RecoveryReserveBytes}}
	ledger.Ceiling.Limit = 2000
	ledger.Notices.LastCriticalGap = at.Add(-time.Minute)
	snap := admissionSnapshot(&health.AdmissionStatus{
		CheckedAt: at, Ledger: ledger, Ingress: &admission.IngressHealth{StoppedSince: at.Add(-time.Minute)},
		Owner: &health.AdmissionOwner{
			Executing: true, Error: "fixture owner stop", TickError: "fixture clock refusal", CeilingSource: "default",
			TurnError: "fixture turn failure", ExecutionHeld: "fixture hold", DamageError: "fixture damaged record",
			InventoryError: "fixture registry unreadable",
		},
	})
	outages := []string{
		"admission owner", "admission clock", "admission turns", "admission execution", "admission ledger damage",
		"admission ingress", "admission response gaps",
	}
	late := *snap
	late.StartedAt = time.Now().Add(-admissionSettleGrace - time.Second)
	stale := doctorReportForSnapshot(t, &late)
	for _, name := range outages {
		row, ok := doctorCheckNamed(stale, name)
		if !ok || row.Status != "fail" || !strings.HasSuffix(row.Message, admission.ExecutionAffected) {
			t.Errorf("past the grace, %s = %+v (%v), want a failure", name, row, ok)
		}
	}
	if stale.OverallStatus != "fail" {
		t.Fatalf("overall past the grace = %q, want fail", stale.OverallStatus)
	}
	report := doctorReportForSnapshot(t, snap)
	for _, name := range outages {
		row, ok := doctorCheckNamed(report, name)
		if !ok || row.Status != "warn" || !strings.HasSuffix(row.Message, admission.ExecutionAffected+"; "+admissionUnsettled) {
			t.Errorf("%s = %+v (%v), want a warning that names the first turn", name, row, ok)
		}
	}
	// A row that only warned says nothing new, and neither does a healthy one.
	for name, status := range map[string]string{"admission inventory": "warn", "admission ceiling": "ok"} {
		row, ok := doctorCheckNamed(report, name)
		if !ok || row.Status != status || !strings.HasSuffix(row.Message, admission.ExecutionAffected) {
			t.Errorf("%s = %+v (%v), want %s unchanged", name, row, ok, status)
		}
	}
	if report.OverallStatus != "warn" {
		t.Fatalf("overall = %q, want warn", report.OverallStatus)
	}
}

// Once admission executes, a ledger the firewall could
// not read at start fails, since the automatic blocks it restored carry no
// proof and admission decides new ones. Until the owner's first turn it
// warns, as the admission rows do.
func TestDoctorFailsFirewallLedgerUnreadableWhileExecuting(t *testing.T) {
	for _, settled := range []bool{false, true} {
		payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
			StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true},
			Automation: health.AutomationStatus{FirewallEnabled: true, FirewallManaged: true, FirewallLedgerError: "fixture ledger damage"},
			Admission:  &health.AdmissionStatus{CheckedAt: time.Now(), Owner: &health.AdmissionOwner{Executing: true, Settled: settled}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
		row, ok := doctorCheckNamed(report, "firewall automatic blocks")
		status, closing := "warn", admission.ExecutionAffected+"; "+admissionUnsettled
		if settled {
			status, closing = "fail", admission.ExecutionAffected
		}
		if !ok || row.Status != status || !strings.HasSuffix(row.Message, "; "+closing) {
			t.Fatalf("settled %t: firewall automatic blocks = %+v (%v), want %s", settled, row, ok, status)
		}
	}
	for _, executing := range []bool{false, true} {
		payload, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{
			StartedAt: time.Now(), StoreHealthy: true, Watchers: map[string]bool{"file": true},
			Automation: health.AutomationStatus{FirewallEnabled: true, FirewallManaged: true, FirewallLedgerError: "fixture ledger damage"},
			Admission:  &health.AdmissionStatus{CheckedAt: time.Now(), Owner: &health.AdmissionOwner{Executing: executing, Settled: true}},
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

// The grace belongs to an executing owner that has not turned, inside the
// window after a daemon start the report can trust. A missing or future
// start time gives none, a previewing owner needs none, a status without
// an owner or without admission is left alone, and rows that pass or only
// warn are never touched.
func TestDoctorSettleGraceBoundaries(t *testing.T) {
	at := time.Now()
	outage := func(executing, settled bool) *health.AdmissionStatus {
		ledger := &admission.LedgerStatus{Storage: admission.StorageStatus{RecoveryRoom: admission.RecoveryReserveBytes}}
		ledger.Ceiling.Limit = 2000
		return &health.AdmissionStatus{
			CheckedAt: at, Ledger: ledger, Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{
				Executing: executing, Settled: settled, CeilingSource: "default",
				TurnError: "fixture turn failure", InventoryError: "fixture registry unreadable",
			},
		}
	}
	for _, tc := range []struct {
		name               string
		executing, settled bool
		started            time.Time
		turns, overall     string
		noted              bool
	}{
		{"executing, unsettled, just started", true, false, at, "warn", "warn", true},
		{"executing, unsettled, no start time", true, false, time.Time{}, "fail", "fail", false},
		{"executing, unsettled, start in the future", true, false, at.Add(time.Hour), "fail", "fail", false},
		{"executing, unsettled, past the grace", true, false, at.Add(-admissionSettleGrace - time.Second), "fail", "fail", false},
		{"executing, settled, just started", true, true, at, "fail", "fail", false},
		{"previewing, unsettled, just started", false, false, at, "warn", "warn", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := admissionSnapshot(outage(tc.executing, tc.settled))
			snap.StartedAt = tc.started
			report := doctorReportForSnapshot(t, snap)
			row, ok := doctorCheckNamed(report, "admission turns")
			if !ok || row.Status != tc.turns || strings.HasSuffix(row.Message, admissionUnsettled) != tc.noted {
				t.Fatalf("admission turns = %+v (%v), want %s, noted %t", row, ok, tc.turns, tc.noted)
			}
			for name, status := range map[string]string{"admission inventory": "warn", "admission ceiling": "ok", "admission ledger": "ok"} {
				other, found := doctorCheckNamed(report, name)
				if !found || other.Status != status || strings.Contains(other.Message, admissionUnsettled) {
					t.Fatalf("%s = %+v (%v), want %s without the note", name, other, found, status)
				}
			}
			if report.OverallStatus != tc.overall {
				t.Fatalf("overall = %q, want %s", report.OverallStatus, tc.overall)
			}
		})
	}
	for name, a := range map[string]*health.AdmissionStatus{"no admission": nil, "no owner": {CheckedAt: at}} {
		snap := admissionSnapshot(a)
		snap.StartedAt = at
		for _, c := range doctorReportForSnapshot(t, snap).Checks {
			if strings.Contains(c.Message, admissionUnsettled) {
				t.Fatalf("%s: %s carries the grace note", name, c.Name)
			}
		}
	}
}
