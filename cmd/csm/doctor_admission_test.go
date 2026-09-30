package main

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/health"
)

func admissionSnapshot(a *health.AdmissionStatus) *health.Snapshot {
	return &health.Snapshot{
		StartedAt:    time.Now(),
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true},
		Admission:    a,
	}
}

// Doctor renders the pure admission rules (ruling 10) when the snapshot
// carries an admission view, judged at the view's own time, and prints no
// admission rows without one.
func TestBuildDoctorReportRendersAdmissionRows(t *testing.T) {
	report := doctorReportForSnapshot(t, admissionSnapshot(nil))
	for _, c := range report.Checks {
		if strings.HasPrefix(c.Name, "admission ") {
			t.Fatalf("admission row without a ledger: %+v", c)
		}
	}
	at := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	ledger := &admission.LedgerStatus{Storage: admission.StorageStatus{RecoveryRoom: admission.RecoveryReserveBytes}}
	ledger.Notices.LastCriticalGap = at.Add(-time.Minute)
	report = doctorReportForSnapshot(t, admissionSnapshot(&health.AdmissionStatus{
		CheckedAt: at, Ledger: ledger,
		Ingress: &admission.IngressHealth{StoppedSince: at.Add(-time.Hour), CriticalRefused: 4},
	}))
	want := admission.DoctorChecks(ledger, &admission.IngressHealth{StoppedSince: at.Add(-time.Hour), CriticalRefused: 4}, at)
	for _, row := range want {
		got, ok := doctorCheckNamed(report, row.Name)
		if !ok || got != (DoctorCheck{Name: row.Name, Status: row.Status, Message: row.Message, Fix: row.Fix}) {
			t.Errorf("%s = %+v, want %+v", row.Name, got, row)
		}
	}
	if gaps, _ := doctorCheckNamed(report, "admission response gaps"); gaps.Status != "fail" {
		t.Fatalf("a gap a minute before the view: %+v", gaps)
	}
	if report.OverallStatus != "fail" {
		t.Fatalf("overall = %q", report.OverallStatus)
	}
}
