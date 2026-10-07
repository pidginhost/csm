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
		if !ok || got != (DoctorCheck{Name: row.Name, Status: row.Status, Message: row.Message, Fix: row.Fix}) || !strings.HasSuffix(got.Message, admission.PreviewUnaffected) {
			t.Errorf("%s = %+v, want %+v", row.Name, got, row)
		}
	}
	if gaps, _ := doctorCheckNamed(report, "admission response gaps"); gaps.Status != "warn" {
		t.Fatalf("a gap a minute before the view: %+v", gaps)
	}
	// R10: legacy blocking enforces while admission previews.
	if report.OverallStatus != "warn" {
		t.Fatalf("overall = %q", report.OverallStatus)
	}
}

// The owner's own view reaches doctor: a ledger that is not running, a
// refused clock reading and ledger damage warn that existing blocking is
// unaffected while admission previews (R10), a degraded clock, a clamped ceiling, a ceiling
// of one, an unreadable legacy count and a failed inventory read warn, and
// a healthy owner shows its ceiling and import.
func TestDoctorRendersAdmissionOwnerRows(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	ledger := func(limit uint32) *admission.LedgerStatus {
		return &admission.LedgerStatus{Ceiling: admission.CeilingStatus{Limit: limit}, Storage: admission.StorageStatus{RecoveryRoom: admission.RecoveryReserveBytes}}
	}
	healthy := &health.AdmissionStatus{CheckedAt: at, Ledger: ledger(2000), Ingress: &admission.IngressHealth{Admitting: true},
		Owner: &health.AdmissionOwner{CeilingSource: "default", Import: &health.AdmissionImport{Units: 12, At: at}}}
	report := doctorReportForSnapshot(t, admissionSnapshot(healthy))
	for name, want := range map[string]string{
		"admission owner":         "ok",
		"admission clock":         "ok",
		"admission ceiling":       "ok",
		"admission legacy import": "ok",
	} {
		if got, ok := doctorCheckNamed(report, name); !ok || got.Status != want || !strings.HasSuffix(got.Message, admission.PreviewUnaffected) || strings.Count(got.Message, admission.PreviewUnaffected) != 1 || got.Fix != "" {
			t.Errorf("%s = %+v (%v), want %s", name, got, ok, want)
		}
	}
	if c, _ := doctorCheckNamed(report, "admission ceiling"); !strings.Contains(c.Message, "2000") || !strings.Contains(c.Message, "default") {
		t.Errorf("ceiling = %+v", c)
	}
	if c, _ := doctorCheckNamed(report, "admission legacy import"); !strings.Contains(c.Message, "12") || !strings.Contains(c.Message, "2026-10-04T13:00:00Z") || !strings.Contains(c.Message, "at least until") {
		t.Errorf("import = %+v", c)
	}
	if _, ok := doctorCheckNamed(report, "admission inventory"); ok {
		t.Error("a healthy inventory printed a row")
	}
	if _, ok := doctorCheckNamed(report, "admission ledger damage"); ok {
		t.Error("an undamaged ledger printed a damage row")
	}
	healthy.Owner.Import = &health.AdmissionImport{}
	if c, _ := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(healthy)), "admission legacy import"); c.Status != "ok" || !strings.Contains(c.Message, "no blocks") || !strings.HasSuffix(c.Message, admission.PreviewUnaffected) || c.Fix != "" {
		t.Errorf("an empty import = %+v", c)
	}

	for _, tc := range []struct {
		name, row, status, text string
		view                    *health.AdmissionStatus
	}{
		{"not running", "admission owner", "warn", "schema", &health.AdmissionStatus{CheckedAt: at, Ingress: &admission.IngressHealth{},
			Owner: &health.AdmissionOwner{Error: "opening the admission ledger: admission ledger schema is not supported"}}},
		{"refused reading", "admission clock", "warn", "clock unavailable", &health.AdmissionStatus{CheckedAt: at, Ledger: ledger(2000), Ingress: &admission.IngressHealth{},
			Owner: &health.AdmissionOwner{TickError: "reading the admission clock: clock unavailable"}}},
		{"degraded clock", "admission clock", "warn", "behind", &health.AdmissionStatus{CheckedAt: at, Ledger: ledger(2000), Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{ClockDegraded: true}}},
		{"clamped", "admission ceiling", "warn", "20000", &health.AdmissionStatus{CheckedAt: at, Ledger: ledger(20000), Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{CeilingSource: "clamped"}}},
		{"ceiling of one", "admission ceiling", "warn", "reserved lane", &health.AdmissionStatus{CheckedAt: at, Ledger: ledger(1), Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{CeilingSource: "configured"}}},
		{"unreadable count", "admission legacy import", "warn", "without saved credit", &health.AdmissionStatus{CheckedAt: at, Ledger: ledger(2000), Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{Import: &health.AdmissionImport{Error: "reading blocked_ips.json: unexpected EOF"}}}},
		{"inventory", "admission inventory", "warn", "registry unreadable", &health.AdmissionStatus{CheckedAt: at, Ledger: ledger(2000), Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{InventoryError: "registry unreadable"}}},
		{"ledger damage", "admission ledger damage", "warn", "admission record is corrupt", &health.AdmissionStatus{CheckedAt: at, Ledger: ledger(2000), Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{DamageError: "draining the ingress: damaged arrivals were isolated: admission record is corrupt"}}},
	} {
		report := doctorReportForSnapshot(t, admissionSnapshot(tc.view))
		got, ok := doctorCheckNamed(report, tc.row)
		if !ok || got.Status != tc.status || !strings.Contains(got.Message, tc.text) || got.Fix == "" {
			t.Errorf("%s: %s = %+v (%v), want %s naming %q with a fix", tc.name, tc.row, got, ok, tc.status, tc.text)
		}
		if !strings.HasSuffix(got.Message, admission.PreviewUnaffected) || strings.Count(got.Message, admission.PreviewUnaffected) != 1 {
			t.Errorf("%s: %+v does not say existing blocking is unaffected", tc.name, got)
		}
	}
	if _, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(&health.AdmissionStatus{CheckedAt: at, Ingress: &admission.IngressHealth{},
		Owner: &health.AdmissionOwner{Error: "x"}})), "admission ceiling"); ok {
		t.Error("a ledger that is not running printed a ceiling")
	}
}
