package main

import (
	"maps"
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
	want := admission.DoctorChecks(ledger, &admission.IngressHealth{StoppedSince: at.Add(-time.Hour), CriticalRefused: 4}, at, false)
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

// Owner rows never advise stopping the daemon or restoring the state
// database while admission previews: legacy blocking still enforces from
// that database.
func TestDoctorOwnerFixesKeepTheStateDatabaseWhileAdmissionPreviews(t *testing.T) {
	at := time.Now().UTC()
	report := doctorReportForSnapshot(t, admissionSnapshot(&health.AdmissionStatus{CheckedAt: at, Ingress: &admission.IngressHealth{},
		Owner: &health.AdmissionOwner{Error: "opening the admission ledger: admission record is corrupt",
			DamageError: "draining the ingress: damaged arrivals were isolated: admission record is corrupt"}}))
	for _, name := range []string{"admission owner", "admission ledger damage"} {
		row, ok := doctorCheckNamed(report, name)
		if !ok || row.Fix == "" || strings.Contains(row.Fix, "restore") || strings.Contains(row.Fix, "stop csm.service") {
			t.Errorf("%s = %+v (%v)", name, row, ok)
		}
	}
}

// Held execution has its own row naming the cause (P8). It fails once
// admission executes and warns while existing blocking still decides
// every block; without a hold there is no row.
func TestDoctorReportsHeldExecution(t *testing.T) {
	at := time.Now().UTC()
	view := func(held string, executing bool) *health.AdmissionStatus {
		return &health.AdmissionStatus{CheckedAt: at, Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{ExecutionHeld: held, Executing: executing}}
	}
	for _, tc := range []struct {
		executing      bool
		status, ending string
	}{
		{false, "warn", admission.PreviewUnaffected},
		{true, "fail", admission.ExecutionAffected},
	} {
		row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view("applying a block batch: blocked sets unavailable", tc.executing))), "admission execution")
		if !ok || row.Status != tc.status || !strings.Contains(row.Message, "blocked sets unavailable") || !strings.HasSuffix(row.Message, "; "+tc.ending) || row.Fix == "" {
			t.Fatalf("executing %v: admission execution = %+v (%v)", tc.executing, row, ok)
		}
	}
	if _, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view("", true))), "admission execution"); ok {
		t.Fatal("execution that is not held printed a row")
	}
}

// The execution row's fix follows its cause: a refused policy is repaired
// in the configuration, an engine hold in the firewall (C4).
func TestDoctorNamesWhatHoldsExecution(t *testing.T) {
	at := time.Now().UTC()
	for by, want := range map[string]string{
		"policy": "correct the setting the message names", "firewall": "probes the firewall", "": "probes the firewall",
	} {
		view := &health.AdmissionStatus{CheckedAt: at, Ingress: &admission.IngressHealth{Admitting: true},
			Owner: &health.AdmissionOwner{ExecutionHeld: "fixture hold", ExecutionHeldBy: by}}
		row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission execution")
		if !ok || !strings.Contains(row.Fix, want) {
			t.Errorf("held by %q: admission execution = %+v (%v)", by, row, ok)
		}
	}
}

// dryRunView is an owner forecasting in dry run with a healthy model.
func dryRunView(at time.Time) *health.AdmissionStatus {
	id, reset := "0123456789abcdef0123456789abcdef", "startup"
	since := at.Add(-time.Hour)
	zero := map[string]uint64{}
	for p := admission.Prediction(1); p.Valid(); p++ {
		zero[p.String()] = 0
	}
	picks, recent := maps.Clone(zero), maps.Clone(zero)
	picks["capacity_admit"], recent["capacity_admit"] = 7, 3
	return &health.AdmissionStatus{CheckedAt: at, Ingress: &admission.IngressHealth{Admitting: true}, Owner: &health.AdmissionOwner{
		DryRun: &health.AdmissionDryRun{Active: true, SessionID: &id, Since: &since, ResetReason: &reset,
			ModelledKinds: []string{"block_ip"}, PredictionScope: "ceiling_and_temporary_capacity",
			Occupancy: &health.AdmissionDryRunOccupancy{Actual: 8, ShadowOnly: 2, Predicted: 10, Limit: 50},
			Ceiling:   &health.AdmissionDryRunCeiling{Limit: 2000, GeneralUsed: 7, GeneralBudget: 259, ReservedBudget: 66},
			Picks:     picks, LastHour: recent},
	}}
}

// Spec 3.8: a dry run alone is not a failure. Doctor names the forecast's
// session and coverage, actual against predicted capacity and the modelled
// ceiling, and says a prediction is not a block.
func TestDoctorRendersAHealthyDryRun(t *testing.T) {
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	report := doctorReportForSnapshot(t, admissionSnapshot(dryRunView(at)))
	run, ok := doctorCheckNamed(report, "admission dry run")
	if !ok || run.Status != "ok" || !strings.Contains(run.Message, "0123456789abcdef0123456789abcdef") || !strings.Contains(run.Message, "startup") ||
		!strings.Contains(run.Message, "block_ip") || !strings.Contains(run.Message, "not blocks") || run.Fix != "" {
		t.Fatalf("admission dry run = %+v (%v)", run, ok)
	}
	capacity, ok := doctorCheckNamed(report, "admission dry-run capacity")
	if !ok || capacity.Status != "ok" || !strings.Contains(capacity.Message, "8 real") || !strings.Contains(capacity.Message, "10 of 50 predicted") ||
		!strings.Contains(capacity.Message, "259 general") || !strings.Contains(capacity.Message, "66 reserved") {
		t.Fatalf("admission dry-run capacity = %+v (%v)", capacity, ok)
	}
	examples, ok := doctorCheckNamed(report, "admission dry-run examples")
	if !ok || examples.Status != "ok" {
		t.Fatalf("admission dry-run examples = %+v (%v)", examples, ok)
	}
	for _, c := range report.Checks {
		if strings.HasPrefix(c.Name, "admission ") && c.Status == "fail" {
			t.Fatalf("a dry run failed doctor: %+v", c)
		}
	}
}

// Spec 3.8: model limits, modelled waits, a held forecast and lost or
// stale examples warn; they never hide held execution, which keeps its own
// row. Existing blocking still decides while admission forecasts, so that
// row warns too.
func TestDoctorWarnsOnDryRunModelProblems(t *testing.T) {
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, row, text string
		mutate          func(*health.AdmissionDryRun)
	}{
		{"modelled waits", "admission dry-run capacity", "would have waited", func(d *health.AdmissionDryRun) {
			d.LastHour["ceiling"], d.LastHour["set_full"] = 2, 1
		}},
		{"model bound", "admission dry-run capacity", "models no more", func(d *health.AdmissionDryRun) { d.Occupancy.Limited = true }},
		{"unlimited set", "admission dry-run capacity", "unlimited", func(d *health.AdmissionDryRun) {
			d.Occupancy.Limit, d.Occupancy.Unlimited = 0, true
		}},
		{"held forecast", "admission dry run", "engine_unavailable", func(d *health.AdmissionDryRun) {
			code, when := "engine_unavailable", at.Add(-time.Minute)
			d.ForecastError, d.LastErrorAt = &code, &when
		}},
		{"lost examples", "admission dry-run examples", "3 examples", func(d *health.AdmissionDryRun) {
			d.ExamplesLost, d.RecordErrors, d.ComparisonIncomplete = 3, 1, true
		}},
		{"lost summaries", "admission dry-run examples", "2 summaries", func(d *health.AdmissionDryRun) { d.SummariesLost = 2 }},
		{"stale examples", "admission dry-run examples", "purge", func(d *health.AdmissionDryRun) { d.ExamplesStale = true }},
	} {
		view := dryRunView(at)
		tc.mutate(view.Owner.DryRun)
		view.Owner.ExecutionHeld = "applying a block batch: blocked sets unavailable"
		report := doctorReportForSnapshot(t, admissionSnapshot(view))
		row, ok := doctorCheckNamed(report, tc.row)
		if !ok || row.Status != "warn" || !strings.Contains(row.Message, tc.text) || row.Fix == "" {
			t.Errorf("%s: %s = %+v (%v), want a warning naming %q with a fix", tc.name, tc.row, row, ok, tc.text)
		}
		if held, ok := doctorCheckNamed(report, "admission execution"); !ok || held.Status != "warn" {
			t.Errorf("%s: a dry-run warning hid held execution: %+v", tc.name, held)
		}
	}
}

// Leaving dry run shows the last session and no forecast; a comparison
// owner shows no dry-run rows at all.
func TestDoctorRendersAnInactiveDryRun(t *testing.T) {
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	view := dryRunView(at)
	d := view.Owner.DryRun
	d.Active, d.Occupancy, d.Ceiling = false, nil, nil
	report := doctorReportForSnapshot(t, admissionSnapshot(view))
	if run, ok := doctorCheckNamed(report, "admission dry run"); !ok || run.Status != "ok" || !strings.Contains(run.Message, "off") || !strings.Contains(run.Message, *d.SessionID) {
		t.Fatalf("admission dry run = %+v (%v)", run, ok)
	}
	if _, ok := doctorCheckNamed(report, "admission dry-run capacity"); ok {
		t.Fatal("an inactive dry run printed its capacity")
	}
	view.Owner.DryRun = nil
	for _, c := range doctorReportForSnapshot(t, admissionSnapshot(view)).Checks {
		if strings.HasPrefix(c.Name, "admission dry") {
			t.Fatalf("a comparison owner printed %+v", c)
		}
	}
}
