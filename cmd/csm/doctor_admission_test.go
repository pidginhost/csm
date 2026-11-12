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

// Doctor renders the pure admission rules when the snapshot
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
	// Legacy blocking enforces while admission previews.
	if report.OverallStatus != "warn" {
		t.Fatalf("overall = %q", report.OverallStatus)
	}
}

// The owner's own view reaches doctor: a ledger that is not running, a
// refused clock reading and ledger damage warn that existing blocking is
// unaffected while admission previews, a degraded clock, a clamped ceiling, a ceiling
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

// Held execution has its own row naming the cause. It fails once
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
// in the configuration, an engine hold in the firewall.
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
			Occupancy: &health.AdmissionDryRunOccupancy{Actual: 8, ShadowOnly: 2, Predicted: 10, Limit: 50, Capacity: 50, Unclaimed: 6, Imported: 2, DrainSeconds: 7200,
				General: health.AdmissionDryRunPartition{Size: 35, Used: 4, Free: 31}, Reserved: health.AdmissionDryRunPartition{Size: 9, Free: 9}},
			Ceiling: &health.AdmissionDryRunCeiling{Limit: 2000, GeneralUsed: 7, GeneralBudget: 259, ReservedBudget: 66},
			Picks:   picks, LastHour: recent},
	}}
}

// A dry run alone is not a failure. Doctor names the forecast's
// session and coverage, actual against predicted capacity, the modelled
// partitions of the automatic slots with the entries admission never
// evicts and when they drain, and the modelled ceiling, and says a
// prediction is not a block.
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
		!strings.Contains(capacity.Message, "259 general") || !strings.Contains(capacity.Message, "66 reserved") ||
		!strings.Contains(capacity.Message, "4 of 35 general") || !strings.Contains(capacity.Message, "0 of 9 reserved") ||
		!strings.Contains(capacity.Message, "6 entries automatic admission never evicts") || !strings.Contains(capacity.Message, "2 legacy automatic") ||
		!strings.Contains(capacity.Message, "2h0m0s") {
		t.Fatalf("admission dry-run capacity = %+v (%v)", capacity, ok)
	}
	examples, ok := doctorCheckNamed(report, "admission dry-run examples")
	if !ok || examples.Status != "ok" {
		t.Fatalf("admission dry-run examples = %+v (%v)", examples, ok)
	}
	// Only the reserve left is not a full set.
	view := dryRunView(at)
	view.Owner.DryRun.Occupancy.General = health.AdmissionDryRunPartition{}
	view.Owner.DryRun.Occupancy.Reserved = health.AdmissionDryRunPartition{Size: 1, Free: 1}
	if reserve, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission dry-run capacity"); !ok || reserve.Status != "ok" {
		t.Fatalf("admission dry-run capacity with only the reserve = %+v (%v)", reserve, ok)
	}
	for _, c := range report.Checks {
		if strings.HasPrefix(c.Name, "admission ") && c.Status == "fail" {
			t.Fatalf("a dry run failed doctor: %+v", c)
		}
	}
}

// Model limits, modelled waits, a held forecast and lost or
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
		{"unlimited set", "admission dry-run capacity", "modelled at 10000", func(d *health.AdmissionDryRun) {
			d.Occupancy.Limit, d.Occupancy.Unlimited, d.Occupancy.Capacity = 0, true, 10000
		}},
		{"set held by entries admission never evicts", "admission dry-run capacity", "fill the set", func(d *health.AdmissionDryRun) {
			d.Occupancy.Unclaimed, d.Occupancy.General, d.Occupancy.Reserved = 50, health.AdmissionDryRunPartition{}, health.AdmissionDryRunPartition{}
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

// setView is an owner whose last turn read the temporary set: 460 slots
// left by 40 entries admission never evicts, 60 legacy automatic blocks and
// 11 of admission's own.
func setView(at time.Time) *health.AdmissionStatus {
	return &health.AdmissionStatus{CheckedAt: at, Ingress: &admission.IngressHealth{Admitting: true}, Owner: &health.AdmissionOwner{
		Set: &health.AdmissionSet{Limit: 500, Capacity: 500, Unclaimed: 40, Imported: 60, DrainSeconds: 3600,
			General: health.AdmissionDryRunPartition{Size: 368, Used: 70, Free: 298}, Reserved: health.AdmissionDryRunPartition{Size: 92, Used: 1, Free: 91}}}}
}

// Doctor shows the set the last turn budgeted block work by: the
// partitions of the automatic slots and the entries admission never evicts
// with their drain time. Only the reserve left is not a full set.
func TestDoctorRendersTheTemporarySet(t *testing.T) {
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(setView(at))), "admission set")
	if !ok || row.Status != "ok" || !strings.Contains(row.Message, "70 of 368 general") || !strings.Contains(row.Message, "1 of 92 reserved") ||
		!strings.Contains(row.Message, "of 500") || !strings.Contains(row.Message, "40 entries automatic admission never evicts") ||
		!strings.Contains(row.Message, "60 legacy automatic") || !strings.Contains(row.Message, "1h0m0s") || row.Fix != "" {
		t.Fatalf("admission set = %+v (%v)", row, ok)
	}
	view := setView(at)
	view.Owner.Set.General.Free = 0
	if row, ok = doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set"); !ok || row.Status != "ok" || !strings.Contains(row.Message, "only direct or corroborated") {
		t.Fatalf("admission set with only the reserve = %+v (%v)", row, ok)
	}
	view.Owner.Set = nil
	if _, ok = doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set"); ok {
		t.Fatal("a turn that read no set printed a row")
	}
}

// A set with no slot for automatic blocks, one modelled for an unlimited
// limit, one held by entries admission never evicts, an unknown drain and
// an unreadable set warn, with a fix.
func TestDoctorWarnsOnTheTemporarySet(t *testing.T) {
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, text string
		mutate     func(*health.AdmissionOwner)
	}{
		{"no free slot", "no free automatic slot", func(o *health.AdmissionOwner) { o.Set.General.Free, o.Set.Reserved.Free = 0, 0 }},
		{"unlimited set", "modelled at 10000", func(o *health.AdmissionOwner) {
			o.Set.Limit, o.Set.Unlimited, o.Set.Capacity = 0, true, 10000
		}},
		{"held by entries admission never evicts", "fill the set", func(o *health.AdmissionOwner) {
			o.Set.Unclaimed, o.Set.General, o.Set.Reserved = 500, health.AdmissionDryRunPartition{}, health.AdmissionDryRunPartition{}
		}},
		{"unknown drain", "kernel expiry", func(o *health.AdmissionOwner) { o.Set.DrainSeconds = -1 }},
		{"unreadable set", "could not be read: set dump failed", func(o *health.AdmissionOwner) { o.Set, o.SetError = nil, "set dump failed" }},
	} {
		view := setView(at)
		tc.mutate(view.Owner)
		row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set")
		if !ok || row.Status != "warn" || !strings.Contains(row.Message, tc.text) || row.Fix == "" {
			t.Errorf("%s: admission set = %+v (%v), want a warning naming %q with a fix", tc.name, row, ok, tc.text)
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

func TestDoctorCapacityExplainsReserveOnly(t *testing.T) {
	view := dryRunView(time.Now()).Owner.DryRun
	view.Occupancy.General = health.AdmissionDryRunPartition{}
	view.Occupancy.Reserved = health.AdmissionDryRunPartition{Size: 1, Free: 1}
	got := dryRunCapacityCheck(view)
	if got.Status != "ok" || !strings.Contains(got.Message, "general work waits") {
		t.Fatalf("reserve-only explanation: %+v", got)
	}
	view.Occupancy.Reserved = health.AdmissionDryRunPartition{}
	got = dryRunCapacityCheck(view)
	if got.Status != "warn" || !strings.Contains(got.Fix, "inspect existing blocks") || !strings.Contains(got.Fix, "renewals") {
		t.Fatalf("full-set action: %+v", got)
	}
}

func TestDoctorWarnsOnUnknownDrain(t *testing.T) {
	view := dryRunView(time.Now()).Owner.DryRun
	view.Occupancy.DrainSeconds = -1
	got := dryRunCapacityCheck(view)
	if got.Status != "warn" || !strings.Contains(got.Message, "unknown drain time") || strings.Contains(got.Message, "-1s") || !strings.Contains(got.Fix, "inspect existing blocks") {
		t.Fatalf("unknown drain: %+v", got)
	}
}

func TestDoctorCapacityExplainsOccupiedGeneral(t *testing.T) {
	view := dryRunView(time.Now()).Owner.DryRun
	view.Occupancy.General = health.AdmissionDryRunPartition{Size: 4, Used: 4}
	view.Occupancy.Reserved = health.AdmissionDryRunPartition{Size: 1, Free: 1}
	got := dryRunCapacityCheck(view)
	if got.Status != "ok" || !strings.Contains(got.Message, "general work waits") {
		t.Fatalf("only reserved room: %+v", got)
	}
	view.Occupancy.Reserved.Free, view.Occupancy.Reserved.Used = 0, 1
	got = dryRunCapacityCheck(view)
	if got.Status != "warn" || !strings.Contains(got.Message, "no free automatic slot") || strings.Contains(got.Message, "only direct or corroborated work has a set slot") {
		t.Fatalf("full reserve promised room: %+v", got)
	}
}

// A full set's fix says block work may still take the slot of an
// automatic block it outranks, such as a legacy block that recorded its
// origin.
func TestDoctorSetFixNamesReplacement(t *testing.T) {
	view := setView(time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	view.Owner.Set.General.Free, view.Owner.Set.Reserved.Free = 0, 0
	row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set")
	if !ok || !strings.Contains(row.Fix, "unless it outranks an automatic block it may replace") {
		t.Fatalf("admission set fix = %q (%v)", row.Fix, ok)
	}
}

// Doctor names the replacements the forecast and the previews counted in
// the last hour, and the legacy blocks the forecast counts as replaced; a
// replacement is an admission, never a wait, and changes no status.
func TestDoctorNamesReplacements(t *testing.T) {
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	view := dryRunView(at)
	view.Owner.DryRun.LastHour["capacity_evict"], view.Owner.DryRun.Occupancy.Replaced = 4, 1
	row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission dry-run capacity")
	if !ok || row.Status != "ok" || !strings.Contains(row.Message, "in the last hour 4 forecast blocks would have replaced lower-priority automatic blocks") ||
		!strings.Contains(row.Message, "legacy automatic blocks the forecast counts as replaced: 1") || strings.Contains(row.Message, "would have waited") {
		t.Fatalf("admission dry-run capacity = %+v (%v)", row, ok)
	}
	set := setView(at)
	set.Owner.PreviewReplacements, set.Owner.PreviewReplacementsLastHour = 9, 2
	row, ok = doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(set)), "admission set")
	if !ok || row.Status != "ok" || !strings.Contains(row.Message, "in the last hour 2 previews would have replaced lower-priority automatic blocks") {
		t.Fatalf("admission set = %+v (%v)", row, ok)
	}
	for _, v := range []*health.AdmissionStatus{dryRunView(at), setView(at)} {
		for _, c := range doctorReportForSnapshot(t, admissionSnapshot(v)).Checks {
			if strings.Contains(c.Message, "replaced") {
				t.Fatalf("a row without replacements names them: %+v", c)
			}
		}
	}
}

// Recent preview counts survive a failed set read; doctor must keep the
// replacement note alongside the read warning and its existing fix.
func TestDoctorNamesReplacementsWhenSetReadFails(t *testing.T) {
	view := setView(time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC))
	view.Owner.Set, view.Owner.SetError = nil, "set dump failed"
	before, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set")
	if !ok || before.Status != "warn" || before.Fix == "" {
		t.Fatalf("unreadable set = %+v (%v)", before, ok)
	}
	view.Owner.PreviewReplacements, view.Owner.PreviewReplacementsLastHour = 9, 2
	after, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set")
	note := "; in the last hour 2 previews would have replaced lower-priority automatic blocks"
	if !ok || strings.Count(after.Message, note) != 1 {
		t.Fatalf("unreadable set lost recent replacements: %+v (%v)", after, ok)
	}
	after.Message = strings.Replace(after.Message, note, "", 1)
	if after != before {
		t.Fatalf("replacement note changed the read warning: got %+v, want %+v", after, before)
	}
}

// Replacements must not clear a full-set warning or inflate the wait
// count, and the operator's existing fix must remain unchanged.
func TestDoctorReplacementsPreserveCapacityWarnings(t *testing.T) {
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	t.Run("forecast", func(t *testing.T) {
		d := dryRunView(at).Owner.DryRun
		d.Occupancy.General = health.AdmissionDryRunPartition{Size: 35, Used: 35}
		d.Occupancy.Reserved = health.AdmissionDryRunPartition{Size: 9, Used: 9}
		d.LastHour["set_full"] = 3
		before := dryRunCapacityCheck(d)
		if before.Status != "warn" || before.Fix == "" || !strings.Contains(before.Message, "no free automatic slot") ||
			!strings.Contains(before.Message, "in the last hour live admission would have waited: 3 set_full") {
			t.Fatalf("full forecast set = %+v", before)
		}
		d.LastHour["capacity_evict"], d.Occupancy.Replaced = 4, 1
		after := dryRunCapacityCheck(d)
		for _, note := range []string{
			"; legacy automatic blocks the forecast counts as replaced: 1",
			"; in the last hour 4 forecast blocks would have replaced lower-priority automatic blocks",
		} {
			if strings.Count(after.Message, note) != 1 {
				t.Fatalf("missing replacement note %q: %+v", note, after)
			}
			after.Message = strings.Replace(after.Message, note, "", 1)
		}
		if after != before {
			t.Fatalf("replacements changed capacity warnings: got %+v, want %+v", after, before)
		}
	})
	t.Run("preview", func(t *testing.T) {
		o := setView(at).Owner
		o.Set.General = health.AdmissionDryRunPartition{Size: 368, Used: 368}
		o.Set.Reserved = health.AdmissionDryRunPartition{Size: 92, Used: 92}
		before := setDoctorCheck(o, admission.PreviewUnaffected)
		if before.Status != "warn" || !strings.Contains(before.Message, "no free automatic slot") ||
			!strings.Contains(before.Fix, "unless it outranks an automatic block it may replace") {
			t.Fatalf("full preview set = %+v", before)
		}
		o.PreviewReplacements, o.PreviewReplacementsLastHour = 9, 2
		after := setDoctorCheck(o, admission.PreviewUnaffected)
		note := "; in the last hour 2 previews would have replaced lower-priority automatic blocks"
		if strings.Count(after.Message, note) != 1 {
			t.Fatalf("full set lost recent replacements: %+v", after)
		}
		after.Message = strings.Replace(after.Message, note, "", 1)
		if after != before {
			t.Fatalf("replacements changed the full-set warning: got %+v, want %+v", after, before)
		}
	})
}

// Forecast rotations of the last hour warn that the set is too small for
// the attack, equal-tier waits join the waits, and the capacity row names
// how many scopes share each partition.
func TestDoctorWarnsOnRotationsAndEqualTierWaits(t *testing.T) {
	at := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	view := dryRunView(at)
	before, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission dry-run capacity")
	if !ok || before.Status != "ok" || strings.Contains(before.Message, "rotated") || strings.Contains(before.Message, "shared by scopes") {
		t.Fatalf("capacity row without rotations = %+v (%v)", before, ok)
	}
	d := view.Owner.DryRun
	d.LastHour["capacity_rotate"], d.LastHour["equal_tier_wait"] = 3, 5
	d.Occupancy.Shares = health.AdmissionDryRunShares{General: health.AdmissionDryRunShare{Scopes: 4, Share: 10}, Reserved: health.AdmissionDryRunShare{Scopes: 1, Share: 9}}
	row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission dry-run capacity")
	for _, want := range []string{
		"in the last hour 3 forecast blocks would have rotated out an equal-priority automatic block held for at least 30 minutes; the set is too small for the attack",
		"in the last hour live admission would have waited: 5 equal_tier_wait",
		"; general slots shared by scopes: 4, at least 10 each; reserved slots shared by scopes: 1, at least 9 each",
	} {
		if !ok || row.Status != "warn" || row.Fix == "" || !strings.Contains(row.Message, want) {
			t.Fatalf("capacity row lacks %q: %+v (%v)", want, row, ok)
		}
	}
}

// Previews of the last hour that rotated an equal-priority block out warn
// in the set row, also when the set could not be read, and the fix names
// rotation.
func TestDoctorWarnsOnPreviewRotations(t *testing.T) {
	at := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, v := range []*health.AdmissionStatus{dryRunView(at), setView(at)} {
		for _, c := range doctorReportForSnapshot(t, admissionSnapshot(v)).Checks {
			if strings.Contains(c.Message, "rotated") {
				t.Fatalf("a row without rotations names them: %+v", c)
			}
		}
	}
	warning := "in the last hour 2 previews would have rotated out an equal-priority automatic block held for at least 30 minutes; the set is too small for the attack"
	view := setView(at)
	view.Owner.PreviewRotations, view.Owner.PreviewRotationsLastHour = 5, 2
	row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set")
	if !ok || row.Status != "warn" || !strings.Contains(row.Message, warning) || !strings.Contains(row.Fix, "rotate out an equal-priority block held for 30 minutes") {
		t.Fatalf("admission set = %+v (%v)", row, ok)
	}
	view.Owner.Set, view.Owner.SetError = nil, "set dump failed"
	row, ok = doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set")
	if !ok || row.Status != "warn" || strings.Count(row.Message, warning) != 1 {
		t.Fatalf("unreadable set lost recent rotations: %+v (%v)", row, ok)
	}
}

// An idle turn or an unavailable engine can clear the set without a read
// error. That must not hide rotations still inside the diagnostic window.
func TestDoctorKeepsPreviewRotationsWithoutSet(t *testing.T) {
	view := setView(time.Now())
	view.Owner.Set = nil
	view.Owner.PreviewRotations, view.Owner.PreviewRotationsLastHour = 5, 2
	row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set")
	if !ok || row.Status != "warn" || row.Fix == "" ||
		strings.Count(row.Message, "in the last hour 2 previews would have rotated out") != 1 ||
		!strings.Contains(row.Message, "no current snapshot") || strings.Contains(row.Message, "could not be read:") {
		t.Fatalf("rotations without a set snapshot = %+v (%v)", row, ok)
	}
	view.Owner.PreviewRotationsLastHour = 0
	if row, ok = doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission set"); ok {
		t.Fatalf("expired rotations printed a set row: %+v", row)
	}
}

// A failed snapshot discards occupancy, not the session's recent
// predictions. Rotation and wait warnings must each survive that failure.
func TestDoctorKeepsForecastWarningsWithoutSnapshot(t *testing.T) {
	for _, tc := range []struct {
		prediction, text string
	}{
		{"capacity_rotate", "in the last hour 3 forecast blocks would have rotated out"},
		{"equal_tier_wait", "in the last hour live admission would have waited: 3 equal_tier_wait"},
	} {
		t.Run(tc.prediction, func(t *testing.T) {
			view := dryRunView(time.Now())
			d := view.Owner.DryRun
			d.Occupancy = nil
			cause := "engine_unavailable"
			d.ForecastError = &cause
			d.LastHour[tc.prediction] = 3
			report := doctorReportForSnapshot(t, admissionSnapshot(view))
			row, ok := doctorCheckNamed(report, "admission dry-run capacity")
			if !ok || row.Status != "warn" || row.Fix == "" || strings.Count(row.Message, tc.text) != 1 ||
				!strings.Contains(row.Message, "no current snapshot") || strings.Contains(row.Message, "real temporary elements") ||
				strings.Contains(row.Message, "shared by scopes") {
				t.Fatalf("forecast warning without a snapshot = %+v (%v)", row, ok)
			}
			if run, ok := doctorCheckNamed(report, "admission dry run"); !ok || run.Status != "warn" || !strings.Contains(run.Message, cause) {
				t.Fatalf("forecast warning hid the snapshot failure: %+v (%v)", run, ok)
			}
			d.Active = false
			if row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission dry-run capacity"); ok {
				t.Fatalf("an inactive forecast printed capacity warnings: %+v", row)
			}
			d.Active, d.LastHour[tc.prediction] = true, 0
			if row, ok := doctorCheckNamed(doctorReportForSnapshot(t, admissionSnapshot(view)), "admission dry-run capacity"); ok {
				t.Fatalf("expired forecast warnings printed a capacity row: %+v", row)
			}
		})
	}
}
