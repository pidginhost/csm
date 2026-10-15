package admission

import (
	"strings"
	"testing"
	"time"
)

// Once admission executes automatic blocks (1.5c-3b), an admission outage
// is an outage of automatic blocking. Every row closes by saying so, never
// that existing blocking is unaffected, and a damaged ledger, a stopped
// ingress or a Critical gap in the last hour fails where a preview only
// warned (spec 5.17: doctor fails on unavailable safety state and on a
// Critical response gap in the past hour). An interrupted generation and
// pressure on the reserve and outbox still warn.
func TestDoctorChecksWhileExecuting(t *testing.T) {
	rows := DoctorChecks(healthyStatus(), &IngressHealth{Admitting: true}, t0, true)
	if len(rows) != 5 {
		t.Fatalf("rows = %+v", rows)
	}
	for _, r := range rows {
		if r.Status != DoctorOK || r.Message != ExecutionAffected || r.Fix != "" {
			t.Errorf("healthy %s = %+v", r.Name, r)
		}
	}
	damaged := healthyStatus()
	damaged.Queue.Error = "fixture damage"
	interrupted := healthyStatus()
	interrupted.Ingress.Resumed = interrupted.Ingress.Generation
	gap := healthyStatus()
	gap.Notices.LastCriticalGap = t0.Add(-time.Minute)
	pinned := healthyStatus()
	pinned.Storage.Pinned = 1
	full := healthyStatus()
	full.Outbox.AuditBytes = RecoveryReserveBytes
	for _, tc := range []struct {
		name, row, status, contains string
		s                           *LedgerStatus
		in                          *IngressHealth
	}{
		{"damaged ledger", "admission ledger", DoctorFail, "queue: fixture damage", damaged, nil},
		{"stopped ingress", "admission ingress", DoctorFail, "refusing every automatic response", healthyStatus(), &IngressHealth{StoppedSince: t0.Add(-time.Minute)}},
		{"interrupted generation", "admission ingress", DoctorWarn, "interrupted", interrupted, &IngressHealth{Admitting: true}},
		{"critical gap", "admission response gaps", DoctorFail, "a Critical finding did not receive its response at", gap, nil},
		{"pinned reserve", "admission recovery reserve", DoctorWarn, "bytes of unresolved outcomes are pinned", pinned, nil},
		{"full outbox", "admission outbox", DoctorWarn, "over half the reserve", full, nil},
	} {
		row := rowsByName(DoctorChecks(tc.s, tc.in, t0, true))[tc.row]
		if row.Status != tc.status || !strings.Contains(row.Message, tc.contains) || !strings.HasSuffix(row.Message, "; "+ExecutionAffected) || row.Fix == "" {
			t.Errorf("%s: %s = %+v", tc.name, tc.row, row)
		}
		if strings.Contains(row.Message+row.Fix, "unaffected") || strings.Contains(row.Fix, "existing blocking") || strings.Contains(row.Fix, "previews") {
			t.Errorf("%s: %s still speaks of previews: %+v", tc.name, tc.row, row)
		}
	}
}

// Unknown outcomes are visible in either mode: a row counts them and says
// when the next can retire (P7); with none there is no row.
func TestDoctorChecksReportUnknownOutcomes(t *testing.T) {
	for _, executing := range []bool{false, true} {
		closing := PreviewUnaffected
		if executing {
			closing = ExecutionAffected
		}
		s := healthyStatus()
		s.Unresolved.Running = 3
		if row, ok := rowsByName(DoctorChecks(s, nil, t0, executing))["admission unresolved outcomes"]; ok {
			t.Fatalf("executing %t: a row without unknown outcomes: %+v", executing, row)
		}
		s.Unresolved = UnresolvedStatus{Running: 1, Unknown: 2, Retires: t0.Add(time.Hour)}
		row := rowsByName(DoctorChecks(s, nil, t0, executing))["admission unresolved outcomes"]
		if row.Status != DoctorWarn || !strings.HasPrefix(row.Message, "2 automatic blocks have an unproven outcome;") ||
			!strings.Contains(row.Message, t0.Add(time.Hour).UTC().Format(time.RFC3339)) || !strings.HasSuffix(row.Message, "; "+closing) || row.Fix == "" {
			t.Fatalf("executing %t: unresolved outcomes = %+v", executing, row)
		}
	}
}
