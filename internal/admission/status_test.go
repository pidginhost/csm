package admission

import (
	"strings"
	"testing"
	"time"
)

func healthyStatus() *LedgerStatus {
	return &LedgerStatus{
		Clock:   ClockStatus{Now: t0},
		Ingress: IngressSection{Generation: 3, Open: true},
		Storage: StorageStatus{RecoveryRoom: RecoveryReserveBytes},
	}
}

func rowsByName(rows []DoctorRow) map[string]DoctorRow {
	out := map[string]DoctorRow{}
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

func TestDoctorChecksPassAHealthyLedgerThatPreviews(t *testing.T) {
	rows := DoctorChecks(healthyStatus(), &IngressHealth{Admitting: true}, t0)
	if len(rows) != 5 {
		t.Fatalf("rows = %+v", rows)
	}
	for _, r := range rows {
		if r.Status != DoctorOK || !strings.HasPrefix(r.Name, "admission ") || r.Message != PreviewUnaffected || r.Fix != "" {
			t.Errorf("%+v", r)
		}
	}
	if DoctorChecks(nil, nil, t0) != nil {
		t.Fatal("rows without a ledger or an ingress")
	}
	if rows := DoctorChecks(nil, &IngressHealth{Admitting: true}, t0); len(rows) != 1 || rows[0].Name != "admission ingress" || rows[0].Status != DoctorOK || rows[0].Message != PreviewUnaffected || rows[0].Fix != "" {
		t.Fatalf("ingress alone: %+v", rows)
	}
}

// R10: while admission previews, legacy blocking enforces, so a damaged
// ledger, a stopped ingress and a recent gap warn, saying so.
func TestDoctorChecksWarnOnDamagedSections(t *testing.T) {
	for name, damage := range map[string]func(*LedgerStatus){
		"clock":    func(s *LedgerStatus) { s.Clock.Error = "admission record is corrupt" },
		"queue":    func(s *LedgerStatus) { s.Queue.Error = "x" },
		"counters": func(s *LedgerStatus) { s.Counters.Error = "x" },
		"outcomes": func(s *LedgerStatus) { s.Outcomes.Error = "x" },
		"ingress":  func(s *LedgerStatus) { s.Ingress.Error = "x" },
		"ceiling":  func(s *LedgerStatus) { s.Ceiling.Error = "x" },
		"storage":  func(s *LedgerStatus) { s.Storage.Error = "x" },
		"outbox":   func(s *LedgerStatus) { s.Outbox.Error = "x" },
		"notices":  func(s *LedgerStatus) { s.Notices.Error = "x" },
	} {
		s := healthyStatus()
		damage(s)
		row := rowsByName(DoctorChecks(s, &IngressHealth{Admitting: true}, t0))["admission ledger"]
		if row.Status != DoctorWarn || !strings.Contains(row.Message, name) || !strings.Contains(row.Message, PreviewUnaffected) || row.Fix == "" {
			t.Errorf("%s: %+v", name, row)
		}
	}
}

func TestDoctorChecksWarnOnAStoppedIngress(t *testing.T) {
	row := rowsByName(DoctorChecks(healthyStatus(), &IngressHealth{StoppedSince: t0.Add(-time.Minute), CriticalRefused: 7}, t0))["admission ingress"]
	if row.Status != DoctorWarn || !strings.Contains(row.Message, "7 Critical") || !strings.Contains(row.Message, PreviewUnaffected) || row.Fix == "" {
		t.Fatalf("%+v", row)
	}
	s := healthyStatus()
	s.Ingress.Resumed = s.Ingress.Generation
	row = rowsByName(DoctorChecks(s, &IngressHealth{Admitting: true}, t0))["admission ingress"]
	if row.Status != DoctorWarn || !strings.Contains(row.Message, "interrupted") || !strings.HasSuffix(row.Message, PreviewUnaffected) || row.Fix == "" {
		t.Fatalf("after an interruption: %+v", row)
	}
	s.Ingress.Resumed = s.Ingress.Generation - 1
	if row = rowsByName(DoctorChecks(s, &IngressHealth{Admitting: true}, t0))["admission ingress"]; row.Status != DoctorOK || row.Message != PreviewUnaffected || row.Fix != "" {
		t.Fatalf("an older interruption still warns: %+v", row)
	}
}

func TestDoctorChecksNeverFailWhileAdmissionPreviews(t *testing.T) {
	s := healthyStatus()
	s.Queue.Error, s.Notices.LastCriticalGap = "x", t0
	s.Ingress.Resumed = s.Ingress.Generation
	s.Storage.Pinned, s.Outbox.AuditBytes = 1, RecoveryReserveBytes
	for _, r := range DoctorChecks(s, &IngressHealth{StoppedSince: t0}, t0) {
		if r.Status != DoctorWarn || !strings.HasSuffix(r.Message, PreviewUnaffected) || strings.Count(r.Message, PreviewUnaffected) != 1 {
			t.Errorf("%+v", r)
		}
	}
}

func TestDoctorChecksWarnOnARecentCriticalGap(t *testing.T) {
	s := healthyStatus()
	s.Notices.LastCriticalGap = t0.Add(-time.Hour + time.Second)
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission response gaps"]; row.Status != DoctorWarn ||
		!strings.Contains(row.Message, "would not have received") || !strings.Contains(row.Message, PreviewUnaffected) {
		t.Fatalf("a gap inside the hour: %+v", row)
	}
	s.Notices.LastCriticalGap = t0.Add(-time.Hour)
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission response gaps"]; row.Status != DoctorOK || row.Message != PreviewUnaffected || row.Fix != "" {
		t.Fatalf("a gap an hour old: %+v", row)
	}
}

func TestDoctorChecksWarnOnReservePressure(t *testing.T) {
	s := healthyStatus()
	s.Storage.Pinned = 1
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission recovery reserve"]; row.Status != DoctorWarn || !strings.HasPrefix(row.Message, "1 bytes of unresolved outcomes are pinned;") || !strings.HasSuffix(row.Message, PreviewUnaffected) || row.Fix == "" {
		t.Fatalf("pinned outcomes: %+v", row)
	}
	s = healthyStatus()
	s.Storage.RecoveryRoom = MaxRecoveryNeed - 1
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission recovery reserve"]; row.Status != DoctorWarn || !strings.Contains(row.Message, "bytes of room remain") || !strings.HasSuffix(row.Message, PreviewUnaffected) || row.Fix == "" {
		t.Fatalf("no room for the largest reservation: %+v", row)
	}
	s.Storage.RecoveryRoom = MaxRecoveryNeed
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission recovery reserve"]; row.Status != DoctorOK || row.Message != PreviewUnaffected || row.Fix != "" {
		t.Fatalf("room for the largest reservation: %+v", row)
	}
	s = healthyStatus()
	s.Outbox.AuditBytes, s.Outbox.NoticeBytes = RecoveryReserveBytes/4, RecoveryReserveBytes/4+1
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission outbox"]; row.Status != DoctorWarn || !strings.Contains(row.Message, "over half the reserve") || !strings.HasSuffix(row.Message, PreviewUnaffected) || row.Fix == "" {
		t.Fatalf("outbox over half the reserve: %+v", row)
	}
	s.Outbox.NoticeBytes--
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission outbox"]; row.Status != DoctorOK || row.Message != PreviewUnaffected || row.Fix != "" {
		t.Fatalf("outbox at half the reserve: %+v", row)
	}
}

// The state database also holds the legacy path's state, which still
// enforces while admission previews: no admission row advises restoring
// it, whatever failed.
func TestDoctorFixesKeepTheStateDatabaseWhileAdmissionPreviews(t *testing.T) {
	s := healthyStatus()
	s.Queue.Error, s.Notices.LastCriticalGap = "admission record is corrupt", t0
	s.Storage.Pinned, s.Outbox.AuditBytes = 1, RecoveryReserveBytes
	for _, r := range DoctorChecks(s, &IngressHealth{StoppedSince: t0}, t0) {
		if strings.Contains(r.Fix, "restore") || strings.Contains(r.Fix, "stop csm.service") {
			t.Errorf("%s advises: %s", r.Name, r.Fix)
		}
	}
}
