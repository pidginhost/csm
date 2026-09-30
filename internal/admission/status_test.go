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

func TestDoctorChecksPassAHealthyLedger(t *testing.T) {
	rows := DoctorChecks(healthyStatus(), &IngressHealth{Admitting: true}, t0)
	if len(rows) != 5 {
		t.Fatalf("rows = %+v", rows)
	}
	for _, r := range rows {
		if r.Status != DoctorOK || !strings.HasPrefix(r.Name, "admission ") {
			t.Errorf("%+v", r)
		}
	}
	if DoctorChecks(nil, nil, t0) != nil {
		t.Fatal("rows without a ledger or an ingress")
	}
	if rows := DoctorChecks(nil, &IngressHealth{Admitting: true}, t0); len(rows) != 1 || rows[0].Name != "admission ingress" {
		t.Fatalf("ingress alone: %+v", rows)
	}
}

func TestDoctorChecksFailOnDamagedSections(t *testing.T) {
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
		if row.Status != DoctorFail || !strings.Contains(row.Message, name) || row.Fix == "" {
			t.Errorf("%s: %+v", name, row)
		}
	}
}

func TestDoctorChecksFailOnAStoppedIngress(t *testing.T) {
	row := rowsByName(DoctorChecks(healthyStatus(), &IngressHealth{StoppedSince: t0.Add(-time.Minute), CriticalRefused: 7}, t0))["admission ingress"]
	if row.Status != DoctorFail || !strings.Contains(row.Message, "7 Critical") || row.Fix == "" {
		t.Fatalf("%+v", row)
	}
	s := healthyStatus()
	s.Ingress.Resumed = s.Ingress.Generation
	row = rowsByName(DoctorChecks(s, &IngressHealth{Admitting: true}, t0))["admission ingress"]
	if row.Status != DoctorWarn || !strings.Contains(row.Message, "interrupted") {
		t.Fatalf("after an interruption: %+v", row)
	}
	s.Ingress.Resumed = s.Ingress.Generation - 1
	if row = rowsByName(DoctorChecks(s, &IngressHealth{Admitting: true}, t0))["admission ingress"]; row.Status != DoctorOK {
		t.Fatalf("an older interruption still warns: %+v", row)
	}
}

func TestDoctorChecksFailOnARecentCriticalGap(t *testing.T) {
	s := healthyStatus()
	s.Notices.LastCriticalGap = t0.Add(-time.Hour + time.Second)
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission response gaps"]; row.Status != DoctorFail {
		t.Fatalf("a gap inside the hour: %+v", row)
	}
	s.Notices.LastCriticalGap = t0.Add(-time.Hour)
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission response gaps"]; row.Status != DoctorOK {
		t.Fatalf("a gap an hour old: %+v", row)
	}
}

func TestDoctorChecksWarnOnReservePressure(t *testing.T) {
	s := healthyStatus()
	s.Storage.Pinned = 1
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission recovery reserve"]; row.Status != DoctorWarn {
		t.Fatalf("pinned outcomes: %+v", row)
	}
	s = healthyStatus()
	s.Storage.RecoveryRoom = uint64(MaxRecoveryNeed) - 1
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission recovery reserve"]; row.Status != DoctorWarn {
		t.Fatalf("no room for the largest reservation: %+v", row)
	}
	s.Storage.RecoveryRoom = uint64(MaxRecoveryNeed)
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission recovery reserve"]; row.Status != DoctorOK {
		t.Fatalf("room for the largest reservation: %+v", row)
	}
	s = healthyStatus()
	s.Outbox.AuditBytes, s.Outbox.NoticeBytes = RecoveryReserveBytes/4, RecoveryReserveBytes/4+1
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission outbox"]; row.Status != DoctorWarn {
		t.Fatalf("outbox over half the reserve: %+v", row)
	}
	s.Outbox.NoticeBytes--
	if row := rowsByName(DoctorChecks(s, nil, t0))["admission outbox"]; row.Status != DoctorOK {
		t.Fatalf("outbox at half the reserve: %+v", row)
	}
}
