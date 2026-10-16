package admission

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This frozen renderer pins every existing preview byte.
func baselineDoctorChecks(s *LedgerStatus, in *IngressHealth, now time.Time) []DoctorRow {
	var rows []DoctorRow
	if s != nil {
		rows = append(rows, baselineLedgerRow(s))
	}
	if in != nil {
		rows = append(rows, baselineIngressRow(s, in))
	}
	if s == nil {
		return rows
	}
	gap := DoctorRow{Name: "admission response gaps", Status: DoctorOK, Message: PreviewUnaffected}
	if last := s.Notices.LastCriticalGap; !last.IsZero() && now.Before(last.Add(time.Hour)) {
		gap.Status = DoctorWarn
		gap.Message = "a Critical finding would not have received its response at " + last.UTC().Format(time.RFC3339) + "; " + PreviewUnaffected
		gap.Fix = "inspect the auto_response_withheld and response_capacity_exhausted notices for the reason"
	}
	reserve := DoctorRow{Name: "admission recovery reserve", Status: DoctorOK, Message: PreviewUnaffected}
	if s.Storage.Pinned > 0 || s.Storage.RecoveryRoom < MaxRecoveryNeed {
		reserve.Status = DoctorWarn
		reserve.Message = fmt.Sprintf("%d bytes of unresolved outcomes are pinned; %d bytes of room remain", s.Storage.Pinned, s.Storage.RecoveryRoom) + "; " + PreviewUnaffected
		reserve.Fix = "resolve unknown outcomes and confirm the audit consumer acknowledges rows; new reservations wait while the reserve is full"
	}
	outbox := DoctorRow{Name: "admission outbox", Status: DoctorOK, Message: PreviewUnaffected}
	if used := s.Outbox.AuditBytes + s.Outbox.NoticeBytes; used > RecoveryReserveBytes/2 {
		outbox.Status = DoctorWarn
		outbox.Message = fmt.Sprintf("the outbox holds %d bytes, over half the reserve", used) + "; " + PreviewUnaffected
		outbox.Fix = "confirm audit and notice delivery is running and acknowledging"
	}
	return append(rows, gap, reserve, outbox)
}

func baselineLedgerRow(s *LedgerStatus) DoctorRow {
	var damaged []string
	for _, section := range []struct{ name, err string }{
		{"clock", s.Clock.Error}, {"queue", s.Queue.Error}, {"counters", s.Counters.Error},
		{"outcomes", s.Outcomes.Error}, {"ingress", s.Ingress.Error}, {"ceiling", s.Ceiling.Error},
		{"storage", s.Storage.Error}, {"outbox", s.Outbox.Error}, {"notices", s.Notices.Error},
		{"unresolved", s.Unresolved.Error},
	} {
		if section.err != "" {
			damaged = append(damaged, section.name+": "+section.err)
		}
	}
	if len(damaged) == 0 {
		return DoctorRow{Name: "admission ledger", Status: DoctorOK, Message: PreviewUnaffected}
	}
	return DoctorRow{
		Name: "admission ledger", Status: DoctorWarn, Message: strings.Join(damaged, "; ") + "; " + PreviewUnaffected,
		Fix: "previews are refused while the ledger is damaged; restart csm.service so opening the ledger proves every record, and keep the state database, which existing blocking still uses",
	}
}

func baselineIngressRow(s *LedgerStatus, in *IngressHealth) DoctorRow {
	switch {
	case !in.Admitting:
		return DoctorRow{
			Name: "admission ingress", Status: DoctorWarn,
			Message: fmt.Sprintf("refusing every automatic response since %s; %d Critical arrivals refused; %s", in.StoppedSince.UTC().Format(time.RFC3339), in.CriticalRefused, PreviewUnaffected),
			Fix:     "the ledger owner has no usable queue snapshot; inspect the daemon log and the admission ledger row",
		}
	case s != nil && s.Ingress.Resumed != 0 && s.Ingress.Resumed == s.Ingress.Generation:
		return DoctorRow{
			Name: "admission ingress", Status: DoctorWarn,
			Message: "the previous ingress generation was interrupted; its held arrivals were lost and counts are lower bounds; " + PreviewUnaffected,
			Fix:     "stop csm.service cleanly next time; the warning clears after a clean restart",
		}
	}
	return DoctorRow{Name: "admission ingress", Status: DoctorOK, Message: PreviewUnaffected}
}

func TestDoctorChecksPreviewBytes(t *testing.T) {
	for _, change := range []func(*LedgerStatus, *IngressHealth){
		func(s *LedgerStatus, in *IngressHealth) {},
		func(s *LedgerStatus, in *IngressHealth) { s.Queue.Error = "fixture queue" },
		func(s *LedgerStatus, in *IngressHealth) { s.Unresolved.Error = "fixture unresolved" },
		func(s *LedgerStatus, in *IngressHealth) { in.Admitting = false },
		func(s *LedgerStatus, in *IngressHealth) { s.Ingress.Resumed = s.Ingress.Generation },
		func(s *LedgerStatus, in *IngressHealth) { s.Notices.LastCriticalGap = t0.Add(-time.Minute) },
		func(s *LedgerStatus, in *IngressHealth) { s.Notices.LastCriticalGap = t0.Add(-time.Hour) },
		func(s *LedgerStatus, in *IngressHealth) { s.Storage.Pinned = 1 },
		func(s *LedgerStatus, in *IngressHealth) { s.Storage.RecoveryRoom = 0 },
		func(s *LedgerStatus, in *IngressHealth) { s.Outbox.AuditBytes = RecoveryReserveBytes },
	} {
		s, in := healthyStatus(), &IngressHealth{Admitting: true}
		change(s, in)
		want := baselineDoctorChecks(s, in, t0)
		if got := DoctorChecks(s, in, t0, false); !reflect.DeepEqual(got, want) {
			t.Fatalf("preview bytes changed: got %+v, want %+v", got, want)
		}
		for i := range want {
			r := &want[i]
			r.Message = strings.ReplaceAll(r.Message, PreviewUnaffected, ExecutionAffected)
			r.Message = strings.ReplaceAll(r.Message, "would not have received", "did not receive")
			r.Fix = strings.ReplaceAll(r.Fix, "previews are refused", "automatic blocks are refused")
			r.Fix = strings.ReplaceAll(r.Fix, ", which existing blocking still uses", "")
			if r.Status == DoctorWarn && (r.Name == "admission ledger" || r.Name == "admission response gaps" || (r.Name == "admission ingress" && !in.Admitting)) {
				r.Status = DoctorFail
			}
		}
		if got := DoctorChecks(s, in, t0, true); !reflect.DeepEqual(got, want) {
			t.Fatalf("executing rows = %+v, want %+v", got, want)
		}
	}
}
