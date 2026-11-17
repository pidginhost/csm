package main

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/health"
)

// The unresolved-outcomes row names what keeps unknown outcomes from
// retiring, and its fix, instead of a retire time that cannot come. With
// nothing named, the ledger's own row is kept.
func TestDoctorNamesWhatHoldsRetirement(t *testing.T) {
	at := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	retires := at.Add(-time.Hour).UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		by, message, fix string
		executing        bool
	}{
		{"engine", "2 automatic blocks have an unproven outcome and stay unresolved until the firewall engine can prove them; their addresses stay held; " + admission.PreviewUnaffected,
			"enable the firewall (firewall.enabled true, mode not observe) and restart csm.service; each block then retires once it has expired and the firewall shows nothing of it", false},
		{"policy", "2 automatic blocks have an unproven outcome and stay unresolved while the execution policy is refused; their addresses stay held; " + admission.ExecutionAffected,
			"correct the setting the admission execution row names; each block then retires once it has expired and the firewall shows nothing of it", true},
		{"", "", "", false},
	} {
		ledger := &admission.LedgerStatus{
			Storage:    admission.StorageStatus{RecoveryRoom: admission.RecoveryReserveBytes},
			Unresolved: admission.UnresolvedStatus{Unknown: 2, Retires: at.Add(-time.Hour)},
		}
		a := &health.AdmissionStatus{CheckedAt: at, Ledger: ledger, Owner: &health.AdmissionOwner{Executing: tc.executing, Settled: true, RetirementHeldBy: tc.by}}
		got, ok := doctorCheckNamed(DoctorReport{Checks: admissionDoctorChecks(a, at.Add(-time.Hour))}, "admission unresolved outcomes")
		if !ok || got.Status != "warn" {
			t.Fatalf("held by %q: row = %+v", tc.by, got)
		}
		if tc.by == "" {
			if !strings.Contains(got.Message, retires) || !strings.HasPrefix(got.Fix, "none needed while the count falls") {
				t.Errorf("nothing named: row = %+v, want the ledger's row", got)
			}
			continue
		}
		if got.Message != tc.message || got.Fix != tc.fix || strings.Contains(got.Message, retires) {
			t.Errorf("held by %q: row = %+v", tc.by, got)
		}
	}
}
