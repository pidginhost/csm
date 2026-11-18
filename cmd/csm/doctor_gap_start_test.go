package main

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/health"
)

// A Critical gap an executing owner recorded before this daemon started
// warns instead of failing: a flood of the hourly ceiling could otherwise
// fail the check that follows every deploy or restart for an hour. A gap
// recorded by the running daemon still fails.
func TestDoctorGapBeforeStartWarns(t *testing.T) {
	at := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	start := at.Add(-10 * time.Minute)
	for _, tc := range []struct {
		name      string
		checked   time.Time
		started   time.Time
		gap       time.Time
		executing bool
		status    string
		note      bool
	}{
		{"before start", at, start, start.Add(-time.Second), true, "warn", true},
		{"at start", at, start, start, true, "fail", false},
		{"after start", at, start, start.Add(time.Minute), true, "fail", false},
		{"preview before start", at, start, start.Add(-time.Second), false, "warn", false},
		// A snapshot without a start time cannot place the gap.
		{"unknown start", at, time.Time{}, start.Add(-time.Second), true, "fail", false},
		// Nor can one whose start follows its check: the clock stepped back.
		{"start after the check", at, at.Add(time.Minute), at.Add(-time.Second), true, "fail", false},
		{"unknown check time", time.Time{}, start, start.Add(-time.Second), true, "fail", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := &admission.LedgerStatus{
				Storage: admission.StorageStatus{RecoveryRoom: admission.RecoveryReserveBytes},
				Notices: admission.NoticesStatus{LastCriticalGap: tc.gap},
			}
			a := &health.AdmissionStatus{CheckedAt: tc.checked, Ledger: ledger, Owner: &health.AdmissionOwner{Executing: tc.executing, Settled: true}}
			got, ok := doctorCheckNamed(DoctorReport{Checks: admissionDoctorChecks(a, tc.started)}, admission.ResponseGapsRow)
			if !ok || got.Status != tc.status {
				t.Fatalf("gap row = %+v, want %s", got, tc.status)
			}
			const note = "recorded before the daemon started"
			if strings.Contains(got.Message, note) != tc.note {
				t.Errorf("gap row message = %q, before-start note %v", got.Message, tc.note)
			}
			if tc.note && !strings.Contains(got.Message, note+" at "+tc.started.Format(time.RFC3339)) {
				t.Errorf("gap row message = %q, want the start time", got.Message)
			}
			if !strings.Contains(got.Message, tc.gap.Format(time.RFC3339)) {
				t.Errorf("gap row lost the gap time: %q", got.Message)
			}
		})
	}
}
