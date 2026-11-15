package main

import (
	"testing"
	"time"
)

// Missing or future start times cannot extend a startup grace indefinitely.
func TestAdmissionSettleGraceWindow(t *testing.T) {
	now := time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		started time.Time
		want    bool
	}{
		{"zero", time.Time{}, false},
		{"future", now.Add(time.Nanosecond), false},
		{"start", now, true},
		{"before deadline", now.Add(-admissionSettleGrace + time.Nanosecond), true},
		{"deadline", now.Add(-admissionSettleGrace), false},
		{"past deadline", now.Add(-admissionSettleGrace - time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := admissionWithinSettleGrace(tc.started, now); got != tc.want {
				t.Fatalf("grace = %t, want %t", got, tc.want)
			}
		})
	}
}
