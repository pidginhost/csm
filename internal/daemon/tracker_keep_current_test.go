package daemon

import (
	"fmt"
	"testing"
	"time"
)

// Ranking established good-source standing above ordinary active failures
// keeps a fresh-IP flood from evicting a legitimate client, but it also
// outranks the source a Record is accumulating into. Evicting that entry
// resets its counter on every call, so a single attacker can never reach
// its threshold while the table is full: detection switches off for exactly
// the source causing the pressure. The entry the caller just wrote is
// therefore never a victim of its own bookkeeping.
func TestMailTrackerNeverEvictsTheEntryBeingWritten(t *testing.T) {
	clock := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	const maxTracked = 8
	tr := newMailAuthTracker(3, 50, 50, 10*time.Minute, 60*time.Minute, 0, 0, maxTracked, func() time.Time { return clock })

	// Fill the table with good sources, each of which outranks a plain
	// failure entry.
	for i := 0; i < maxTracked; i++ {
		tr.RecordSuccess(fmt.Sprintf("198.51.100.%d", i+1), fmt.Sprintf("u%d@example.com", i))
		clock = clock.Add(time.Millisecond)
	}

	fired := false
	for i := 0; i < 3; i++ {
		clock = clock.Add(time.Second)
		for _, f := range tr.Record("203.0.113.7", "victim@example.com") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatal("attacker entry was evicted between its own failures, so the threshold was never reached")
	}
}

func TestSMTPTrackerNeverEvictsTheEntryBeingWritten(t *testing.T) {
	clock := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	const maxTracked = 8
	tr := newSMTPAuthTracker(3, 50, 50, 10*time.Minute, 60*time.Minute, 0, 0, maxTracked, func() time.Time { return clock })

	for i := 0; i < maxTracked; i++ {
		tr.RecordSuccess(fmt.Sprintf("198.51.100.%d", i+1))
		clock = clock.Add(time.Millisecond)
	}

	fired := false
	for i := 0; i < 3; i++ {
		clock = clock.Add(time.Second)
		for _, f := range tr.Record("203.0.113.8", "victim@example.com") {
			if f.Check == "smtp_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatal("attacker entry was evicted between its own failures, so the threshold was never reached")
	}
}
