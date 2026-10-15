package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A failed attempt can leave its firewall row behind a failed restore
// write. Its history stays until the row's expiry, so startup still knows
// the action while that row could be restored; a preview, which writes no
// row, keeps only the review window. The storage proof accepts both.
func TestAdmissionLedgerKeepsRowHistoryUntilExpiry(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	lifetime := 30 * 24 * time.Hour
	id, a := f.admitted(lifetime)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	ended, err := f.l.Terminate(id, admission.ReasonProtected)
	if err != nil {
		t.Fatal(err)
	}
	h, found := f.historyEntry(id)
	if !found || !h.Eligible.Equal(ended.ExpiresAt) {
		t.Fatalf("failed history eligible at %v, want the row's expiry %v", h.Eligible, ended.ExpiresAt)
	}
	f.nextGeneration()
	observed, _ := f.observedArrival("192.0.2.40", "offset=retention")
	p, found := f.historyEntry(observed)
	if !found || !p.Eligible.Equal(p.Ended.Add(admission.HistoryRetention)) {
		t.Fatalf("preview history eligible at %v, want the review window", p.Eligible)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("kept history does not prove its storage: %v", err)
	}
	// An entry ended before this rule keeps its review-window time and
	// still proves; any other time does not.
	for _, tc := range []struct {
		eligible time.Time
		ok       bool
	}{
		{h.Ended.Add(admission.HistoryRetention), true},
		{h.Ended.Add(admission.HistoryRetention + time.Hour), false},
	} {
		old := h
		old.Eligible = tc.eligible
		if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putHistoryEntry(tx, id, old) }); err != nil {
			t.Fatal(err)
		}
		if _, err = OpenAdmissionLedger(f.db, f.reg); (err == nil) != tc.ok {
			t.Fatalf("history eligible at %v: open error %v, want ok=%t", tc.eligible, err, tc.ok)
		}
	}
}

// A live failed row and a pinned unknown must remain identifiable even
// after the normal history target. At expiry both histories can retire.
func TestAdmissionLedgerRowHistoryRetiresAtExpiry(t *testing.T) {
	for _, outcome := range []admission.Disposition{admission.DispositionFailed, admission.DispositionUnknown} {
		t.Run(outcome.String(), func(t *testing.T) {
			f := newLedgerFixture(t)
			id, a := f.admitted(40 * 24 * time.Hour)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.l.Finish(a.Attempt.ID, outcome); err != nil {
				t.Fatal(err)
			}
			if outcome == admission.DispositionFailed {
				if _, err := f.l.Terminate(id, admission.ReasonProtected); err != nil {
					t.Fatal(err)
				}
			}
			f.ackAll()
			f.tickAt(a.ExpiresAt.Add(-time.Nanosecond))
			ids := []string{string(a.Attempt.ID)}
			if got, err := ReadUnprovenBlockActions(f.db, ids); err != nil || len(got) != 1 || got[0] != ids[0] {
				t.Fatalf("live row lost its history: %v, %v", got, err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("live history cannot reopen: %v", err)
			}
			f.tickAt(a.ExpiresAt)
			if outcome == admission.DispositionUnknown {
				if _, _, granted, err := f.l.RetireUnproven(a.Attempt.ID); err != nil || !granted {
					t.Fatalf("retire = %t, %v", granted, err)
				}
				h, found := f.historyEntry(id)
				if !found || h.Pinned || !h.Eligible.Equal(a.ExpiresAt) {
					t.Fatalf("retired unknown history = %+v, found %t", h, found)
				}
				f.ackAll()
				f.tickAt(a.ExpiresAt.Add(time.Second))
			}
			if _, err := f.l.Candidate(id); err != errCandidateMissing {
				t.Fatalf("expired history stayed: %v", err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("retired history cannot reopen: %v", err)
			}
		})
	}
}

// Earlier retired unknowns keep the eligibility that was written at the
// time. Opening must accept it without moving the history index.
func TestAdmissionLedgerOpensEarlierRetiredUnknownHistory(t *testing.T) {
	f := newLedgerFixture(t)
	u := f.unknownAt("192.0.2.82", ledgerT0.Add(40*24*time.Hour))
	f.ackAll()
	f.tickAt(u.ExpiresAt)
	if _, _, granted, err := f.l.RetireUnproven(u.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire = %t, %v", granted, err)
	}
	h, found := f.historyEntry(u.Attempt.Candidate)
	if !found {
		t.Fatal("retired unknown lost its history before audit delivery")
	}
	h.Eligible = h.Ended.Add(admission.HistoryRetention)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putHistoryEntry(tx, u.Attempt.Candidate, h) }); err != nil {
		t.Fatal(err)
	}
	f.ackAll()
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("earlier retired unknown rejected: %v", err)
	}
	got, found := f.historyEntry(u.Attempt.Candidate)
	if !found || got != h {
		t.Fatalf("open rewrote earlier history: %+v, want %+v", got, h)
	}
}

// Retiring failed or unknown history cannot mint the same action again.
// Its saved clock also remains an expiry floor after a wall rollback.
func TestAdmissionLedgerRetiredRowActionCannotRepeat(t *testing.T) {
	for _, outcome := range []admission.Disposition{admission.DispositionFailed, admission.DispositionUnknown} {
		t.Run(outcome.String(), func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=retired-row"}))[0].Candidate
			_, a, _, err := f.l.Reserve(first, admission.LaneGeneral, f.wall.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.Finish(a.Attempt.ID, outcome); err != nil {
				t.Fatal(err)
			}
			if outcome == admission.DispositionFailed {
				if _, err = f.l.Terminate(first, admission.ReasonProtected); err != nil {
					t.Fatal(err)
				}
			}
			f.ackAll()
			f.tickAt(a.ExpiresAt)
			if outcome == admission.DispositionUnknown {
				if _, _, granted, retireErr := f.l.RetireUnproven(a.Attempt.ID); retireErr != nil || !granted {
					t.Fatalf("retire = %t, %v", granted, retireErr)
				}
				f.ackAll()
			}
			f.tickAt(ledgerT0.Add(admission.HistoryTarget + time.Hour))
			if _, err = f.l.Candidate(first); err != errCandidateMissing {
				t.Fatalf("history did not retire: %v", err)
			}
			if tick, tickErr := f.l.Tick(admission.ClockReading{Wall: ledgerT0, BootID: ledgerBoot, SinceBoot: f.since}); tickErr != nil || !tick.Degraded {
				t.Fatalf("rollback = %+v, %v", tick, tickErr)
			}
			floor, clockErr := ReadAdmissionClock(f.db)
			if clockErr != nil || floor.Now().Before(a.ExpiresAt) {
				t.Fatalf("forgotten row lost its expiry floor: %v, %v", floor.Now(), clockErr)
			}
			if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatal(err)
			}
			f.tickAt(ledgerT0.Add(admission.HistoryTarget + 2*time.Hour))
			f.tickAt(f.wall)
			again := f.arrive(f.arrival(evidenceSpec{cursor: "offset=after-retirement"}))[0]
			if again.Err != nil || !again.Created || again.Candidate == first {
				t.Fatalf("new arrival reused candidate: %+v", again)
			}
			_, next, granted, reserveErr := f.l.Reserve(again.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour))
			if reserveErr != nil || !granted || next.Attempt.ID == a.Attempt.ID {
				t.Fatalf("new arrival reused action: %+v, %t, %v", next, granted, reserveErr)
			}
		})
	}
}

// A candidate whose live attempt failed can be previewed on its retry, for
// instance after execution is switched off. It then ends observed, but the
// failed attempt's row can still be on disk, so its history stays until
// that row's expiry, including after a schema upgrade. Earlier history
// keeps its stored review window; other retirement times are corruption.
func TestAdmissionLedgerPreviewAfterAFailedAttemptKeepsRowHistory(t *testing.T) {
	for _, mode := range []string{"current", "schema three", "earlier history", "invalid time"} {
		t.Run(mode, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			id, a := f.admitted(40 * 24 * time.Hour)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			queued, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
			if err != nil || queued.State != admission.StateQueued {
				t.Fatalf("failed attempt requeued = %+v, %v", queued, err)
			}
			f.tickAt(queued.NotBefore)
			c, preview, granted, err := f.l.Observe(id, admission.LaneGeneral, time.Time{})
			if err != nil || !granted || c.State != admission.StateObserved || c.Attempts != 2 || !c.ExpiresAt.Equal(a.ExpiresAt) || !preview.ExpiresAt.Equal(a.ExpiresAt) {
				t.Fatalf("preview of the retry = %+v, %+v, %t, %v", c, preview, granted, err)
			}
			eligible, target := a.ExpiresAt, a.ExpiresAt
			if mode == "earlier history" || mode == "invalid time" {
				h, found := f.historyEntry(id)
				if !found {
					t.Fatal("previewed retry lost its history")
				}
				eligible, target = h.Ended.Add(admission.HistoryRetention), h.Ended.Add(admission.HistoryTarget)
				h.Eligible = eligible
				if mode == "invalid time" {
					h.Eligible = h.Eligible.Add(time.Hour)
				}
				// No retirement keys exist while the audit rows are pending.
				if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putHistoryEntry(tx, id, h) }); err != nil {
					t.Fatal(err)
				}
			}
			f.ackAll()
			if mode == "schema three" {
				f.schemaThree()
				if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
					t.Fatalf("previewed retry cannot upgrade: %v", err)
				}
			}
			before := f.snapshot()
			reopened, err := OpenAdmissionLedger(f.db, f.reg)
			if !reflect.DeepEqual(f.snapshot(), before) {
				t.Fatal("opening changed stored history or its retirement index")
			}
			if mode == "invalid time" {
				if !isCorrupt(err) {
					t.Fatalf("invalid retirement time opened: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("kept history does not prove its storage: %v", err)
			}
			f.l = reopened
			h, found := f.historyEntry(id)
			if !found || !h.Eligible.Equal(eligible) || !h.Target().Equal(target) {
				t.Fatalf("history = %+v, want eligibility %v and target %v", h, eligible, target)
			}
			f.tickAt(target.Add(-time.Nanosecond))
			ids := []string{string(a.Attempt.ID), string(preview.Attempt.ID)}
			if got, readErr := ReadSettledBlockActions(f.db, ids); readErr != nil || !reflect.DeepEqual(got, ids[:1]) {
				t.Fatalf("failed row lost its history before retirement: %v, %v", got, readErr)
			}
			f.tickAt(target)
			if _, err = f.l.Candidate(id); err != errCandidateMissing {
				t.Fatalf("history did not retire at its target: %v", err)
			}
			for _, attempt := range []admission.AttemptRecord{a, preview} {
				if _, err = f.l.Attempt(attempt.Attempt.ID); err == nil {
					t.Fatalf("retired history kept attempt %s", attempt.Attempt.ID)
				}
			}
			if _, found = f.historyEntry(id); found || len(retireKeysIn(t, f.db)) != 0 {
				t.Fatal("retired history kept its entry or index")
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("retired history cannot reopen: %v", err)
			}
		})
	}
}
