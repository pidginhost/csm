package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// unknownAt runs a candidate at target and ends its attempt unknown; the
// attempt expires at expires.
func (f *ledgerFixture) unknownAt(target string, expires time.Time) admission.AttemptRecord {
	f.t.Helper()
	a := f.reservedAt(target, expires)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, done, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		f.t.Fatal(err)
	} else {
		a = done
	}
	return a
}

// An unknown outcome holds the slot of the row that will retire it.
func TestAdmissionLedgerUnknownHoldsItsRetirementRow(t *testing.T) {
	f := newLedgerFixture(t)
	f.unknownAt("192.0.2.10", ledgerT0.Add(time.Hour))
	if rows := f.pendingAudit(); len(rows) != 3 || f.storageState().AuditSlots != 4 {
		t.Fatalf("rows %d, slots %d", len(rows), f.storageState().AuditSlots)
	}
	f.ackAll()
	if slots := f.storageState().AuditSlots; slots != 1 {
		t.Fatalf("slots after delivery = %d", slots)
	}
}

// Once its expiry has passed on a trusted clock, an unknown attempt's
// uncertainty is retired: the outcome stays unknown and counts as nothing
// new, the intent goes, the history and intent leave the recovery reserve
// for the allowance, and the expired_unproven row records the event in the
// slot the outcome held. Again it is a no-op.
func TestAdmissionLedgerRetiresAnExpiredUnknownAttempt(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	u := f.unknownAt("192.0.2.10", expires)
	f.ackAll()
	before := f.snapshot()
	_, _, _, err := f.l.RetireUnproven(u.Attempt.ID)
	wantLedgerErr(t, "before expiry", err, admission.ErrNotReady)
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a refused retirement changed the ledger")
	}
	f.tickAt(expires)
	cost := uint64(f.cost(u.Attempt.Candidate))
	storage := f.storageState()
	outcomes := f.l.Status().Outcomes
	c, a, granted, err := f.l.RetireUnproven(u.Attempt.ID)
	if err != nil || !granted {
		t.Fatalf("retire: %v %v", granted, err)
	}
	if a.State != admission.StateUnknown || a.Disposition != admission.DispositionUnknown || !a.Retired || a.Finished != u.Finished {
		t.Fatalf("attempt = %+v", a)
	}
	if c.State != admission.StateUnknown || c.Disposition != admission.DispositionUnknown {
		t.Fatalf("candidate = %+v", c)
	}
	if len(f.intents()) != 0 {
		t.Fatalf("intents = %+v", f.intents())
	}
	got := f.storageState()
	want := storage
	want.Recovery -= cost + admission.MaxIntentBytes
	want.General.Used += cost
	if got != want {
		t.Fatalf("storage = %+v\nwant %+v", got, want)
	}
	if h, found := f.historyEntry(u.Attempt.Candidate); !found || h.Pinned || !h.Eligible.Equal(u.Finished.Add(admission.HistoryRetention)) {
		t.Fatalf("history = %+v, %v", h, found)
	}
	rows := f.pendingAudit()
	if len(rows) != 1 || rows[0].State != admission.StateUnknown || rows[0].Disposition != admission.DispositionExpiredUnproven ||
		!rows[0].At.Equal(expires) || rows[0].Transition != c.Transitions {
		t.Fatalf("rows = %+v", rows)
	}
	if after := f.l.Status().Outcomes; !reflect.DeepEqual(after, outcomes) {
		t.Fatalf("outcomes %+v -> %+v", outcomes, after)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	if _, _, granted, err = f.l.RetireUnproven(u.Attempt.ID); err != nil || granted {
		t.Fatalf("again: %v %v", granted, err)
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a repeated retirement changed the ledger")
	}
	f.ackAll()
	if slots := f.storageState().AuditSlots; slots != 0 {
		t.Fatalf("slots after the retirement row = %d", slots)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// Only an unknown attempt past its expiry, on a current and trusted clock,
// can be retired.
func TestAdmissionLedgerRetirementRefusals(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	running := f.reservedAt("192.0.2.10", expires)
	applied := f.reservedAt("192.0.2.11", expires)
	for _, a := range []admission.AttemptRecord{running, applied} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.l.Finish(applied.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	u := f.unknownAt("192.0.2.12", expires)
	f.tickAt(expires)
	before := f.snapshot()
	_, _, _, err := f.l.RetireUnproven(u.Attempt.ID)
	wantLedgerErr(t, "undelivered outcome", err, admission.ErrNotReady)
	for name, a := range map[string]admission.AttemptRecord{"running": running, "applied": applied} {
		_, _, _, err = f.l.RetireUnproven(a.Attempt.ID)
		wantLedgerErr(t, name, err, admission.ErrTransitionConflict)
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a refused retirement changed the ledger")
	}
	f.ackAll()
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = l.RetireUnproven(u.Attempt.ID)
	wantLedgerReason(t, "no current reading", err, admission.ReasonEngineUnavailable)
	// The wall moves a minute further than the elapsed time.
	f.wall, f.since = f.wall.Add(time.Hour+time.Minute), f.since+time.Hour
	if tick, tickErr := f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerBoot, SinceBoot: f.since}); tickErr != nil || !tick.Degraded {
		t.Fatalf("tick = %+v, %v", tick, tickErr)
	}
	before = f.snapshot()
	_, _, _, err = f.l.RetireUnproven(u.Attempt.ID)
	wantLedgerReason(t, "degraded clock", err, admission.ReasonEngineUnavailable)
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a refused retirement changed the ledger")
	}
}

// Opening proves a retirement against its records: a retired attempt has
// no intent, no pinned history and no future row, and its row cannot be
// dated before the expiry; an unretired unknown keeps its slot.
func TestAdmissionLedgerOpenProvesRetirement(t *testing.T) {
	expires := ledgerT0.Add(time.Hour)
	setup := func(t *testing.T, retire bool) (*ledgerFixture, admission.AttemptRecord) {
		f := newLedgerFixture(t)
		u := f.unknownAt("192.0.2.10", expires)
		f.ackAll()
		f.tickAt(expires)
		if retire {
			if _, _, _, err := f.l.RetireUnproven(u.Attempt.ID); err != nil {
				t.Fatal(err)
			}
		}
		return f, u
	}
	for name, tc := range map[string]struct {
		retire bool
		damage func(*testing.T, *bolt.Tx, admission.AttemptRecord) error
	}{
		"retired attempt keeps its intent": {true, func(_ *testing.T, tx *bolt.Tx, u admission.AttemptRecord) error {
			c, err := loadCandidate(tx, u.Attempt.Candidate)
			if err != nil {
				return err
			}
			return putIntent(tx, admission.Intent{Action: u.Attempt.ID, Batch: batchOfID(u.Attempt.ID), Kind: c.Key.Kind, Target: c.Key.Target, ExpiresAt: u.ExpiresAt})
		}},
		"retired attempt stays pinned": {true, func(_ *testing.T, tx *bolt.Tx, u admission.AttemptRecord) error {
			h, _, err := loadHistoryEntry(tx, u.Attempt.Candidate)
			if err != nil {
				return err
			}
			h.Pinned, h.Eligible = true, time.Time{}
			if err = tx.Bucket([]byte(admissionHistoryBucket)).Put([]byte(u.Attempt.Candidate), mustEncode(h)); err != nil {
				return err
			}
			return adjustStorage(tx, func(s *admission.StorageState) {
				s.Recovery += uint64(h.Charged()) + admission.MaxIntentBytes
				s.General.Used -= uint64(h.General)
			})
		}},
		"retirement row before the expiry": {true, func(_ *testing.T, tx *bolt.Tx, u admission.AttemptRecord) error {
			return rewriteRow(tx, u.Attempt.ID, func(r *admission.AuditRow) { r.At = u.Finished })
		}},
		"retirement row of an unretired attempt": {true, func(_ *testing.T, tx *bolt.Tx, u admission.AttemptRecord) error {
			a, err := loadAttempt(tx, u.Attempt.ID)
			if err != nil {
				return err
			}
			a.Retired = false
			return putAttempt(tx, a)
		}},
		"unknown without its retirement slot": {false, func(_ *testing.T, tx *bolt.Tx, _ admission.AttemptRecord) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.AuditSlots-- })
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f, u := setup(t, tc.retire)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return tc.damage(t, tx, u) }); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("open = %v", err)
			}
		})
	}
}

func batchOfID(id admission.ActionID) admission.BatchID {
	b, err := admission.NewBatchID([]admission.ActionID{id})
	if err != nil {
		panic(err)
	}
	return b
}

func mustEncode(v interface{ MarshalBinary() ([]byte, error) }) []byte {
	data, err := v.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return data
}

// rewriteRow replaces the last pending audit row of attempt id.
func rewriteRow(tx *bolt.Tx, id admission.ActionID, edit func(*admission.AuditRow)) error {
	outbox := tx.Bucket([]byte(admissionOutboxBucket))
	prefix := admission.AuditPrefix(id)
	var last admission.AuditRow
	var key []byte
	cur := outbox.Cursor()
	for k, v := cur.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = cur.Next() {
		r, err := admission.UnmarshalAuditRow(v)
		if err != nil {
			return err
		}
		last, key = r, append([]byte(nil), k...)
	}
	edit(&last)
	data, err := last.MarshalBinary()
	if err != nil {
		return err
	}
	return outbox.Put(key, data)
}

// Status counts the attempts whose outcome is unresolved, running or
// unknown, and says when the first unknown one can be retired. A damaged
// intent fails only this section.
func TestAdmissionLedgerStatusCountsUnresolvedAttempts(t *testing.T) {
	f := newLedgerFixture(t)
	if s := f.l.Status().Unresolved; s != (admission.UnresolvedStatus{}) {
		t.Fatalf("empty ledger = %+v", s)
	}
	early, late := ledgerT0.Add(time.Hour), ledgerT0.Add(2*time.Hour)
	running := f.reservedAt("192.0.2.10", ledgerT0.Add(30*time.Minute))
	if _, _, _, err := f.l.Execute(running.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	f.unknownAt("192.0.2.11", late)
	f.unknownAt("192.0.2.12", early)
	retired := f.unknownAt("192.0.2.13", ledgerT0.Add(time.Minute))
	f.ackAll()
	f.tickAt(ledgerT0.Add(time.Minute))
	if _, _, _, err := f.l.RetireUnproven(retired.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	want := admission.UnresolvedStatus{Running: 1, Unknown: 2, Retires: early}
	if s := f.l.Status().Unresolved; s != want {
		t.Fatalf("unresolved = %+v, want %+v", s, want)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(running.Attempt.ID), []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	s := f.l.Status()
	if s.Unresolved.Error == "" || s.Queue.Error != "" || s.Storage.Error != "" {
		t.Fatalf("damaged intent: %+v %q %q", s.Unresolved, s.Queue.Error, s.Storage.Error)
	}
}

// I2: after an unknown outcome the target answers its kind without
// extending the episode, however long the attack lasts, until recovery
// retires the outcome; the next observation then opens a new episode with
// a new candidate.
func TestAdmissionLedgerUnknownLineHoldsItsEpisode(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0]
	expires := f.wall.Add(time.Hour)
	_, a, _, err := f.l.Reserve(first.Candidate, admission.LaneGeneral, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	held, _ := f.episodeAt("192.0.2.10")
	f.tickAt(ledgerT0.Add(3 * admission.EpisodeQuiet))
	in := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	wantLedgerReason(t, "unresolved outcome", in.Err, admission.ReasonExistingEffect)
	if row, _ := f.episodeAt("192.0.2.10"); !reflect.DeepEqual(row, held) {
		t.Fatalf("an answered observation changed the episode: %+v -> %+v", held, row)
	}
	f.ackAll()
	if _, _, _, err = f.l.RetireUnproven(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Minute))
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3"}))[0]
	if next.Err != nil {
		t.Fatalf("after retirement: %v", next.Err)
	}
	if c := f.candidateOf(next.Candidate); c.Key.Episode == held.ID || c.Key.Generation != 1 || c.State != admission.StateQueued {
		t.Fatalf("after retirement: %+v", c)
	}
}

// I2: once a candidate's last attempt has failed, a later observation of
// the same episode starts its next generation instead of being answered,
// and so does one after the failed candidate's details are retired while
// another kind keeps the episode row.
func TestAdmissionLedgerFailedLineStartsTheNextGeneration(t *testing.T) {
	failed := func(t *testing.T) (*ledgerFixture, admission.CandidateID) {
		f := newLedgerFixture(t)
		f.begin()
		first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
		expires := f.wall.Add(admission.HistoryTarget)
		for seq := uint32(1); seq <= admission.MaxAttempts; seq++ {
			_, a, _, err := f.l.Reserve(first, admission.LaneGeneral, expires)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
				t.Fatal(err)
			}
			f.tickAt(f.wall.Add(admission.RetryBackoff(seq)))
		}
		if c := f.candidateOf(first); c.State != admission.StateFailed {
			t.Fatalf("candidate = %+v", c)
		}
		return f, first
	}
	t.Run("live", func(t *testing.T) {
		f, first := failed(t)
		episode := f.candidateOf(first).Key.Episode
		next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
		if c := f.candidateOf(next.Candidate); next.Err != nil || c.Key.Episode != episode || c.Key.Generation != 2 {
			t.Fatalf("after a final failure: %+v %+v", next, c.Key)
		}
	})
	t.Run("retired", func(t *testing.T) {
		f, first := failed(t)
		episode := f.candidateOf(first).Key.Episode
		other := f.arrival(evidenceSpec{cursor: "promotion"})
		other.Request.Kind = admission.KindPromote
		kept := f.arrive(other)[0].Candidate
		if _, _, _, err := f.l.Reserve(kept, admission.LaneGeneral, f.wall.Add(2*admission.HistoryTarget)); err != nil {
			t.Fatal(err)
		}
		f.ackAll()
		f.tickAt(f.wall.Add(admission.HistoryTarget + time.Hour))
		if _, err := f.l.Candidate(first); err != errCandidateMissing {
			t.Fatalf("the failed candidate was not retired: %v", err)
		}
		row, ok := f.episodeAt("192.0.2.10")
		if line, found := row.Line(admission.KindBlockIP); !ok || !found || line.Candidate != "" || line.Answered {
			t.Fatalf("retired failure: %+v", row)
		}
		again := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3"}))[0]
		if c := f.candidateOf(again.Candidate); again.Err != nil || c.Key.Episode != episode || c.Key.Generation != 2 {
			t.Fatalf("after the failure was retired: %+v %+v", again, c.Key)
		}
	})
}
