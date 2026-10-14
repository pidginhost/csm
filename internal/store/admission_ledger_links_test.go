package store

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) schema() byte {
	f.t.Helper()
	var schema []byte
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		schema = append(schema, tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey)...)
		return nil
	}); err != nil || len(schema) != 1 {
		f.t.Fatalf("schema = %v, %v", schema, err)
	}
	return schema[0]
}

func testLink(prefix string, expires time.Time) admission.EffectLink {
	return admission.EffectLink{Effect: prefix + strings.Repeat("0123456789abcdef", 2), ExpiresAt: expires}
}

// A pick refused before any reservation records the block that already
// enforces it. The first linked record moves the ledger to schema 8, which
// older builds refuse; until then the schema stays 7.
func TestAdmissionLedgerTerminateExistingLinksAPick(t *testing.T) {
	f := newLedgerFixture(t)
	if _, err := f.l.Terminate(f.queued(), admission.ReasonExistingEffect); err != nil {
		t.Fatal(err)
	}
	if got := f.schema(); got != admissionSchemaVersion {
		t.Fatalf("an unlinked ending wrote schema %d", got)
	}
	f.nextGeneration()
	id := f.queued()
	link := testLink("eff_", time.Time{})
	beforeStorage := f.storageState()
	c, err := f.l.TerminateExisting(id, link)
	if err != nil || c.State != admission.StateRefused || c.Reason != admission.ReasonExistingEffect || c.Link != link {
		t.Fatalf("TerminateExisting = %+v, %v", c, err)
	}
	if got := f.schema(); got != admissionSchemaLinked {
		t.Fatalf("schema after a linked ending = %d, want %d", got, admissionSchemaLinked)
	}
	afterStorage := f.storageState()
	if afterStorage.General != beforeStorage.General || afterStorage.Reserved != beforeStorage.Reserved || afterStorage.Ended.Count != beforeStorage.Ended.Count+1 {
		t.Fatalf("unadmitted link did not use only the ended ring: %+v -> %+v", beforeStorage, afterStorage)
	}
	again, err := f.l.TerminateExisting(id, link)
	if err != nil || again.Transitions != c.Transitions {
		t.Fatalf("repeat = %+v, %v; want the same ending unchanged", again, err)
	}
	if _, err = f.l.TerminateExisting(id, testLink("act_", f.wall.Add(time.Hour))); err != admission.ErrCandidateTerminal {
		t.Fatalf("another link = %v, want ErrCandidateTerminal", err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := reopened.Candidate(id); err != nil || !reflect.DeepEqual(back, c) {
		t.Fatalf("reopened = %+v, %v; want %+v", back, err, c)
	}
	if _, err := ReadAdmissionClock(f.db); err != nil {
		t.Fatalf("a read without a handle refused schema 8: %v", err)
	}
}

// A block found when the batch applies ends the attempt failed, keeping
// its charge, and the pick refused with its link, in one transaction. The
// history pays for the link, so the ledger still proves its storage, and a
// repeat changes nothing.
func TestAdmissionLedgerFinishExistingEndsAttemptAndPick(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	before, err := f.l.Candidate(id)
	if err != nil {
		t.Fatal(err)
	}
	link := testLink("act_", f.wall.Add(2*time.Hour))
	c, done, err := f.l.FinishExisting(a.Attempt.ID, link)
	if err != nil || done.State != admission.StateFailed || c.State != admission.StateRefused || c.Reason != admission.ReasonExistingEffect || c.Link != link || c.Attempts != 1 || c.Transitions != before.Transitions+2 {
		t.Fatalf("FinishExisting = %+v, %+v, %v", c, done, err)
	}
	rows := f.pendingAudit()
	if last := rows[len(rows)-1]; last.Attempt.ID != a.Attempt.ID || last.State != admission.StateFailed {
		t.Fatalf("last audit row = %+v, want the failed outcome", last)
	}
	again, _, err := f.l.FinishExisting(a.Attempt.ID, link)
	if err != nil || again.Transitions != c.Transitions {
		t.Fatalf("repeat = %+v, %v; want no change", again, err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("linked history does not prove its storage: %v", err)
	}
}

// The last attempt has no retry left: the pick stays failed and no link
// or schema change is written.
func TestAdmissionLedgerFinishExistingOnTheLastAttempt(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.retried(admission.MaxAttempts)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	c, done, err := f.l.FinishExisting(a.Attempt.ID, testLink("act_", f.wall.Add(2*time.Hour)))
	if err != nil || done.State != admission.StateFailed || c.State != admission.StateFailed || c.Link != (admission.EffectLink{}) {
		t.Fatalf("FinishExisting = %+v, %+v, %v; want the pick failed without a link", c, done, err)
	}
	if got := f.schema(); got != admissionSchemaVersion {
		t.Fatalf("schema = %d, want %d", got, admissionSchemaVersion)
	}
}

// With no history room for the link nothing is written: the attempt keeps
// running and the caller can still finish it failed.
func TestAdmissionLedgerFinishExistingNeedsRoomForTheLink(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	general, _ := admission.HistoryLanes()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		s, err := loadStorageState(tx)
		if err != nil {
			return err
		}
		s.General.Used = general
		return putStorageState(tx, s)
	}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if _, _, err := f.l.FinishExisting(a.Attempt.ID, testLink("act_", f.wall.Add(2*time.Hour))); err == nil {
		t.Fatal("a link was written without history room")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused link changed records")
	}
	if c, done, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil || done.State != admission.StateFailed || c.State != admission.StateQueued {
		t.Fatalf("Finish = %+v, %+v, %v", c, done, err)
	}
	if c, err := f.l.Candidate(id); err != nil || c.Link != (admission.EffectLink{}) {
		t.Fatalf("candidate = %+v, %v", c, err)
	}
}

// Only the current attempt can link a pick. A delayed outcome from its
// predecessor must not terminate the queued retry or acknowledge its link.
func TestAdmissionLedgerFinishExistingRejectsHistoricalAttempts(t *testing.T) {
	for _, state := range []string{"queued", "reserved", "executing", "linked"} {
		t.Run(state, func(t *testing.T) {
			f := newLedgerFixture(t)
			a := f.retried(2)
			id := a.Attempt.Candidate
			old, err := admission.NewAttempt(id, 1)
			if err != nil {
				t.Fatal(err)
			}
			link := testLink("act_", f.wall.Add(time.Hour))
			switch state {
			case "queued", "linked":
				if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
					t.Fatal(err)
				}
				if state == "linked" {
					if _, err := f.l.TerminateExisting(id, link); err != nil {
						t.Fatal(err)
					}
				}
			case "executing":
				if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := f.snapshot()
			if _, _, err := f.l.FinishExisting(old.ID, link); err != admission.ErrTransitionConflict {
				t.Fatalf("historical finish = %v, want ErrTransitionConflict", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("historical finish changed the current candidate")
			}
		})
	}
}

// Idempotence compares expiry instants, including after decoding UTC, and
// never acknowledges a different effect or expiry as the recorded ending.
func TestAdmissionLedgerFinishExistingRepeatsOnlyTheSameLink(t *testing.T) {
	for _, finish := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminate", true: "finish"}[finish], func(t *testing.T) {
			f := newLedgerFixture(t)
			id, a := f.admitted(time.Hour)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if !finish {
				if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
					t.Fatal(err)
				}
			}
			end := func(link admission.EffectLink) error {
				if finish {
					_, _, err := f.l.FinishExisting(a.Attempt.ID, link)
					return err
				}
				_, err := f.l.TerminateExisting(id, link)
				return err
			}
			link := testLink("act_", f.wall.Add(time.Hour).In(time.FixedZone("fixture", 3600)))
			if err := end(link); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if err := end(link); err != nil {
				t.Fatalf("same expiry instant refused after decode: %v", err)
			}
			for _, other := range []admission.EffectLink{
				testLink("eff_", link.ExpiresAt),
				testLink("act_", link.ExpiresAt.Add(time.Second)),
			} {
				if err := end(other); err != admission.ErrCandidateTerminal {
					t.Fatalf("different ending = %v, want ErrCandidateTerminal", err)
				}
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("a repeated ending changed ledger bytes")
			}
		})
	}
}

// Both paths pay precisely the link growth on the last attempt's lane.
// A failed commit rolls back all records, and a repeat pays nothing.
func TestAdmissionLedgerTerminateExistingChargesRetryHistory(t *testing.T) {
	for _, lane := range []admission.Lane{admission.LaneGeneral, admission.LaneDirect} {
		for _, finish := range []bool{false, true} {
			f := newLedgerFixture(t)
			root := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", severity: admission.SeverityCritical})
			_, id := f.enqueue(f.request("192.0.2.10", root))
			_, a, granted, err := f.l.Reserve(id, lane, f.wall.Add(time.Hour))
			if err != nil || !granted {
				t.Fatalf("reserve: %t, %v", granted, err)
			}
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if !finish {
				if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
					t.Fatal(err)
				}
			}
			link := testLink("eff_", time.Time{})
			end := func() error {
				if finish {
					_, _, err := f.l.FinishExisting(a.Attempt.ID, link)
					return err
				}
				_, err := f.l.TerminateExisting(id, link)
				return err
			}
			before := f.snapshot()
			op := "terminate"
			if finish {
				op = "finish"
			}
			f.failNext(op)
			if err := end(); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatalf("failed linked commit changed records: %v", err)
			}
			h, found := f.historyEntry(id)
			if !found {
				t.Fatal("reserved candidate has no history")
			}
			start := f.storageState()
			// No credit must refuse both paths without a partial schema bump.
			f.adjustStorage(func(s *admission.StorageState) {
				if lane == admission.LaneGeneral {
					s.General.Credit = 0
				} else {
					s.Reserved.Credit = 0
				}
			})
			noCredit := f.snapshot()
			if err := end(); err == nil || !reflect.DeepEqual(noCredit, f.snapshot()) {
				t.Fatalf("link without credit changed records: %v", err)
			}
			f.adjustStorage(func(s *admission.StorageState) { *s = start })
			if err := end(); err != nil {
				t.Fatal(err)
			}
			next, _ := f.historyEntry(id)
			cost := f.cost(id)
			if cost <= h.Charged() || next.Charged() != cost {
				t.Fatalf("history = %+v -> %+v; want %d bytes", h, next, cost)
			}
			growth := uint64(cost - h.Charged())
			want := start
			if lane == admission.LaneGeneral {
				want.General.Used += growth
				want.General.Credit -= growth * uint64(time.Second)
				if next.Reserved != h.Reserved {
					t.Fatal("link charged the wrong lane")
				}
			} else {
				want.Reserved.Used += growth
				want.Reserved.Credit -= growth * uint64(time.Second)
				if next.General != h.General {
					t.Fatal("link charged the wrong lane")
				}
			}
			got := f.storageState()
			if got.General != want.General || got.Reserved != want.Reserved {
				t.Fatalf("history meters = %+v, want general=%+v reserved=%+v", got, want.General, want.Reserved)
			}
			before = f.snapshot()
			if err := end(); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatalf("repeat charged or rewrote the ending: %v", err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("linked retry history cannot reopen: %v", err)
			}
		}
	}
}

// A reserved attempt can fail before dispatch. Its linked ending still
// counts both transitions and pays for a valid terminal candidate.
func TestAdmissionLedgerFinishExistingBeforeExecution(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	before, readErr := f.l.Candidate(id)
	if readErr != nil || before.State != admission.StateReserved {
		t.Fatalf("reserved candidate = %+v, %v", before, readErr)
	}
	link := testLink("eff_", f.wall.Add(2*time.Hour))
	c, done, finishErr := f.l.FinishExisting(a.Attempt.ID, link)
	if finishErr != nil || c.State != admission.StateRefused || c.Link != link || c.Transitions != before.Transitions+2 || done.State != admission.StateFailed || done.Attempt != a.Attempt {
		t.Fatalf("linked failure before dispatch = %+v, %+v, %v", c, done, finishErr)
	}
	if _, openErr := OpenAdmissionLedger(f.db, f.reg); openErr != nil {
		t.Fatalf("linked failure before dispatch cannot reopen: %v", openErr)
	}
}

// A queued attempt from before lanes existed pays link growth from the
// general history allowance without rewriting its attempt or action charge.
func TestAdmissionLedgerTerminateExistingChargesLegacyRetry(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.schemaTwo()
	reopened, openErr := OpenAdmissionLedger(f.db, f.reg)
	if openErr != nil {
		t.Fatal(openErr)
	}
	f.l = reopened
	// Upgrades start with no byte credit; elapsed time refills it.
	f.tickAt(f.wall.Add(time.Minute))
	legacy, readErr := f.l.Attempt(a.Attempt.ID)
	if readErr != nil || legacy.Lane != 0 || legacy.State != admission.StateFailed {
		t.Fatalf("legacy attempt = %+v, %v", legacy, readErr)
	}
	h, found := f.historyEntry(id)
	if !found {
		t.Fatal("legacy retry has no history")
	}
	start := f.storageState()
	before := f.snapshot()
	link := testLink("eff_", time.Time{})
	c, endErr := f.l.TerminateExisting(id, link)
	if endErr != nil || c.State != admission.StateRefused || c.Link != link || c.Attempts != 1 {
		t.Fatalf("legacy linked ending = %+v, %v", c, endErr)
	}
	next, found := f.historyEntry(id)
	cost := f.cost(id)
	if !found || cost <= h.Charged() || next.General != cost || next.Reserved != h.Reserved {
		t.Fatalf("legacy history = %+v -> %+v; want %d general bytes", h, next, cost)
	}
	growth := uint64(cost - h.Charged())
	want := start.General
	want.Used += growth
	want.Credit -= growth * uint64(time.Second)
	if got := f.storageState(); got.General != want || got.Reserved != start.Reserved {
		t.Fatalf("legacy link meters = %+v; want general=%+v reserved=%+v", got, want, start.Reserved)
	}
	after := f.snapshot()
	for key, value := range before {
		if strings.HasPrefix(key, admissionAttemptsBucket+":") || strings.HasPrefix(key, admissionChargesBucket+":") {
			if after[key] != value {
				t.Fatalf("link rewrote legacy attempt or charge: %s", key)
			}
		}
	}
	if _, repeatErr := f.l.TerminateExisting(id, link); repeatErr != nil || !reflect.DeepEqual(after, f.snapshot()) {
		t.Fatalf("legacy repeat changed records: %v", repeatErr)
	}
	if _, reopenErr := OpenAdmissionLedger(f.db, f.reg); reopenErr != nil {
		t.Fatalf("linked legacy retry cannot reopen: %v", reopenErr)
	}
}

// A delayed finish can acknowledge the same link written by termination,
// but cannot replace that ending, invent a missing link or change its reason.
func TestAdmissionLedgerFinishExistingAfterTermination(t *testing.T) {
	for _, mode := range []string{"same", "effect", "expiry", "unlinked", "protected"} {
		t.Run(mode, func(t *testing.T) {
			f := newLedgerFixture(t)
			id, a := f.admitted(time.Hour)
			if _, _, finishErr := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); finishErr != nil {
				t.Fatal(finishErr)
			}
			link := testLink("act_", f.wall.Add(time.Hour).In(time.FixedZone("fixture", 3600)))
			var ended admission.Candidate
			var endErr error
			switch mode {
			case "unlinked":
				ended, endErr = f.l.Terminate(id, admission.ReasonExistingEffect)
			case "protected":
				ended, endErr = f.l.Terminate(id, admission.ReasonProtected)
			default:
				ended, endErr = f.l.TerminateExisting(id, link)
			}
			if endErr != nil {
				t.Fatal(endErr)
			}
			reopened, openErr := OpenAdmissionLedger(f.db, f.reg)
			if openErr != nil {
				t.Fatal(openErr)
			}
			f.l = reopened
			before := f.snapshot()
			switch mode {
			case "effect":
				link.Effect = testLink("eff_", time.Time{}).Effect
			case "expiry":
				link.ExpiresAt = link.ExpiresAt.Add(time.Second)
			}
			got, done, finishErr := f.l.FinishExisting(a.Attempt.ID, link)
			if mode == "same" {
				if finishErr != nil || got.State != ended.State || got.Reason != ended.Reason || got.Transitions != ended.Transitions || got.Link.Effect != ended.Link.Effect || !got.Link.ExpiresAt.Equal(ended.Link.ExpiresAt) || done.Attempt != a.Attempt || done.State != admission.StateFailed {
					t.Fatalf("finish after linked termination = %+v, %+v, %v", got, done, finishErr)
				}
			} else if finishErr != admission.ErrCandidateTerminal {
				t.Fatalf("finish replaced another ending: %v", finishErr)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("finish after termination changed ledger bytes")
			}
		})
	}
}

// A first linked write that aborts leaves schema 7 and every record intact,
// including after reopen; only a later successful ending may write schema 8.
func TestAdmissionLedgerTerminateExistingFirstWriteRollback(t *testing.T) {
	for _, mode := range []string{"unadmitted", "retry", "executing"} {
		t.Run(mode, func(t *testing.T) {
			f := newLedgerFixture(t)
			var id admission.CandidateID
			var a admission.AttemptRecord
			if mode == "unadmitted" {
				id = f.queued()
			} else {
				id, a = f.admitted(time.Hour)
				if _, _, _, executeErr := f.l.Execute(a.Attempt.ID); executeErr != nil {
					t.Fatal(executeErr)
				}
				if mode == "retry" {
					if _, _, finishErr := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); finishErr != nil {
						t.Fatal(finishErr)
					}
				}
			}
			link := testLink("eff_", f.wall.Add(2*time.Hour))
			end := func() error {
				if mode == "executing" {
					_, _, finishErr := f.l.FinishExisting(a.Attempt.ID, link)
					return finishErr
				}
				_, endErr := f.l.TerminateExisting(id, link)
				return endErr
			}
			if got := f.schema(); got != admissionSchemaVersion {
				t.Fatalf("schema before first link = %d", got)
			}
			before := f.snapshot()
			op := "terminate"
			if mode == "executing" {
				op = "finish"
			}
			f.failNext(op)
			if endErr := end(); endErr == nil {
				t.Fatal("first linked write did not hit the commit failure")
			}
			if got := f.schema(); got != admissionSchemaVersion || !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatalf("rolled-back first link changed schema or records: schema=%d", got)
			}
			reopened, openErr := OpenAdmissionLedger(f.db, f.reg)
			if openErr != nil {
				t.Fatalf("reopen after rollback: %v", openErr)
			}
			f.l = reopened
			if got := f.schema(); got != admissionSchemaVersion || !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatalf("reopen upgraded a ledger without a committed link: schema=%d", got)
			}
			if _, readErr := ReadAdmissionClock(f.db); readErr != nil {
				t.Fatal(readErr)
			}
			if endErr := end(); endErr != nil {
				t.Fatalf("retry after rolled-back first link: %v", endErr)
			}
			if got := f.schema(); got != admissionSchemaLinked {
				t.Fatalf("committed retry schema = %d", got)
			}
			if c, readErr := f.l.Candidate(id); readErr != nil || c.State != admission.StateRefused || c.Link != link {
				t.Fatalf("committed retry = %+v, %v", c, readErr)
			}
			if _, reopenErr := OpenAdmissionLedger(f.db, f.reg); reopenErr != nil {
				t.Fatalf("reopen after committed retry: %v", reopenErr)
			}
		})
	}
}
