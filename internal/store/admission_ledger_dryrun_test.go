package store

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// historyOf is the stored history entry of id.
func (f *ledgerFixture) historyOf(id admission.CandidateID) (admission.HistoryEntry, bool) {
	f.t.Helper()
	var h admission.HistoryEntry
	var found bool
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		h, found, err = loadHistoryEntry(tx, id)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return h, found
}

// countersSnapshot is the stored queue counters.
func (f *ledgerFixture) countersSnapshot() []admission.QueueCount {
	f.t.Helper()
	var rows []admission.QueueCount
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		counters, err := loadQueueCounters(tx)
		rows = counters.Rows()
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return rows
}

// queueEntries are the keys holding a queue position.
func (f *ledgerFixture) queueEntries() map[string]bool {
	f.t.Helper()
	out := map[string]bool{}
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueBucket)).ForEach(func(k, _ []byte) error {
			out[string(k)] = true
			return nil
		})
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// exhausted is a candidate whose last attempt failed for good.
func (f *ledgerFixture) exhausted() admission.CandidateID {
	f.t.Helper()
	a := f.retried(admission.MaxAttempts)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	c, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
	if err != nil || c.State != admission.StateFailed {
		f.t.Fatalf("exhausted = %+v, %v", c, err)
	}
	return a.Attempt.Candidate
}

// A dry-run ending (D1) takes queued work to dry_run with no attempt,
// ceiling charge, history allocation, audit row or notice, even for
// Critical work. It counts one dry-run outcome and no queue event, takes
// an ended position and moves the ledger to schema 9. The same ending again
// changes nothing and reports so.
func TestAdmissionLedgerEndDryRunEndsAFreshPick(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	tier := f.entryTier(id)
	ceiling, storage, attempts := f.ceilingState(), f.storageState(), f.attemptRows()
	notices, err := f.l.PendingNotices()
	if err != nil {
		t.Fatal(err)
	}
	counters := f.countersSnapshot()
	c, changed, err := f.l.EndDryRun(id)
	if err != nil || !changed || c.State != admission.StateDryRun || c.Disposition != admission.DispositionDryRun || c.Reason != 0 || c.Attempts != 0 || c.Transitions != 2 {
		t.Fatalf("EndDryRun = %+v, %v, %v", c, changed, err)
	}
	if got := f.schema(); got != admissionSchemaShadow {
		t.Fatalf("schema = %d", got)
	}
	after := f.storageState()
	if !reflect.DeepEqual(f.ceilingState(), ceiling) || f.attemptRows() != attempts ||
		after.General != storage.General || after.Reserved != storage.Reserved || after.Ended.Count != storage.Ended.Count+1 {
		t.Fatalf("a dry run spent capacity: storage %+v -> %+v", storage, after)
	}
	if _, found := f.historyOf(id); found {
		t.Fatal("a dry run allocated history")
	}
	if !reflect.DeepEqual(f.countersSnapshot(), counters) {
		t.Fatal("a dry run counted a queue event")
	}
	for _, span := range admission.Spans() {
		if n := f.outcomesAt(span, f.wall).Count(admission.AttemptOutcome(admission.DispositionDryRun, tier)); n != 1 {
			t.Fatalf("%v dry-run outcomes = %d", span, n)
		}
	}
	if rows := f.pendingAudit(); len(rows) != 0 {
		t.Fatalf("a dry run wrote audit rows: %+v", rows)
	}
	if again, noticeErr := f.l.PendingNotices(); noticeErr != nil || !reflect.DeepEqual(again, notices) {
		t.Fatalf("a dry run raised a notice: %+v, %v", again, noticeErr)
	}
	if _, inQueue := f.queueEntries()[string(id)]; inQueue {
		t.Fatal("the ending kept its queue position")
	}
	before := f.snapshot()
	again, changed, err := f.l.EndDryRun(id)
	if err != nil || changed || !reflect.DeepEqual(again, c) || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("repeat = %+v, %v, %v; want the same ending unchanged", again, changed, err)
	}
	if _, err = f.l.Terminate(id, admission.ReasonProtected); err != admission.ErrCandidateTerminal {
		t.Fatalf("another ending = %v, want ErrCandidateTerminal", err)
	}
}

// Only queued work ends as a dry run: reserved and running attempts are a
// conflict, other endings are terminal and an unknown ID is not queued.
func TestAdmissionLedgerEndDryRunNeedsQueuedWork(t *testing.T) {
	f := newLedgerFixture(t)
	exhausted := f.exhausted()
	// A running or unknown attempt holds its target, so each sits alone.
	admittedAt := func(target string) (admission.CandidateID, admission.AttemptRecord) {
		f.nextGeneration()
		root := f.published(evidenceSpec{target: target, cursor: "at=" + target})
		_, id := f.enqueue(f.request(target, root))
		_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return id, a
	}
	reserved, _ := admittedAt("192.0.2.11")
	running, a := admittedAt("192.0.2.12")
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	unknown, u := admittedAt("192.0.2.13")
	if _, _, _, err := f.l.Execute(u.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(u.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	refused := f.published(evidenceSpec{target: "192.0.2.14", cursor: "refused"})
	_, refusedID := f.enqueue(f.request("192.0.2.14", refused))
	if _, err := f.l.Terminate(refusedID, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	for name, tc := range map[string]struct {
		id   admission.CandidateID
		want error
	}{
		"reserved":  {reserved, admission.ErrTransitionConflict},
		"executing": {running, admission.ErrTransitionConflict},
		"unknown":   {unknown, admission.ErrCandidateTerminal},
		"refused":   {refusedID, admission.ErrCandidateTerminal},
		"exhausted": {exhausted, admission.ErrCandidateTerminal},
		"missing":   {admission.CandidateID("cand_" + "ffffffffffffffffffffffffffffffff"), errCandidateMissing},
	} {
		if _, changed, err := f.l.EndDryRun(tc.id); !errors.Is(err, tc.want) || changed {
			t.Errorf("%s: changed %v, err %v; want %v", name, changed, err, tc.want)
		}
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused dry run changed the ledger")
	}
}

// A queued retry ends as a dry run after its backoff, keeping its failed
// attempt, the attempt's ceiling charge and the history it paid for, which
// ends; nothing new is reserved or charged. Its retry delay is cleared and
// its original expiry kept.
func TestAdmissionLedgerEndDryRunEndsARetry(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	queued := f.candidateOf(id)
	if _, _, err := f.l.EndDryRun(id); !errors.Is(err, admission.ErrNotReady) {
		t.Fatalf("during the backoff: %v, want ErrNotReady", err)
	}
	f.tickAt(queued.NotBefore)
	ceiling, storage, attempts := f.ceilingState(), f.storageState(), f.attemptRows()
	history, _ := f.historyOf(id)
	c, changed, err := f.l.EndDryRun(id)
	if err != nil || !changed || c.State != admission.StateDryRun || c.Attempts != 1 || !c.NotBefore.IsZero() || !c.ExpiresAt.Equal(queued.ExpiresAt) {
		t.Fatalf("EndDryRun = %+v, %v, %v", c, changed, err)
	}
	if !reflect.DeepEqual(f.ceilingState(), ceiling) || f.attemptRows() != attempts {
		t.Fatal("ending a retry changed its charges or attempts")
	}
	after := f.storageState()
	if after.General != storage.General || after.Reserved != storage.Reserved || after.Ended != storage.Ended {
		t.Fatalf("ending a retry allocated storage: %+v -> %+v", storage, after)
	}
	ended, found := f.historyOf(id)
	wantEligible, _ := admission.HistoryTimes(f.wall, c.ExpiresAt, false)
	if !found || ended.General != history.General || ended.Reserved != history.Reserved || !ended.Ended.Equal(f.wall) || !ended.Eligible.Equal(wantEligible) {
		t.Fatalf("history %+v -> %+v", history, ended)
	}
	if prior, attemptErr := f.l.Attempt(a.Attempt.ID); attemptErr != nil || prior.State != admission.StateFailed {
		t.Fatalf("prior attempt = %+v, %v", prior, attemptErr)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

// Dry run is no bypass: an aged-out pick or a retry past its expiry is
// stale, and an unresolved attempt still holds its target.
func TestAdmissionLedgerEndDryRunKeepsSafetyGates(t *testing.T) {
	f := newLedgerFixture(t)
	held, u := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(u.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(u.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	other := f.queued()
	if f.candidateOf(other).Key.Target != f.candidateOf(held).Key.Target {
		t.Fatal("fixture: the pick does not share the held target")
	}
	before := f.snapshot()
	if _, changed, err := f.l.EndDryRun(other); changed {
		t.Fatal("a held target ended")
	} else {
		wantLedgerReason(t, "held target", err, admission.ReasonPendingRecovery)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused dry run changed the ledger")
	}

	g := newLedgerFixture(t)
	stale := g.queued()
	g.tickAt(g.candidateOf(stale).AgeOut)
	if _, changed, err := g.l.EndDryRun(stale); changed {
		t.Fatal("an aged-out pick ended as a dry run")
	} else {
		wantLedgerReason(t, "aged out", err, admission.ReasonStale)
	}

	h := newLedgerFixture(t)
	id, a := h.admitted(time.Minute)
	if _, _, err := h.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	h.tickAt(h.candidateOf(id).ExpiresAt)
	if _, changed, err := h.l.EndDryRun(id); changed {
		t.Fatal("an expired retry ended as a dry run")
	} else {
		wantLedgerReason(t, "expired retry", err, admission.ReasonStale)
	}

	k := newLedgerFixture(t)
	fresh := k.queued()
	reopened, err := OpenAdmissionLedger(k.db, k.reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, endErr := reopened.EndDryRun(fresh); changed {
		t.Fatal("a handle without a current reading ended work")
	} else {
		wantLedgerReason(t, "no current reading", endErr, admission.ReasonEngineUnavailable)
	}
}

// A failed commit leaves the schema, the queue, the counters and the
// episode as they were; the retry commits once.
func TestAdmissionLedgerEndDryRunRollsBack(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	tier := f.entryTier(id)
	before := f.snapshot()
	f.failNext("dry_run")
	if _, changed, err := f.l.EndDryRun(id); err == nil || changed {
		t.Fatalf("the ending did not hit the commit failure: %v %v", changed, err)
	}
	if got := f.schema(); got != admissionSchemaVersion || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("a rolled-back dry run changed the ledger: schema %d", got)
	}
	if _, changed, err := f.l.EndDryRun(id); err != nil || !changed {
		t.Fatalf("retry: %v %v", changed, err)
	}
	if n := f.outcomesAt(admission.SpanDay, f.wall).Count(admission.AttemptOutcome(admission.DispositionDryRun, tier)); n != 1 {
		t.Fatalf("dry-run outcomes = %d", n)
	}
}

// A dry-run ending survives a reopen, is never scheduled or reserved, and
// does not answer the episode: a later observation queues the next
// generation, which can run live.
func TestAdmissionLedgerEndDryRunDoesNotAnswerTheEpisode(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1", age: time.Minute}))[0].Candidate
	tier := f.entryTier(first)
	if _, _, err := f.l.EndDryRun(first); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	f.tickAt(f.wall.Add(time.Second))
	if n := f.outcomesAt(admission.SpanDay, f.wall).Count(admission.AttemptOutcome(admission.DispositionDryRun, tier)); n != 1 {
		t.Fatalf("dry-run outcomes after reopen = %d", n)
	}
	if picks, schedErr := f.l.Schedule(fullSchedule, nil); schedErr != nil || len(picks) != 0 {
		t.Fatalf("schedule after a dry run = %+v, %v", picks, schedErr)
	}
	if _, _, _, reserveErr := f.l.Reserve(first, admission.LaneGeneral, f.wall.Add(time.Hour)); reserveErr != admission.ErrCandidateTerminal {
		t.Fatalf("reserve after a dry run = %v", reserveErr)
	}
	episode := f.candidateOf(first).Key.Episode
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	c := f.candidateOf(next.Candidate)
	if next.Err != nil || !next.Created || c.Key.Episode != episode || c.Key.Generation != 2 {
		t.Fatalf("later observation: %+v %+v", next, c.Key)
	}
	if _, _, granted, reserveErr := f.l.Reserve(next.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour)); reserveErr != nil || !granted {
		t.Fatalf("the next generation cannot run live: %v %v", granted, reserveErr)
	}
}

// Roots a retry gained while it waited are queue data no reservation paid
// for; a dry-run ending drops them as other endings do, rather than keep
// them as unpaid history.
func TestAdmissionLedgerEndDryRunDropsUnreservedRoots(t *testing.T) {
	f := newLedgerFixture(t)
	root := f.published(evidenceSpec{})
	_, id := f.enqueue(f.request("192.0.2.10", root))
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	extra := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "retry-support"})
	if _, _, err = f.l.Enqueue(f.request("192.0.2.10", root, extra)); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.candidateOf(id).NotBefore)
	charged := f.storageState().General.Used
	c, _, err := f.l.EndDryRun(id)
	if err != nil || len(c.Roots) != 1 || c.Roots[0] != root {
		t.Fatalf("ending = %+v, %v", c, err)
	}
	if f.storageState().General.Used != charged || uint64(f.cost(id)) > charged {
		t.Fatal("the ending retained unpaid history")
	}
	if r, found := refsIn(t, f.db, extra); !found || r.Refs != 0 || r.Loose == 0 {
		t.Fatalf("unused support references: %+v %v", r, found)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}
