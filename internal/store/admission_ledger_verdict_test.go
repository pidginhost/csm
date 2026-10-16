package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// countOf is the queue counter of one event, reason and tier.
func (f *ledgerFixture) countOf(event admission.QueueEvent, reason admission.Reason, tier admission.Tier) uint64 {
	f.t.Helper()
	var n uint64
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		counters, err := loadQueueCounters(tx)
		for _, row := range counters.Rows() {
			if row.Key == (admission.CountKey{Event: event, Reason: reason, Class: tier.Class, Severity: tier.Severity}) {
				n = row.N
			}
		}
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// attemptRows counts the stored attempt records.
func (f *ledgerFixture) attemptRows() (n int) {
	f.t.Helper()
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionAttemptsBucket)).ForEach(func(_, _ []byte) error {
			n++
			return nil
		})
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// A panel allow ends queued work refused (D5): no attempt, ceiling charge,
// history allocation or audit row, one ended count, and the withheld
// notice Critical work raises for any refusal. The first one moves the
// ledger to schema 9, which older builds refuse. The same ending again
// changes nothing.
func TestAdmissionLedgerVerdictAllowEndsUncharged(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	tier := f.entryTier(id)
	ceiling, storage, attempts := f.ceilingState(), f.storageState(), f.attemptRows()
	c, err := f.l.Terminate(id, admission.ReasonVerdictAllow)
	if err != nil || c.State != admission.StateRefused || c.Disposition != admission.DispositionRefused || c.Reason != admission.ReasonVerdictAllow || c.Attempts != 0 {
		t.Fatalf("Terminate = %+v, %v", c, err)
	}
	if got := f.schema(); got != admissionSchemaShadow {
		t.Fatalf("schema = %d, want %d", got, admissionSchemaShadow)
	}
	after := f.storageState()
	if !reflect.DeepEqual(f.ceilingState(), ceiling) || f.attemptRows() != attempts ||
		after.General != storage.General || after.Reserved != storage.Reserved || after.Ended.Count != storage.Ended.Count+1 {
		t.Fatalf("an allow spent capacity: storage %+v -> %+v", storage, after)
	}
	if n := f.countOf(admission.EventEnded, admission.ReasonVerdictAllow, tier); n != 1 {
		t.Fatalf("ended count = %d", n)
	}
	if n := f.outcomesAt(admission.SpanHour, f.wall).Count(admission.QueueOutcome(admission.EventEnded, admission.ReasonVerdictAllow, tier)); n != 1 {
		t.Fatalf("windowed count = %d", n)
	}
	if rows := f.pendingAudit(); len(rows) != 0 {
		t.Fatalf("an allow wrote audit rows: %+v", rows)
	}
	records, err := f.l.PendingNotices()
	if err != nil {
		t.Fatal(err)
	}
	var notice *admission.NoticeRecord
	for i := range records {
		if records[i].Key == sshKey(admission.NoticeWithheld, admission.ReasonVerdictAllow) {
			notice = &records[i]
		}
	}
	if notice == nil || notice.Count != 1 || len(notice.Examples) != 1 || notice.Examples[0].Candidate != id {
		t.Fatalf("withheld notice = %+v", notice)
	}
	before := f.snapshot()
	again, err := f.l.Terminate(id, admission.ReasonVerdictAllow)
	if err != nil || !reflect.DeepEqual(again, c) || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("repeat = %+v, %v; want the same ending unchanged", again, err)
	}
	if _, err = f.l.Terminate(id, admission.ReasonProtected); err != admission.ErrCandidateTerminal {
		t.Fatalf("another ending = %v, want ErrCandidateTerminal", err)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen at schema 9: %v", err)
	}
}

// The first allow that fails to commit leaves schema 7 and every record as
// they were; a retry that commits writes schema 9.
func TestAdmissionLedgerVerdictAllowRollsBack(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	before := f.snapshot()
	f.failNext("terminate")
	if _, err := f.l.Terminate(id, admission.ReasonVerdictAllow); err == nil {
		t.Fatal("the allow did not hit the commit failure")
	}
	if got := f.schema(); got != admissionSchemaVersion || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("a rolled-back allow changed the ledger: schema %d", got)
	}
	if _, err := f.l.Terminate(id, admission.ReasonVerdictAllow); err != nil {
		t.Fatal(err)
	}
	if got := f.schema(); got != admissionSchemaShadow {
		t.Fatalf("schema = %d", got)
	}
}

// An allow does not answer the episode: a later observation queues the
// next generation, which the panel can be asked about again.
func TestAdmissionLedgerVerdictAllowLetsTheNextGenerationQueue(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1", age: time.Minute}))[0].Candidate
	if _, err := f.l.Terminate(first, admission.ReasonVerdictAllow); err != nil {
		t.Fatal(err)
	}
	episode := f.candidateOf(first).Key.Episode
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	if c := f.candidateOf(next.Candidate); next.Err != nil || !next.Created || c.Key.Episode != episode || c.Key.Generation != 2 {
		t.Fatalf("later observation: %+v %+v", next, c.Key)
	}
}

// Ending a retry as allowed keeps the failed attempt's charge and history
// and ends that history; nothing new is allocated.
func TestAdmissionLedgerVerdictAllowEndsARetry(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	ceiling, storage := f.ceilingState(), f.storageState()
	c, err := f.l.Terminate(id, admission.ReasonVerdictAllow)
	if err != nil || c.State != admission.StateRefused || c.Attempts != 1 {
		t.Fatalf("Terminate = %+v, %v", c, err)
	}
	if !reflect.DeepEqual(f.ceilingState(), ceiling) || !reflect.DeepEqual(f.storageState(), storage) {
		t.Fatal("ending a retry changed its charges")
	}
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		h, found, loadErr := loadHistoryEntry(tx, id)
		if loadErr != nil || !found || !h.Ended.Equal(f.wall) {
			t.Errorf("history = %+v %v %v", h, found, loadErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
