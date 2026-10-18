package store

import (
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// A response the operator turned off ends refused as disabled: no attempt,
// ceiling charge, history allocation or audit row, one ended count and no
// withheld notice, since nothing the operator wants was withheld. The
// first one moves the ledger to schema 10, which this build's opener and
// startup reads accept and older builds refuse; the same ending again
// changes nothing.
func TestAdmissionLedgerDisabledEndsWithoutANotice(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	tier := f.entryTier(id)
	ceiling, storage, attempts := f.ceilingState(), f.storageState(), f.attemptRows()
	c, err := f.l.Terminate(id, admission.ReasonDisabled)
	if err != nil || c.State != admission.StateRefused || c.Disposition != admission.DispositionRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
		t.Fatalf("Terminate = %+v, %v", c, err)
	}
	if got := f.schema(); got != admissionSchemaDisabled {
		t.Fatalf("schema = %d, want %d", got, admissionSchemaDisabled)
	}
	after := f.storageState()
	if !reflect.DeepEqual(f.ceilingState(), ceiling) || f.attemptRows() != attempts ||
		after.General != storage.General || after.Reserved != storage.Reserved || after.Ended.Count != storage.Ended.Count+1 {
		t.Fatalf("a disabled response spent capacity: storage %+v -> %+v", storage, after)
	}
	if n := f.countOf(admission.EventEnded, admission.ReasonDisabled, tier); n != 1 {
		t.Fatalf("ended count = %d", n)
	}
	if rows := f.pendingAudit(); len(rows) != 0 {
		t.Fatalf("a disabled response wrote audit rows: %+v", rows)
	}
	if records, noticeErr := f.l.PendingNotices(); noticeErr != nil || len(records) != 0 {
		t.Fatalf("notices = %+v, %v", records, noticeErr)
	}
	before := f.snapshot()
	again, err := f.l.Terminate(id, admission.ReasonDisabled)
	if err != nil || !reflect.DeepEqual(again, c) || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("repeat = %+v, %v; want the same ending unchanged", again, err)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen at schema 10: %v", err)
	}
	if _, err = ReadUnprovenBlockActions(f.db, nil); err != nil {
		t.Fatalf("startup read at schema 10: %v", err)
	}
}

// Schema 10 follows schema 9 and is never lowered by a later dry-run
// ending or panel allow. A disabled ending that fails to commit leaves the
// schema as it was.
func TestAdmissionLedgerDisabledRaisesTheSchemaOnce(t *testing.T) {
	f := newLedgerFixture(t)
	if _, err := f.l.Terminate(f.queued(), admission.ReasonVerdictAllow); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	second := f.queued()
	f.failNext("terminate")
	if _, err := f.l.Terminate(second, admission.ReasonDisabled); err == nil {
		t.Fatal("the ending did not hit the commit failure")
	}
	if got := f.schema(); got != admissionSchemaShadow {
		t.Fatalf("schema after a rolled-back ending = %d", got)
	}
	if _, err := f.l.Terminate(second, admission.ReasonDisabled); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	if _, err := f.l.Terminate(f.queued(), admission.ReasonVerdictAllow); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	if _, changed, err := f.l.EndDryRun(f.queued()); err != nil || !changed {
		t.Fatalf("dry-run ending after disabled: changed=%v err=%v", changed, err)
	}
	if got := f.schema(); got != admissionSchemaDisabled {
		t.Fatalf("schema = %d, want %d", got, admissionSchemaDisabled)
	}
}
