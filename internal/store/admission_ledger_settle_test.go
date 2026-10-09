package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A new process settles what the previous one left outstanding, before it
// reserves anything and without a current reading. A reservation recorded
// no intent, so it dispatched nothing: it fails, keeps its charge and
// retries after its backoff. A running attempt may have applied its effect:
// it ends unknown and keeps its intent. Nothing runs again.
func TestAdmissionLedgerSettlesWhatAPreviousProcessLeft(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	reserved, running := f.reservedAt("192.0.2.10", expires), f.reservedAt("192.0.2.11", expires)
	applied := f.reservedAt("192.0.2.12", expires)
	for _, a := range []admission.AttemptRecord{running, applied} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.l.Finish(applied.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	f.ackAll()
	charges := f.charges()
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	failed, unknown, err := l.Settle()
	if err != nil || failed != 1 || unknown != 1 {
		t.Fatalf("settle = %d failed, %d unknown, %v", failed, unknown, err)
	}
	c, err := l.Candidate(reserved.Attempt.Candidate)
	if err != nil || c.State != admission.StateQueued || c.Attempts != 1 || !c.NotBefore.Equal(ledgerT0.Add(admission.RetryBackoff(1))) {
		t.Fatalf("reserved candidate = %+v, %v", c, err)
	}
	if a, readErr := l.Attempt(reserved.Attempt.ID); readErr != nil || a.State != admission.StateFailed || !a.Finished.Equal(ledgerT0) {
		t.Fatalf("reserved attempt = %+v, %v", a, readErr)
	}
	c, err = l.Candidate(running.Attempt.Candidate)
	if err != nil || c.State != admission.StateUnknown || c.Disposition != admission.DispositionUnknown {
		t.Fatalf("running candidate = %+v, %v", c, err)
	}
	if _, kept := f.intents()[running.Attempt.ID]; !kept || len(f.intents()) != 1 {
		t.Fatalf("intents = %+v", f.intents())
	}
	if got := f.charges(); !reflect.DeepEqual(got, charges) {
		t.Fatalf("charges %+v -> %+v", charges, got)
	}
	rows := f.pendingAudit()
	if len(rows) != 2 {
		t.Fatalf("settlement rows = %+v", rows)
	}
	for _, r := range rows {
		want := admission.DispositionFailed
		if r.Attempt.ID == running.Attempt.ID {
			want = admission.DispositionUnknown
		}
		if r.Disposition != want || !r.At.Equal(ledgerT0) {
			t.Errorf("row %+v, want %s", r, want)
		}
	}
	before := f.snapshot()
	if failed, unknown, err = l.Settle(); err != nil || failed != 0 || unknown != 0 {
		t.Fatalf("second settle = %d, %d, %v", failed, unknown, err)
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a second settle changed the ledger")
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// Settlement is one transaction: a failed commit leaves every attempt
// outstanding.
func TestAdmissionLedgerSettleIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	f.reservedAt("192.0.2.10", expires)
	running := f.reservedAt("192.0.2.11", expires)
	if _, _, _, err := f.l.Execute(running.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	f.failNext("settle")
	if _, _, err := f.l.Settle(); err == nil {
		t.Fatal("injected commit failure was ignored")
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a failed settlement changed the ledger")
	}
}
