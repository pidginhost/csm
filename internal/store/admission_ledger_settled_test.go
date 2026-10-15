package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Settled actions are those whose rows may go: a failed attempt applied
// nothing, and a retired unknown one was found absent after its expiry.
// Running and unknown attempts stay held; a verified one is enforced; a
// name the ledger never recorded is not claimed.
func TestReadSettledBlockActions(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	running, unknown := f.reservedAt("192.0.2.30", expires), f.reservedAt("192.0.2.31", expires)
	failed, applied := f.reservedAt("192.0.2.32", expires), f.reservedAt("192.0.2.33", expires)
	retired := f.reservedAt("192.0.2.34", expires)
	for _, a := range []admission.AttemptRecord{running, unknown, failed, applied, retired} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	for a, d := range map[admission.AttemptRecord]admission.Disposition{
		unknown: admission.DispositionUnknown, failed: admission.DispositionFailed,
		applied: admission.DispositionApplied, retired: admission.DispositionUnknown,
	} {
		if _, _, err := f.l.Finish(a.Attempt.ID, d); err != nil {
			t.Fatal(err)
		}
	}
	f.ackAll()
	f.tickAt(expires.Add(time.Second))
	if _, _, granted, err := f.l.RetireUnproven(retired.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire = %t, %v", granted, err)
	}
	const unrecorded = "act_00000000000000000000000000000000"
	ids := []string{
		string(applied.Attempt.ID), string(retired.Attempt.ID), string(failed.Attempt.ID), "not-an-action",
		string(running.Attempt.ID), unrecorded, string(unknown.Attempt.ID),
	}
	want := []string{string(retired.Attempt.ID), string(failed.Attempt.ID)}
	if got, err := ReadSettledBlockActions(f.db, ids); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("settled = %v, %v; want %v", got, err, want)
	}
	held, err := ReadUnprovenBlockActions(f.db, ids)
	if err != nil || !reflect.DeepEqual(held, []string{string(retired.Attempt.ID), string(failed.Attempt.ID), string(running.Attempt.ID), string(unknown.Attempt.ID)}) {
		t.Fatalf("unproven = %v, %v; want every unverified action", held, err)
	}
	empty, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = empty.Close() })
	if got, readErr := ReadSettledBlockActions(empty, ids); readErr != nil || got != nil {
		t.Fatalf("no ledger: %v, %v", got, readErr)
	}
}

// The owner lists the unresolved intents through its handle: running and
// unknown attempts, not retired ones, in action order.
func TestAdmissionLedgerUnresolvedIntents(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	running, unknown, retired := f.reservedAt("192.0.2.35", expires), f.reservedAt("192.0.2.36", expires), f.reservedAt("192.0.2.37", expires)
	for _, a := range []admission.AttemptRecord{running, unknown, retired} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []admission.AttemptRecord{unknown, retired} {
		if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
			t.Fatal(err)
		}
	}
	f.ackAll()
	f.tickAt(expires.Add(time.Second))
	if _, _, granted, err := f.l.RetireUnproven(retired.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire = %t, %v", granted, err)
	}
	got, err := f.l.UnresolvedIntents()
	if err != nil {
		t.Fatal(err)
	}
	want, err := ReadUnresolvedIntents(f.db)
	if err != nil || len(got) != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("handle intents = %+v, %v; want the two unresolved %+v", got, err, want)
	}
	for _, in := range got {
		if in.Action == retired.Attempt.ID {
			t.Fatal("a retired attempt kept its intent")
		}
	}
}
