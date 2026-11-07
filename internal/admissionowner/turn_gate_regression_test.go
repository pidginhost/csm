package admissionowner

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// A policy installed at the turn boundary owns selection eligibility. A
// previous live batch must not delay a dry-run turn whose cadence is due.
func TestOwnerBatchGateUsesNewDryRunPolicy(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, reader, mono := policyOwner(t, f, blocks, validPolicy(1))
	reserve := reserveLedger
	setOwnerHook(t, o, &reserveLedger, func(l *store.AdmissionLedger, id admission.CandidateID, lane admission.Lane, expires time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
		mono.advance(100 * time.Millisecond)
		f.host.advance(100 * time.Millisecond)
		return reserve(l, id, lane, expires)
	})
	first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, first); c.State != admission.StateVerified {
		t.Fatalf("initial block = %+v", c)
	}
	waiting, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	charged := ceiling(t, o).General.Used
	mono.advance(900 * time.Millisecond)
	f.host.advance(900 * time.Millisecond)
	reader.publish(dryPolicy(2))
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, waiting); c.State != admission.StateDryRun || c.Attempts != 0 || ceiling(t, o).General.Used != charged {
		t.Fatalf("old live gate delayed the new dry-run policy: %+v", c)
	}
	if _, applies := blocks.calls(); len(applies) != 1 {
		t.Fatalf("dry-run transition applied %d batches, want 1", len(applies))
	}
}

// Returning from a dry run while an earlier live batch is still gated
// must not spend the next selection before a batch can actually start.
func TestOwnerBatchGateKeepsTurnAfterLivePolicyReturns(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, reader, mono := policyOwner(t, f, blocks, validPolicy(1))
	reserve := reserveLedger
	setOwnerHook(t, o, &reserveLedger, func(l *store.AdmissionLedger, id admission.CandidateID, lane admission.Lane, expires time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
		mono.advance(100 * time.Millisecond)
		f.host.advance(100 * time.Millisecond)
		return reserve(l, id, lane, expires)
	})
	first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, first); c.State != admission.StateVerified {
		t.Fatalf("initial block = %+v", c)
	}
	reader.publish(dryPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	waiting, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	before, charged := candidate(t, o, waiting), ceiling(t, o).General.Used
	mono.advance(900 * time.Millisecond)
	f.host.advance(900 * time.Millisecond)
	reader.publish(validPolicy(3))
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, waiting); !reflect.DeepEqual(c, before) || ceiling(t, o).General.Used != charged {
		t.Fatalf("return to live bypassed the batch gate: %+v", c)
	}
	mono.advance(100 * time.Millisecond)
	f.host.advance(100 * time.Millisecond)
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, waiting); c.State != admission.StateVerified || c.Attempts != 1 || ceiling(t, o).General.Used != charged+1 {
		t.Fatalf("return to live postponed the next batch: %+v", c)
	}
	if _, applies := blocks.calls(); len(applies) != 2 {
		t.Fatalf("return to live applied %d batches, want 2", len(applies))
	}
}

// An opt-out cannot become an outage notice merely because its policy
// arrives during the gap between selection and batch deadlines.
func TestOwnerBatchGateRefusesDisabledBeforeDeferring(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, reader, mono := policyOwner(t, f, blocks, validPolicy(1))
	reserve := reserveLedger
	setOwnerHook(t, o, &reserveLedger, func(l *store.AdmissionLedger, id admission.CandidateID, lane admission.Lane, expires time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
		mono.advance(100 * time.Millisecond)
		f.host.advance(100 * time.Millisecond)
		return reserve(l, id, lane, expires)
	})
	first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, first); c.State != admission.StateVerified {
		t.Fatalf("initial block = %+v", c)
	}
	waiting, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	var before []admission.NoticeRecord
	if err := o.do(func() (err error) { before, err = o.ledger.PendingNotices(); return err }); err != nil {
		t.Fatal(err)
	}
	mono.advance(900 * time.Millisecond)
	f.host.advance(900 * time.Millisecond)
	next := validPolicy(2)
	next.Allows = func(admission.Candidate) bool { return false }
	reader.publish(next)
	if err := o.do(func() error {
		o.hold(firewall.ErrBlockBatchState, false)
		o.schedule()
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, waiting); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
		t.Errorf("disabled work was deferred: %+v", c)
	}
	var notices []admission.NoticeRecord
	if err := o.do(func() (err error) { notices, err = o.ledger.PendingNotices(); return err }); err != nil || !reflect.DeepEqual(notices, before) {
		t.Fatalf("disabled work raised notices: %+v, %v", notices, err)
	}
}

// An arrival inside the turn cadence gets maintenance only. Even there,
// an operator opt-out must not create an execution-outage notice.
func TestOwnerBatchGateKeepsDisabledMaintenanceSilent(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, reader, _ := policyOwner(t, f, blocks, validPolicy(1))
	first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, first); c.State != admission.StateVerified {
		t.Fatalf("initial block = %+v", c)
	}
	waiting, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	var before []admission.NoticeRecord
	if err := o.do(func() (err error) { before, err = o.ledger.PendingNotices(); return err }); err != nil {
		t.Fatal(err)
	}
	next := validPolicy(2)
	next.Allows = func(admission.Candidate) bool { return false }
	reader.publish(next)
	if err := o.do(func() error {
		o.hold(firewall.ErrBlockBatchState, false)
		o.schedule()
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, waiting); c.Reason == admission.ReasonEngineUnavailable || c.Attempts != 0 {
		t.Errorf("disabled work reached execution: %+v", c)
	}
	var notices []admission.NoticeRecord
	if err := o.do(func() (err error) { notices, err = o.ledger.PendingNotices(); return err }); err != nil || !reflect.DeepEqual(notices, before) {
		t.Fatalf("disabled maintenance raised notices: %+v, %v", notices, err)
	}
}

// Expiry during the batch gate must retain the terminal stale ending,
// without first counting or announcing an engine deferral.
func TestOwnerBatchGateRevalidatesExpiredWork(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	stale, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
	age := candidate(t, o, stale).AgeOut.Sub(f.host.now())
	mono.advance(age - batchEvery/2)
	f.host.advance(age - batchEvery/2)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	fresh, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	selectQueue := scheduleLedger
	setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, lim admission.ScheduleLimits, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		return selectQueue(l, lim, map[admission.CandidateID]admission.Answer{stale: admission.AnswerPending})
	})
	turn(t, o)
	if c := candidate(t, o, fresh); c.State != admission.StateVerified {
		t.Fatalf("initial block = %+v", c)
	}
	setOwnerHook(t, o, &scheduleLedger, selectQueue)
	before := candidate(t, o, stale)
	mono.advance(batchEvery / 2)
	f.host.advance(batchEvery / 2)
	if err := o.do(func() error {
		o.hold(firewall.ErrBlockBatchState, false)
		return o.turn()
	}); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, stale); c.State != admission.StateDropped || c.Reason != admission.ReasonStale || c.Transitions != before.Transitions+1 || c.Attempts != 0 {
		t.Fatalf("expired work took an engine deferral: %+v", c)
	}
}
