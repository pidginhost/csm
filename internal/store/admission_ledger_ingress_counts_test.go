package store

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// Every queue drop is counted once in the lifetime counters, as in the
// windowed outcomes: arrivals the ingress refused for want of a position
// as well as those a drain refused (spec 7.1: exact counters for normal
// drops). Status shows the lifetime rows.
func TestIngressRefusalsReachTheLifetimeCounters(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	f.fill(admission.PartitionGeneral.DurableCapacity(), evidenceSpec{owner: f.owner("alice")})
	in := f.ingress()
	refused := 0
	for i := 0; i < admission.IngressPositions+5; i++ {
		sub := f.submission(evidenceSpec{owner: f.owner("alice"), target: fmt.Sprintf("2001:db8:1::%x", i+1), cursor: fmt.Sprint(i)})
		if err := in.Submit(sub); err != nil {
			wantLedgerReason(t, "submission past the positions", err, admission.ReasonQueueOverflow)
			refused++
		}
	}
	if refused != 5 {
		t.Fatalf("fixture: ingress refused %d, want 5", refused)
	}
	for in.Len() > 0 {
		if _, err := in.Drain(f.l, admission.MaxArrivalGroup, f.requestFor); err != nil {
			t.Fatal(err)
		}
	}
	key := admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonQueueOverflow, Class: admission.ClassC2, Severity: admission.SeverityHigh}
	lifetime := f.count(key)
	var hour uint64
	s := f.l.Status()
	for _, row := range s.Outcomes.Hour {
		if row.Event == key.Event.String() && row.Reason == key.Reason.String() {
			hour += row.N
		}
	}
	var shown uint64
	for _, row := range s.Counters.Rows {
		if row.Event == key.Event.String() && row.Reason == key.Reason.String() {
			shown += row.N
		}
	}
	if lifetime != uint64(admission.IngressPositions+5) || lifetime != hour || shown != lifetime {
		t.Fatalf("lifetime %d, status %d, hour %d; %d refused at the ingress", lifetime, shown, hour, refused)
	}
}

// A checkpoint without arrivals has no queue event to dirty the lifetime
// counters. Commit failure, replay and a new generation must not double it.
func TestIngressRefusalsCheckpointOnly(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	in := f.ingress()
	key := admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonQueueOverflow}
	want := uint64(0)
	assertCounts := func() {
		t.Helper()
		if got := f.count(key); got != want {
			t.Fatalf("checkpoint-only lifetime %d, want %d", got, want)
		}
		for _, span := range admission.Spans() {
			outcome := admission.QueueOutcome(key.Event, key.Reason, admission.Tier{})
			if got := f.outcomesAt(span, f.wall).Count(outcome); got != want {
				t.Fatalf("checkpoint-only %v count %d, want %d", span, got, want)
			}
		}
	}
	for generation := 0; generation < 2; generation++ {
		if generation != 0 {
			path := filepath.Dir(f.db.bolt.Path())
			if err := f.db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			f.db = db
			f.l, err = OpenAdmissionLedger(db, f.reg)
			if err != nil {
				t.Fatal(err)
			}
			f.tickAt(f.wall)
			f.begin()
			in = f.ingress()
			assertCounts()
			cp := in.Checkpoint()
			if cp.Sequence != 0 {
				t.Fatalf("new ingress sequence %d, want 0", cp.Sequence)
			}
			if _, _, err = f.l.EnqueueGroup(nil, &cp); err != nil {
				t.Fatal(err)
			}
			assertCounts()
		}
		for range 3 {
			in.Refuse(&admission.Error{Reason: key.Reason}, admission.SeverityHigh)
		}
		cp := in.Checkpoint()
		before := f.snapshot()
		f.failNext("group")
		if _, _, err := f.l.EnqueueGroup(nil, &cp); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatal("failed checkpoint changed durable state")
		}
		assertCounts()
		if _, _, err := f.l.EnqueueGroup(nil, &cp); err != nil {
			t.Fatal(err)
		}
		want += 3
		assertCounts()
		before = f.snapshot()
		if _, _, err := f.l.EnqueueGroup(nil, &cp); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatalf("repeated checkpoint changed durable state: %v", err)
		}
		assertCounts()
	}
}

// The direct queue writer already counts both destinations. Adding ingress
// checkpoint accounting must not count these transitions a second time.
func TestIngressRefusalsKeepDirectQueueCountsExact(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	tier := f.entryTier(id)
	if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Terminate(id, admission.ReasonProtected); err != nil {
		t.Fatal(err)
	}
	for _, key := range []admission.CountKey{
		{Event: admission.EventDeferred, Reason: admission.ReasonCeiling, Class: tier.Class, Severity: tier.Severity},
		{Event: admission.EventEnded, Reason: admission.ReasonProtected, Class: tier.Class, Severity: tier.Severity},
	} {
		if got := f.count(key); got != 1 {
			t.Fatalf("direct queue lifetime %+v = %d, want 1", key, got)
		}
		for _, span := range admission.Spans() {
			if got := f.outcomesAt(span, f.wall).Count(admission.QueueOutcome(key.Event, key.Reason, tier)); got != 1 {
				t.Fatalf("direct queue %v %+v = %d, want 1", span, key, got)
			}
		}
	}
}
