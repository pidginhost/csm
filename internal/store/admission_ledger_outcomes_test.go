package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// outcomesAt reads span's bucket that holds at.
func (f *ledgerFixture) outcomesAt(span admission.Span, at time.Time) admission.OutcomeCounts {
	f.t.Helper()
	var c admission.OutcomeCounts
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(admissionWindowsBucket)).Get(span.Key(span.Start(at)))
		if raw == nil {
			return nil
		}
		var err error
		c, err = admission.UnmarshalOutcomeCounts(raw)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return c
}

// Every queue event and attempt outcome is counted, in its own
// transaction, into the bucket of each span that holds its time.
func TestAdmissionLedgerCountsOutcomesInWindows(t *testing.T) {
	f := newLedgerFixture(t)
	crit := f.criticalQueued()
	tier := f.entryTier(crit)
	if _, err := f.l.Defer(crit, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Terminate(crit, admission.ReasonCollateral); err != nil {
		t.Fatal(err)
	}
	id, a := f.admitted(time.Hour)
	high := f.entryTier(id)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.applied(time.Hour)
	for _, span := range admission.Spans() {
		c := f.outcomesAt(span, f.wall)
		for k, want := range map[admission.OutcomeKey]uint64{
			admission.QueueOutcome(admission.EventDeferred, admission.ReasonCeiling, tier): 1,
			admission.QueueOutcome(admission.EventEnded, admission.ReasonCollateral, tier): 1,
			admission.AttemptOutcome(admission.DispositionFailed, high):                    1,
			admission.AttemptOutcome(admission.DispositionApplied, high):                   1,
		} {
			if got := c.Count(k); got != want {
				t.Errorf("%v %+v = %d, want %d", span, k, got, want)
			}
		}
	}
	later := f.wall.Add(10 * time.Minute)
	f.tickAt(later)
	f.applied(time.Hour)
	applied := admission.AttemptOutcome(admission.DispositionApplied, high)
	if f.outcomesAt(admission.SpanFiveMinutes, later).Count(applied) != 1 || f.outcomesAt(admission.SpanHour, later).Count(applied) != 2 {
		t.Fatal("a later outcome did not take its own five-minute bucket")
	}
	other := f.criticalQueued()
	f.failNext("defer")
	before := f.outcomesAt(admission.SpanDay, later)
	if _, err := f.l.Defer(other, admission.ReasonCeiling); err == nil {
		t.Fatal("injected failure")
	}
	if got := f.outcomesAt(admission.SpanDay, later); got.Count(admission.QueueOutcome(admission.EventDeferred, admission.ReasonCeiling, tier)) != before.Count(admission.QueueOutcome(admission.EventDeferred, admission.ReasonCeiling, tier)) {
		t.Fatal("a failed deferral was counted")
	}
}

// The ingress's own decisions reach the windows through its checkpoints:
// each checkpoint counts what grew since the last, and Critical losses
// among them raise their notices, with no example.
func TestAdmissionLedgerCountsCheckpointedIngressLosses(t *testing.T) {
	f := newLedgerFixture(t)
	s, err := f.l.BeginIngress()
	if err != nil {
		t.Fatal(err)
	}
	crit := admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityCritical}
	lost := admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonQueueOverflow, Class: crit.Class, Severity: crit.Severity}
	checkpoint := func(seq uint64, n int) *admission.IngressCheckpoint {
		var c admission.QueueCounters
		for i := 0; i < n; i++ {
			if addErr := c.Add(lost); addErr != nil {
				t.Fatal(addErr)
			}
		}
		data, encErr := c.MarshalBinary()
		if encErr != nil {
			t.Fatal(encErr)
		}
		return &admission.IngressCheckpoint{Generation: s.Generation, Sequence: seq, Counters: data}
	}
	key := admission.QueueOutcome(admission.EventRefused, admission.ReasonQueueOverflow, crit)
	notice := admission.NoticeKey{Kind: admission.NoticeCapacity, Reason: admission.ReasonQueueOverflow}
	for _, step := range []struct {
		seq       uint64
		n         int
		windows   uint64
		notices   uint64
		summaries uint64
	}{{1, 3, 3, 3, 3}, {2, 5, 5, 5, 5}, {2, 5, 5, 5, 5}} {
		if _, _, err = f.l.EnqueueGroup(nil, checkpoint(step.seq, step.n)); err != nil {
			t.Fatal(err)
		}
		got := f.notices()
		if w := f.outcomesAt(admission.SpanHour, f.wall).Count(key); w != step.windows || got[notice].Count != step.notices || got[criticalSummary].Count != step.summaries {
			t.Fatalf("after %d: windows %d, notice %+v, summary %+v", step.n, w, got[notice], got[criticalSummary])
		}
		if len(got[notice].Examples) != 0 {
			t.Fatal("a checkpointed loss named an example")
		}
	}
}
