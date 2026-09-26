package store

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func TestIngressDrainPreservesWorkOnSharedRecordDamage(t *testing.T) {
	for _, shape := range []string{"ingress", "queue", "counters", "candidate", "entry", "due root"} {
		t.Run(shape, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			id := f.queued()
			candidate, err := f.l.Candidate(id)
			if err != nil {
				t.Fatal(err)
			}
			if shape == "due root" {
				f.tickAt(candidate.AgeOut)
			}
			in := f.ingress()
			for _, target := range []string{"192.0.2.20", "192.0.2.21"} {
				if err = in.Submit(f.submission(evidenceSpec{target: target, cursor: target})); err != nil {
					t.Fatal(err)
				}
			}
			bucket, key := admissionQueueStateBucket, ingressStateKey
			switch shape {
			case "queue":
				key = queueStateKey
			case "counters":
				key = queueCountersKey
			case "candidate":
				bucket, key = admissionCandidatesBucket, []byte(id)
			case "entry":
				bucket, key = admissionQueueBucket, []byte(id)
			case "due root":
				bucket, key = admissionEvidenceBucket, []byte(candidate.Roots[0])
			}
			var good []byte
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(bucket))
				good = append([]byte(nil), b.Get(key)...)
				return b.Put(key, []byte("damaged"))
			}); err != nil {
				t.Fatal(err)
			}
			before, stats := f.snapshot(), in.Stats()
			report, err := in.Drain(f.l, 2, f.requestFor)
			if !isCorrupt(err) || report != (admission.DrainReport{}) || in.Len() != 2 {
				t.Fatalf("shared damage discarded arrivals: report=%+v err=%v held=%d", report, err, in.Len())
			}
			if !reflect.DeepEqual(stats, in.Stats()) || !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("shared damage changed loss counts or committed a checkpoint")
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(bucket)).Put(key, good) }); err != nil {
				t.Fatal(err)
			}
			if report, err = in.Drain(f.l, 2, f.requestFor); err != nil || report != (admission.DrainReport{Queued: 2}) || in.Len() != 0 {
				t.Fatalf("released arrivals could not retry: %+v %v held=%d", report, err, in.Len())
			}
		})
	}
}

func TestIngressRemintOverflowUsesOriginalEvidence(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	original := f.arrival(evidenceSpec{})
	if _, _, err := f.l.EnqueueGroup([]admission.Arrival{original}, nil); err != nil {
		t.Fatal(err)
	}
	in := f.ingress()
	for i := 1; i <= admission.MaxReportLinks+3; i++ {
		if err := in.Submit(f.submission(evidenceSpec{finding: fmt.Sprintf("%016x", i)})); err != nil {
			t.Fatal(err)
		}
	}
	report, err := in.Drain(f.l, 1, f.requestFor)
	if err != nil || report != (admission.DrainReport{Coalesced: 1}) || in.Len() != 0 {
		t.Fatalf("valid remint overflow was lost: %+v %v held=%d", report, err, in.Len())
	}
	links, dropped, err := f.l.Reports(original.Evidence.ID())
	if err != nil || len(links) != admission.MaxReportLinks || dropped != 3 {
		t.Fatalf("remint links=%v dropped=%d err=%v", links, dropped, err)
	}
	if _, err = in.Drain(f.l, 1, f.requestFor); err != nil {
		t.Fatal(err)
	}
	_, again, err := f.l.Reports(original.Evidence.ID())
	if err != nil || again != dropped {
		t.Fatal("remint overflow was counted twice")
	}
}

type fixedQueueSnapshot struct {
	admission.Ledger
	snapshot *admission.QueueSnapshot
}

func (l fixedQueueSnapshot) QueueSnapshot() (*admission.QueueSnapshot, error) {
	return l.snapshot, nil
}

func TestIngressDrainFencesUnpublishedPrecommitSnapshots(t *testing.T) {
	for _, shape := range []string{"failed read", "stale read", "other generation"} {
		t.Run(shape, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			in := f.ingress()
			// Other owner operations advance the database beyond the last
			// snapshot published to ingress, without new memory decisions.
			f.tickAt(f.wall)
			f.tickAt(f.wall)
			stale, err := f.l.QueueSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if err = in.Submit(f.submission(evidenceSpec{})); err != nil {
				t.Fatal(err)
			}
			var ledger admission.Ledger = failingQueueSnapshot{f.l}
			if shape != "failed read" {
				snapshot := *stale
				if shape == "other generation" {
					snapshot.Generation++
					snapshot.Revision++
				}
				ledger = fixedQueueSnapshot{Ledger: f.l, snapshot: &snapshot}
			}
			report, err := in.Drain(ledger, 1, f.requestFor)
			if (shape == "failed read" && err == nil) || report.Queued != 1 || in.Len() != 0 {
				t.Fatalf("expected committed drain: %+v %v held=%d", report, err, in.Len())
			}
			next := f.submission(evidenceSpec{target: "192.0.2.20", cursor: "next"})
			wantLedgerReason(t, "unusable completion snapshot", in.Submit(next), admission.ReasonEngineUnavailable)
			in.Publish(stale)
			wantLedgerReason(t, "delayed precommit snapshot", in.Submit(next), admission.ReasonEngineUnavailable)
			if in.Len() != 0 {
				t.Fatal("precommit snapshot resumed admission")
			}
			current, err := f.l.QueueSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			in.Publish(current)
			if err = in.Submit(next); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type transientIsolationLedger struct {
	admission.Ledger
	calls, failCall int
}

func (l *transientIsolationLedger) EnqueueGroup(a []admission.Arrival, cp *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	l.calls++
	if l.calls == 1 {
		return nil, 0, admission.ErrCorruptRecord
	}
	if l.calls == l.failCall {
		return nil, 0, errors.New("storage temporarily unavailable")
	}
	return l.Ledger.EnqueueGroup(a, cp)
}

func TestIngressIsolationReleasesRemainingHandoffOnTransientError(t *testing.T) {
	for _, committed := range []int{0, 1} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			in := f.ingress()
			for _, target := range []string{"192.0.2.20", "192.0.2.21", "192.0.2.22"} {
				if err := in.Submit(f.submission(evidenceSpec{target: target, cursor: target})); err != nil {
					t.Fatal(err)
				}
			}
			l := &transientIsolationLedger{Ledger: f.l, failCall: 3 + committed}
			report, err := in.Drain(l, 3, f.requestFor)
			if err == nil || report != (admission.DrainReport{Queued: committed}) || in.Len() != 3-committed || f.candidateCount() != committed {
				t.Fatalf("transient isolation error continued the handoff: %+v %v held=%d", report, err, in.Len())
			}
			if report, err = in.Drain(f.l, 3, f.requestFor); err != nil || report != (admission.DrainReport{Queued: 3 - committed}) || in.Len() != 0 {
				t.Fatalf("released handoff could not retry: %+v %v held=%d", report, err, in.Len())
			}
		})
	}
}
