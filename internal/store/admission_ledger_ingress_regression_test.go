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

// isolationSnapshotLedger fails a drain's first group as damaged, captures
// the durable snapshot just before one later group, can fail one group,
// and never serves the drain's own completion snapshot.
type isolationSnapshotLedger struct {
	admission.Ledger
	t                           testing.TB
	calls, captureBefore, fails int
	captured                    *admission.QueueSnapshot
}

func (l *isolationSnapshotLedger) EnqueueGroup(a []admission.Arrival, cp *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	l.calls++
	switch l.calls {
	case 1:
		return nil, 0, admission.ErrCorruptRecord
	case l.fails:
		return nil, 0, errors.New("storage temporarily unavailable")
	case l.captureBefore:
		snap, err := l.Ledger.QueueSnapshot()
		if err != nil {
			l.t.Fatal(err)
		}
		l.captured = snap
	}
	return l.Ledger.EnqueueGroup(a, cp)
}

func (*isolationSnapshotLedger) QueueSnapshot() (*admission.QueueSnapshot, error) {
	return nil, errors.New("snapshot unavailable")
}

// After an isolating drain, a snapshot read before any of its commits is
// stale: the fence is the last committed group, whether that is an
// arrival or the closing checkpoint.
func TestIngressIsolationFencesSnapshotsBetweenCommits(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		captureBefore, fails int
	}{
		// Calls: 1 failed group, 2 probe, 3 the arrival, 4 the checkpoint.
		{"arrival", 3, 4},
		{"checkpoint", 4, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			in := f.ingress()
			if err := in.Submit(f.submission(evidenceSpec{})); err != nil {
				t.Fatal(err)
			}
			l := &isolationSnapshotLedger{Ledger: f.l, t: t, captureBefore: tc.captureBefore, fails: tc.fails}
			report, err := in.Drain(l, 1, f.requestFor)
			if err == nil || report != (admission.DrainReport{Queued: 1}) || in.Len() != 0 || l.captured == nil {
				t.Fatalf("drain = %+v, %v; %d held", report, err, in.Len())
			}
			in.Publish(l.captured)
			next := f.submission(evidenceSpec{target: "192.0.2.20", cursor: "next"})
			wantLedgerReason(t, "snapshot older than the last commit", in.Submit(next), admission.ReasonEngineUnavailable)
		})
	}
}

// Reports acknowledged with a refused request are stored with their
// evidence, so a later report-only tail still records its overflow.
func TestIngressRefusedRequestKeepsReportsAndOverflow(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	in := f.ingress()
	first := f.submission(evidenceSpec{})
	remint := func(i int) {
		t.Helper()
		if err := in.Submit(f.submission(evidenceSpec{finding: fmt.Sprintf("%016x", i)})); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.Submit(first); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		remint(i)
	}
	// While the first group commits, three reports fill the held list and
	// two more overflow it.
	hook := ingressHandoffHook{Ledger: f.l, before: func() {
		for i := 6; i <= 10; i++ {
			remint(i)
		}
	}}
	// The request names other published evidence for the same target, so
	// only the request check can refuse it.
	other := f.submission(evidenceSpec{cursor: "other"})
	if _, err := f.l.PublishEvidence(other.Evidence); err != nil {
		t.Fatal(err)
	}
	report, err := in.Drain(hook, 1, func(s admission.Submission) (admission.CandidateRequest, error) {
		req, reqErr := f.requestFor(s)
		req.Primary = other.Evidence.ID()
		return req, reqErr
	})
	if err != nil || report != (admission.DrainReport{Refused: 1}) || in.Len() != 1 {
		t.Fatalf("refused request = %+v %v held=%d", report, err, in.Len())
	}
	tail, err := in.Drain(f.l, 1, f.requestFor)
	if err != nil || tail.Refused != 0 || in.Len() != 0 {
		t.Fatalf("report tail = %+v %v held=%d", tail, err, in.Len())
	}
	links, dropped, err := f.l.Reports(first.Evidence.ID())
	if err != nil || len(links) != admission.MaxReportLinks || dropped != 2 {
		t.Fatalf("reports=%v dropped=%d err=%v", links, dropped, err)
	}
}
