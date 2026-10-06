package store

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// The missing queue entry is met only by arrivals for its target, so an
// empty group and unrelated arrivals still commit.
func damageArrivalTarget(t *testing.T, f *ledgerFixture) {
	t.Helper()
	id := f.arrive(f.arrival(evidenceSpec{cursor: "damaged"}))[0].Candidate
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueBucket)).Delete([]byte(id))
	}); err != nil {
		t.Fatal(err)
	}
}

type failureAfterIsolation struct {
	admission.Ledger
	stage       string
	fault       error
	checkpoints int
}

func (l *failureAfterIsolation) EnqueueGroup(a []admission.Arrival, cp *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	if len(a) == 0 {
		l.checkpoints++
		if l.stage == "checkpoint" && l.checkpoints == 2 {
			return nil, 0, l.fault
		}
	}
	if l.stage == "arrival" && len(a) == 1 && a[0].Request.Target.Prefix().Addr().String() == "192.0.2.20" {
		return nil, 0, l.fault
	}
	return l.Ledger.EnqueueGroup(a, cp)
}

func (l *failureAfterIsolation) QueueSnapshot() (*admission.QueueSnapshot, error) {
	if l.stage == "snapshot" {
		return nil, l.fault
	}
	return l.Ledger.QueueSnapshot()
}

// Once an arrival is lost to damage, a later failure must retain that
// cause without treating the failed drain as successful isolation.
func TestIngressDrainRetainsDamageWithALaterFailure(t *testing.T) {
	for _, stage := range []string{"arrival", "checkpoint", "snapshot"} {
		t.Run(stage, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			damageArrivalTarget(t, f)
			in := f.ingress()
			for _, target := range []string{"192.0.2.10", "192.0.2.20", "192.0.2.21"} {
				if err := in.Submit(f.submission(evidenceSpec{target: target, cursor: target})); err != nil {
					t.Fatal(err)
				}
			}
			fault := errors.New("storage temporarily unavailable")
			report, err := in.Drain(&failureAfterIsolation{Ledger: f.l, stage: stage, fault: fault}, 3, f.requestFor)
			if !errors.Is(err, fault) || !errors.Is(err, admission.ErrCorruptRecord) || errors.Is(err, admission.ErrArrivalsIsolated) {
				t.Errorf("mixed failure lost a cause or claimed success: %v", err)
			}
			queued, held := 2, 0
			if stage == "arrival" {
				queued, held = 0, 2
			}
			if report != (admission.DrainReport{Queued: queued, Failed: 1}) || in.Len() != held || in.Health().Admitting {
				t.Fatalf("failed drain: %+v, %d held, admitting %v", report, in.Len(), in.Health().Admitting)
			}
			// Only the undamaged suffix is retried; committed arrivals and
			// the discarded arrival must never create work again.
			report, err = in.Drain(f.l, 3, f.requestFor)
			if err != nil || report != (admission.DrainReport{Queued: held}) || in.Len() != 0 || !in.Health().Admitting {
				t.Fatalf("recovery: %+v, %v, %d held", report, err, in.Len())
			}
			snap, err := f.l.QueueSnapshot()
			if err != nil || len(snap.Items) != 2 {
				t.Fatalf("healthy arrivals after recovery: %+v, %v", snap, err)
			}
		})
	}
}

func TestIngressDrainIsolatesEveryDamagedArrival(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	damageArrivalTarget(t, f)
	in := f.ingress()
	for _, cursor := range []string{"hit-1", "hit-2", "hit-3"} {
		if err := in.Submit(f.submission(evidenceSpec{cursor: cursor})); err != nil {
			t.Fatal(err)
		}
	}
	report, err := in.Drain(f.l, 3, f.requestFor)
	if !errors.Is(err, admission.ErrArrivalsIsolated) || !errors.Is(err, admission.ErrCorruptRecord) || report != (admission.DrainReport{Failed: 3}) || in.Len() != 0 || !in.Health().Admitting {
		t.Fatalf("all damaged arrivals: %+v, %v, %d held, admitting %v", report, err, in.Len(), in.Health().Admitting)
	}
	if err = in.Submit(f.submission(evidenceSpec{target: "192.0.2.20", cursor: "healthy"})); err != nil {
		t.Fatal(err)
	}
	if report, err = in.Drain(f.l, 1, f.requestFor); err != nil || report != (admission.DrainReport{Queued: 1}) {
		t.Fatalf("healthy arrival after isolation: %+v, %v", report, err)
	}
}
