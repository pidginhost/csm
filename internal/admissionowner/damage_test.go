package admissionowner

import (
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

type failingDamagedTargetLedger struct {
	damagedTargetLedger
	stage       string
	fault       error
	checkpoints int
}

func (l *failingDamagedTargetLedger) EnqueueGroup(a []admission.Arrival, cp *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	if len(a) == 0 {
		l.checkpoints++
		if l.stage == "checkpoint" && l.checkpoints == 2 {
			return nil, 0, l.fault
		}
	}
	if l.stage == "arrival" && len(a) == 1 && a[0].Request.Target != l.bad {
		return nil, 0, l.fault
	}
	return l.damagedTargetLedger.EnqueueGroup(a, cp)
}

func (l *failingDamagedTargetLedger) QueueSnapshot() (*admission.QueueSnapshot, error) {
	if l.stage == "snapshot" {
		return nil, l.fault
	}
	return l.Ledger.QueueSnapshot()
}

// Recovery from a write or publication failure cannot hide arrivals lost
// to damage earlier in that same drain.
func TestOwnerRetainsDamageAfterAFailedDrainRecovers(t *testing.T) {
	for _, stage := range []string{"arrival", "checkpoint", "snapshot"} {
		t.Run(stage, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			sink := &noticeSink{}
			opts := f.options()
			opts.Deliver = sink.deliver
			o := f.start(opts)
			bad, err := admission.CanonicalAddress("192.0.2.66", admission.Caps{IPv6: true})
			if err != nil {
				t.Fatal(err)
			}
			prev := drainGroupOf
			fault := errors.New("storage temporarily unavailable")
			setOwnerHook(t, o, &drainGroupOf, func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
				return in.DrainTaken(&failingDamagedTargetLedger{
					damagedTargetLedger: damagedTargetLedger{Ledger: l, bad: bad}, stage: stage, fault: fault,
				}, items, arrivalRequest)
			})
			for _, addr := range []string{"192.0.2.66", "192.0.2.20", "192.0.2.21"} {
				submitTo(t, o, p, addr, f.host.now())
			}
			if err = o.do(o.drain); !errors.Is(err, fault) || errors.Is(err, admission.ErrArrivalsIsolated) {
				t.Fatalf("mixed failure succeeded or lost the drain cause: %v", err)
			}
			st := o.Status()
			if st.Ingress.Admitting || !strings.Contains(st.Owner.Error, fault.Error()) {
				t.Fatalf("failed drain did not stop admission: %+v %+v", st.Owner, st.Ingress)
			}
			if !strings.Contains(st.Owner.DamageError, admission.ErrCorruptRecord.Error()) {
				t.Errorf("discarded arrival's damage was not published: %+v", st.Owner)
			}
			damage := st.Owner.DamageError
			o.notices.cycle()
			// Ticks, inventory and reload recovery must preserve both the
			// admission hold and its independent damage signal.
			setOwnerHook(t, o, &drainGroupOf, prev)
			if err = o.do(o.tick); err != nil {
				t.Fatal(err)
			}
			if err = o.do(func() error { o.refreshInventory(); return nil }); err != nil {
				t.Fatal(err)
			}
			if err = o.Reload(); err != nil {
				t.Fatal(err)
			}
			st = o.Status()
			if st.Ingress.Admitting || !strings.Contains(st.Owner.Error, fault.Error()) || st.Owner.DamageError != damage {
				t.Fatalf("other recovery hid the drain failure or damage: %+v %+v", st.Owner, st.Ingress)
			}
			o.notices.cycle()
			if sink.count() != 1 {
				t.Fatalf("lasting drain failure announced %d stops, want one", sink.count())
			}
			if err = o.do(o.drain); err != nil {
				t.Fatal(err)
			}
			st = o.Status()
			if !st.Ingress.Admitting || st.Owner.Error != "" || len(queuedCandidates(t, o)) != 2 || o.ingress.Len() != 0 {
				t.Fatalf("drain did not recover the healthy arrivals: %+v %+v", st.Owner, st.Ingress)
			}
			if st.Owner.DamageError == "" || st.Owner.DamageError != damage {
				t.Errorf("drain recovery cleared the damage signal: %+v", st.Owner)
			}
			o.Stop()
			o = f.start(opts)
			if st = o.Status(); st.Owner.DamageError != "" || st.Owner.Error != "" || !st.Ingress.Admitting {
				t.Fatalf("restart retained process-local damage: %+v %+v", st.Owner, st.Ingress)
			}
		})
	}
}
