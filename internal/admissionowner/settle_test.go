package admissionowner

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// A process that stopped with one attempt reserved and another running
// left both outstanding. The next owner settles them at start, before its
// first turn: the reserved one dispatched nothing, so it fails and its
// candidate waits out the retry backoff; the running one may have applied
// its effect, so it ends unknown and holds its target. Neither runs again.
func TestOwnerStartSettlesWhatAStoppedProcessLeft(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	first := f.start(f.options())
	reservedID, now := queuedAt(t, first, p, f.host, admission.SeverityHigh, "192.0.2.10")
	runningID, _ := queuedAt(t, first, p, f.host, admission.SeverityHigh, "192.0.2.11")
	if err := first.do(func() error {
		if _, _, _, err := first.ledger.Reserve(reservedID, admission.LaneGeneral, now.Add(time.Hour)); err != nil {
			return err
		}
		_, a, _, err := first.ledger.Reserve(runningID, admission.LaneGeneral, now.Add(time.Hour))
		if err != nil {
			return err
		}
		_, _, _, err = first.ledger.Execute(a.Attempt.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	first.Stop()

	next := f.start(f.options())
	if s := next.Status(); s == nil || s.Owner == nil || s.Owner.Error != "" {
		t.Fatalf("status after start = %+v", s)
	}
	var reserved, running admission.Candidate
	if err := next.do(func() (err error) {
		if reserved, err = next.ledger.Candidate(reservedID); err != nil {
			return err
		}
		running, err = next.ledger.Candidate(runningID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if reserved.State != admission.StateQueued || reserved.Attempts != 1 || !reserved.NotBefore.After(now) {
		t.Fatalf("reserved candidate after start = %+v", reserved)
	}
	if running.State != admission.StateUnknown || running.Disposition != admission.DispositionUnknown {
		t.Fatalf("running candidate after start = %+v", running)
	}
	if s := ledgerStatus(t, next); s.Unresolved.Unknown != 1 || s.Unresolved.Running != 0 {
		t.Fatalf("unresolved after start = %+v", s.Unresolved)
	}
}

// An owner that cannot settle does not start: its first turn could reserve
// over work a previous process left running. Status says why.
func TestOwnerStartWaitsForSettlement(t *testing.T) {
	f := newOwnerFixture(t)
	prev := settleLedger
	settleLedger = func(*store.AdmissionLedger) (int, int, error) { return 0, 0, errors.New("disk read failed") }
	o := f.start(f.options())
	t.Cleanup(func() {
		o.Stop()
		settleLedger = prev
	})
	s := o.Status()
	if s == nil || s.Owner == nil || !strings.Contains(s.Owner.Error, "settling outstanding attempts: disk read failed") {
		t.Fatalf("status after a failed settlement = %+v", s)
	}
	var started bool
	if err := o.do(func() error { started = o.started; return nil }); err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("the owner started without settling")
	}
}

func TestOwnerStartRetriesSettlementOnTheSameHandle(t *testing.T) {
	f := newOwnerFixture(t)
	previousSettle, previousSnapshot := settleLedger, readSnapshot
	settles, snapshots := 0, 0
	settleLedger = func(l *store.AdmissionLedger) (int, int, error) {
		settles++
		if settles == 1 {
			return 0, 0, errors.New("settlement unavailable")
		}
		return previousSettle(l)
	}
	readSnapshot = func(l *store.AdmissionLedger) (*admission.QueueSnapshot, error) {
		snapshots++
		if snapshots == 1 {
			return nil, errors.New("snapshot unavailable")
		}
		return previousSnapshot(l)
	}
	o := f.start(f.options())
	t.Cleanup(func() { o.Stop(); settleLedger, readSnapshot = previousSettle, previousSnapshot })
	if err := o.do(func() error {
		original := o.ledger
		if original == nil || o.started || settles != 1 || snapshots != 0 {
			return errors.New("startup continued after settlement failed")
		}
		o.startErr = o.start()
		if o.startErr == nil || !strings.Contains(o.startErr.Error(), "snapshot unavailable") || o.started || o.ledger != original {
			return errors.New("failed startup retry replaced or started the handle")
		}
		o.startErr = o.start()
		if o.startErr != nil {
			return o.startErr
		}
		if !o.started || o.ledger != original || settles != 3 || snapshots != 2 || !o.ingress.Health().Admitting {
			return errors.New("startup retry did not reuse and admit on its handle")
		}
		if status := o.ledger.Status(); status.Unresolved.Running != 0 || status.Unresolved.Unknown != 0 {
			return errors.New("startup retries created outstanding work")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
