package admissionowner

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// A successful inventory read cannot override a refused clock reading.
func TestOwnerInventoryCannotResumeAfterClockFailure(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	if err := o.do(o.tick); err == nil {
		t.Fatal("failed clock reading succeeded")
	}
	if err := o.do(func() error { o.refreshInventory(); return nil }); err != nil {
		t.Fatal(err)
	}
	if h := o.ingress.Health(); h.Admitting {
		t.Fatal("inventory resumed admission without a good clock reading")
	}
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	if h := o.ingress.Health(); !h.Admitting {
		t.Fatal("good clock reading did not resume admission")
	}
}

// A publication failure must close the cached health view immediately.
func TestOwnerPublishesSnapshotFailureStatusImmediately(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	setOwnerHook(t, o, &readSnapshot, func(*store.AdmissionLedger) (*admission.QueueSnapshot, error) {
		return nil, errors.New("snapshot unavailable")
	})
	if err := o.do(o.tick); err == nil {
		t.Fatal("failed snapshot read succeeded")
	}
	if st := o.Status(); st.Ingress.Admitting || !strings.Contains(st.Owner.Error, "snapshot unavailable") {
		t.Fatalf("cached status hides the failed publication: %+v %+v", st.Ingress, st.Owner)
	}
}

// A good reading clears the clock error even if publication still fails.
func TestOwnerRefreshesStatusWhileAdmissionRemainsStopped(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	if err := o.do(o.tick); err == nil {
		t.Fatal("failed clock reading succeeded")
	}
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	setOwnerHook(t, o, &readSnapshot, func(*store.AdmissionLedger) (*admission.QueueSnapshot, error) {
		return nil, errors.New("snapshot unavailable")
	})
	if err := o.do(o.tick); err == nil {
		t.Fatal("failed snapshot read succeeded")
	}
	if st := o.Status(); st.Ingress.Admitting || st.Owner.TickError != "" || !strings.Contains(st.Owner.Error, "snapshot unavailable") {
		t.Fatalf("cached status kept the old stop cause: %+v %+v", st.Ingress, st.Owner)
	}
}

// Both stoppers wait for a sender blocked in do, without repeating shutdown.
func TestOwnerConcurrentStopsReleaseBlockedSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newOwnerFixture(t)
		opts := f.options()
		opts.NoticeEvery = time.Millisecond
		opts.Deliver = func([]alert.Finding, bool) error { t.Error("healthy ingress produced a notice"); return nil }
		o := f.start(opts)
		entered, release, requestDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			requestDone <- o.do(func() error { close(entered); <-release; return nil })
		}()
		<-entered
		time.Sleep(time.Millisecond)
		synctest.Wait()
		var stoppers sync.WaitGroup
		stoppers.Go(o.Stop)
		synctest.Wait()
		if !o.stopping.Load() {
			t.Error("Stop did not begin while the owner request was blocked")
		}
		secondEntered := make(chan struct{})
		stoppers.Go(func() { close(secondEntered); o.Stop() })
		<-secondEntered
		// Mutex waiters are not durably blocked for synctest.Wait.
		close(release)
		stoppers.Wait()
		if err := <-requestDone; err != nil {
			t.Fatal(err)
		}
		select {
		case <-o.notices.done:
		default:
			t.Fatal("Stop returned before the blocked sender exited")
		}
		if f.host.reads != 2 || o.Status().Ingress.Admitting || o.Status().Ledger.Ingress.Open {
			t.Fatalf("shutdown was repeated or incomplete: reads=%d status=%+v", f.host.reads, o.Status())
		}
	})
}
