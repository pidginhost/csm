package admissionowner

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

func liveStarted(t *testing.T, o *Owner) bool {
	t.Helper()
	var started bool
	if err := o.do(func() error { started = o.ledger.LiveStarted(); return nil }); err != nil {
		t.Fatal(err)
	}
	return started
}

// refusedForAttribution is the ledger's count of refusals for attribution.
func refusedForAttribution(t *testing.T, o *Owner) uint64 {
	t.Helper()
	var n uint64
	for _, row := range ledgerStatus(t, o).Counters.Rows {
		if row.Event == admission.EventRefused.String() && row.Reason == admission.ReasonAttribution.String() {
			n += row.N
		}
	}
	return n
}

// swapStartLive replaces the ledger's live start for one test; owners the
// test starts later use it from their first start.
func swapStartLive(t *testing.T, fn func(*store.AdmissionLedger, admission.LegacyHandover) error) {
	t.Helper()
	previous := startLiveLedger
	startLiveLedger = fn
	t.Cleanup(func() { startLiveLedger = previous })
}

// previewed runs a previewing owner on f's database that answers addr with
// an observe preview, then stops it.
func previewed(t *testing.T, f *ownerFixture, p *admission.Producer, blocks *fakeBlocks, addr string) {
	t.Helper()
	withLiveExecution(t, false)
	o, _, _ := policyOwner(t, f, blocks, validPolicy(1))
	id := observe(t, o, p, f, addr, "offset=1")
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateObserved {
		t.Fatalf("pick under a live policy = %+v", c)
	}
	o.Stop()
	withLiveExecution(t, true)
}

// Design C7: the first owner that executes carries legacy blocking's state
// over before it serves anything live. The legacy hour counts the greater
// of its count and the preview's charge in it, the pending entry legacy
// would still retry is refused for attribution and the stale one is not,
// and an address a preview answered is blocked on its next observation.
// A restart starts nothing again.
func TestOwnerStartsLiveWhenItFirstExecutes(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	previewed(t, f, p, blocks, "192.0.2.10")
	now := f.host.now()
	f.legacy(fmt.Sprintf(`{"ips":[],"pending":[{"ip":"198.51.100.1","reason":"r","queued_at":%q},{"ip":"198.51.100.2","reason":"r","queued_at":%q}],"blocks_this_hour":9,"hour_key":%q}`,
		now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(-3*time.Hour).Format(time.RFC3339Nano), now.Format("2006-01-02T15")))
	o, _, mono := policyOwner(t, f, blocks, validPolicy(1))
	if !liveStarted(t, o) {
		t.Fatal("the first executing owner did not start live")
	}
	if got := ceiling(t, o).General.Used; got != 9 {
		t.Fatalf("general use = %d, want the legacy hour's 9", got)
	}
	if got := refusedForAttribution(t, o); got != 1 {
		t.Fatalf("pending refusals = %d, want 1", got)
	}
	f.host.advance(time.Second)
	again := observe(t, o, p, f, "192.0.2.10", "offset=2")
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, again); c.State != admission.StateVerified {
		t.Fatalf("previewed address after the live start = %+v", c)
	}
	used := ceiling(t, o).General.Used
	o.Stop()
	calls := 0
	swapStartLive(t, func(l *store.AdmissionLedger, h admission.LegacyHandover) error {
		calls++
		return l.StartLive(h)
	})
	o, _, _ = policyOwner(t, f, blocks, validPolicy(1))
	turn(t, o)
	if calls != 0 || ceiling(t, o).General.Used != used || refusedForAttribution(t, o) != 1 {
		t.Fatalf("a restart started again: %d calls, use %d", calls, ceiling(t, o).General.Used)
	}
}

// The live start waits for live execution: an owner that previews or
// forecasts never runs it, and a live policy a reload installs runs it
// before the reload returns.
func TestOwnerLiveStartWaitsForLiveExecution(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	withLiveExecution(t, false)
	o, _, _ := policyOwner(t, f, newFakeBlocks(), validPolicy(1))
	turn(t, o)
	if liveStarted(t, o) {
		t.Fatal("a previewing owner started live")
	}
	o.Stop()
	withLiveExecution(t, true)
	o, r, _ := policyOwner(t, f, newFakeBlocks(), dryPolicy(1))
	turn(t, o)
	if liveStarted(t, o) {
		t.Fatal("a forecasting owner started live")
	}
	r.publish(validPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	if !liveStarted(t, o) {
		t.Fatal("a reload into a live policy did not start live")
	}
}

// A legacy state file the live start cannot read is not an empty one: the
// ledger keeps no saved credit, and status names the error.
func TestOwnerLiveStartWithoutTheLegacyStateKeepsNoCredit(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	previewed(t, f, p, blocks, "192.0.2.10")
	f.legacy(`{"blocks_this_hour":3}`)
	o, _, _ := policyOwner(t, f, blocks, validPolicy(1))
	if s := ceiling(t, o); !liveStarted(t, o) || s.General.Credit != 0 || s.Reserved.Credit != 0 || s.General.Used != 1 {
		t.Fatalf("ceiling after an unreadable legacy state = %+v", s)
	}
	if st := o.Status(); st.Owner == nil || st.Owner.Import == nil || st.Owner.Import.Error == "" {
		t.Fatalf("status = %+v, want the legacy read error", st.Owner)
	}
}

// Nothing is placed under a live policy before the live start: a drain
// reads the clock first, and a failed live start fails it, so an
// observation held meanwhile is queued once the live start ran, not
// refused as answered by a preview.
func TestOwnerDrainsNothingBeforeTheLiveStart(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	previewed(t, f, p, blocks, "192.0.2.10")
	o, r, _ := policyOwner(t, f, blocks, dryPolicy(1))
	f.host.advance(time.Second)
	submitObservation(t, o, p, "192.0.2.10", "offset=2", f.host.now())
	fail := true
	setOwnerHook(t, o, &startLiveLedger, func(l *store.AdmissionLedger, h admission.LegacyHandover) error {
		if fail {
			return errors.New("ledger busy")
		}
		return l.StartLive(h)
	})
	r.publish(validPolicy(2))
	if err := o.Reload(); err == nil {
		t.Fatal("a failed live start did not fail the reload")
	}
	if err := o.do(o.drain); err == nil || len(queuedCandidates(t, o)) != 0 {
		t.Fatalf("a drain before the live start: %v", err)
	}
	fail = false
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	queued := queuedCandidates(t, o)
	if len(queued) != 1 || queued[0].Key.Target.Key() != "ip:192.0.2.10" {
		t.Fatalf("queued = %+v, want the held observation", queued)
	}
}

// ledgerDeliveries counts the deliveries of ledger notices, leaving out
// the stopped-admission notice.
func ledgerDeliveries(s *noticeSink) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, fs := range s.deliveries {
		if len(fs) > 0 && !strings.HasPrefix(fs[0].Message, "Automatic response admission") {
			n++
		}
	}
	return n
}

// Ledger notices raised before the live start describe gaps legacy
// blocking covered: an executing owner holds them until the live start
// clears them, then delivers later gaps as live alerts.
func TestOwnerHoldsLedgerNoticesUntilTheLiveStart(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	o, r := noticeOwner(t, f, dryPolicy(1), sink)
	criticalGap(t, o, p, f.host)
	fail := true
	setOwnerHook(t, o, &startLiveLedger, func(l *store.AdmissionLedger, h admission.LegacyHandover) error {
		if fail {
			return errors.New("ledger busy")
		}
		return l.StartLive(h)
	})
	r.publish(validPolicy(2))
	if err := o.Reload(); err == nil {
		t.Fatal("a failed live start did not fail the reload")
	}
	o.notices.cycle()
	if n := ledgerDeliveries(sink); n != 0 {
		t.Fatalf("delivered %d notices before the live start", n)
	}
	fail = false
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	o.notices.cycle()
	if n := ledgerDeliveries(sink); n != 0 {
		t.Fatalf("delivered %d preview notices after the live start", n)
	}
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
		t.Fatal(err)
	}
	o.notices.cycle()
	if n := ledgerDeliveries(sink); n != 1 || sink.lastPreview() {
		t.Fatalf("deliveries %d, preview %v; want one live", n, sink.lastPreview())
	}
}
