package store

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Design C7: the live start runs once, in one transaction that writes its
// marker and raises the schema, so a build that predates it refuses the
// ledger. A second call refuses without a write, and a reopened handle
// knows it ran.
func TestAdmissionLedgerLiveStartRunsOnce(t *testing.T) {
	f := newLedgerFixture(t)
	if f.l.LiveStarted() {
		t.Fatal("a new ledger has started live")
	}
	stale, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stale.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerBoot, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	if err = f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	if !f.l.LiveStarted() || f.schema() != admissionSchemaLive {
		t.Fatalf("started %v at schema %d", f.l.LiveStarted(), f.schema())
	}
	before := f.snapshot()
	again := admission.LegacyHandover{Spend: admission.LegacySpend{Units: 5, At: f.wall}}
	wantLedgerErr(t, "a second live start", f.l.StartLive(again), admission.ErrTransitionConflict)
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.LiveStarted() {
		t.Fatal("a reopened ledger forgot its live start")
	}
	wantLedgerErr(t, "a live start after reopening", reopened.StartLive(again), admission.ErrTransitionConflict)
	wantLedgerErr(t, "a live start through a handle opened before it", stale.StartLive(again), admission.ErrTransitionConflict)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused live start changed the ledger")
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueStateBucket)).Put(liveStartKey, []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("a damaged live start record opened: %v", err)
	}
}

// A failed live start leaves the ledger as it was and can run again. It
// needs a reading this handle recorded.
func TestAdmissionLedgerFailedLiveStartChangesNothing(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	f.observedArrival("192.0.2.10", "offset=1")
	h := admission.LegacyHandover{
		Spend:   admission.LegacySpend{Units: 9, At: f.wall.Add(30 * time.Minute)},
		Pending: 2,
	}
	before := f.snapshot()
	f.failNext("live start")
	if err := f.l.StartLive(h); err == nil {
		t.Fatal("injected failure did not abort the live start")
	}
	if f.l.LiveStarted() || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed live start changed the ledger")
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	wantLedgerReason(t, "without a reading", reopened.StartLive(h), admission.ReasonEngineUnavailable)
	if err := f.l.StartLive(h); err != nil || !f.l.LiveStarted() {
		t.Fatalf("retried live start: %v", err)
	}
}

// The legacy hour counts the greater of its count and the ledger's
// retained charges in that hour, never their sum: previews and legacy
// blocking describe the same responses. The hour is the window that ends
// at its end; a charge at the hour's start belongs to the hour before.
func TestAdmissionLedgerLiveStartCarriesTheGreaterHour(t *testing.T) {
	for _, tc := range []struct {
		name     string
		previews int
		units    uint32
		end      time.Duration
		extra    uint32
	}{
		{"legacy counted more", 3, 10, 30 * time.Minute, 7},
		{"previews counted more", 5, 3, 30 * time.Minute, 0},
		{"previews before the hour", 2, 4, time.Hour, 4},
		{"no legacy count", 2, 0, 30 * time.Minute, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			for i := range tc.previews {
				f.observedArrival(fmt.Sprintf("192.0.2.%d", 10+i), "offset=1")
			}
			before, charges := f.ceilingState(), f.charges()
			end := ledgerT0.Add(tc.end)
			if err := f.l.StartLive(admission.LegacyHandover{Spend: admission.LegacySpend{Units: tc.units, At: end}}); err != nil {
				t.Fatal(err)
			}
			after := f.ceilingState()
			want := carriedPreviewCharges(charges)
			if tc.extra > 0 {
				want = append(want, admission.Charge{At: end, Action: admission.LiveStartActionID(end, 1), Lane: admission.LaneGeneral, Cost: tc.extra, Elapsed: before.Elapsed})
			}
			if got := f.charges(); !reflect.DeepEqual(got, want) {
				t.Fatalf("charges = %+v, want %+v", got, want)
			}
			if after.General.Used != before.General.Used+tc.extra || after.General.Credit != before.General.Credit-uint64(tc.extra)*uint64(time.Hour) || after.Reserved != before.Reserved {
				t.Fatalf("ceiling %+v after %+v, want %d more units used and spent", after, before, tc.extra)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("reopening a carried ledger: %v", err)
			}
		})
	}
}

// Charges a first start imported for the same hour, and previews in it,
// are the same legacy units: the live start charges only what legacy
// counted beyond them, and a later forecast keeps the whole hour. The first
// import's status reading stays its own.
func TestAdmissionLedgerLiveStartCountsTheImportedHourOnce(t *testing.T) {
	f := newLedgerFixture(t)
	f.newUnlimitedLedger()
	f.tickAt(f.wall)
	end := f.wall.Add(20 * time.Minute)
	if err := f.l.ImportLegacySpend(2000, admission.LegacySpend{Units: 12, At: end}); err != nil {
		t.Fatal(err)
	}
	f.begin()
	f.observedArrival("192.0.2.10", "offset=1")
	if err := f.l.StartLive(admission.LegacyHandover{Spend: admission.LegacySpend{Units: 15, At: end}}); err != nil {
		t.Fatal(err)
	}
	if s := f.ceilingState(); s.General.Used != 15 {
		t.Fatalf("used = %d, want 15", s.General.Used)
	}
	if got, err := f.l.ImportedLegacySpend(); err != nil || got.Units != 12 || !got.At.Equal(end) {
		t.Fatalf("imported spend = %+v, %v", got, err)
	}
	if seed, _, err := f.l.ForecastSeed(); err != nil || seed.General.Used != 15 {
		t.Fatalf("forecast seed = %+v, %v; want the whole hour", seed, err)
	}
}

// A first import of an earlier hour may still be retained when the live
// start carries a later one: both stay, under their own names, so the
// first import's status reading and the ledger's proofs still hold.
func TestAdmissionLedgerLiveStartBesideAnEarlierImportedHour(t *testing.T) {
	f := newLedgerFixture(t)
	f.newUnlimitedLedger()
	f.tickAt(f.wall)
	first := f.wall.Add(20 * time.Minute)
	if err := f.l.ImportLegacySpend(2000, admission.LegacySpend{Units: 12, At: first}); err != nil {
		t.Fatal(err)
	}
	f.tickAt(first.Add(10 * time.Minute))
	later := first.Add(time.Hour)
	if err := f.l.StartLive(admission.LegacyHandover{Spend: admission.LegacySpend{Units: 5, At: later}}); err != nil {
		t.Fatal(err)
	}
	if s := f.ceilingState(); s.General.Used != 17 {
		t.Fatalf("used = %d, want both hours' 17", s.General.Used)
	}
	if got, err := f.l.ImportedLegacySpend(); err != nil || got.Units != 12 || !got.At.Equal(first) {
		t.Fatalf("imported spend = %+v, %v", got, err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening both hours: %v", err)
	}
}

// A legacy counter the live start could not read keeps no saved credit,
// as a failed first import grants none.
func TestAdmissionLedgerLiveStartWithoutTheLegacyCountKeepsNoCredit(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	f.observedArrival("192.0.2.10", "offset=1")
	before, charges := f.ceilingState(), f.charges()
	if err := f.l.StartLive(admission.LegacyHandover{Spend: admission.LegacySpend{Unknown: true}}); err != nil {
		t.Fatal(err)
	}
	s := f.ceilingState()
	if s.General != (admission.Meter{Used: before.General.Used}) || s.Reserved != (admission.Meter{Used: before.Reserved.Used}) || !reflect.DeepEqual(f.charges(), carriedPreviewCharges(charges)) {
		t.Fatalf("ceiling = %+v, want no credit and the same %d charges", s, len(charges))
	}
}

// Legacy pending entries carry no observation, so admission counts each
// as refused for attribution, unassessed, as it counts a finding refused
// without evidence; none raises a notice.
func TestAdmissionLedgerLiveStartRefusesLegacyPending(t *testing.T) {
	f := newLedgerFixture(t)
	notices := f.notices()
	if err := f.l.StartLive(admission.LegacyHandover{Pending: 3}); err != nil {
		t.Fatal(err)
	}
	if got := f.countOf(admission.EventRefused, admission.ReasonAttribution, admission.Tier{}); got != 3 {
		t.Errorf("refusals = %d, want 3", got)
	}
	if got := f.notices(); !reflect.DeepEqual(got, notices) {
		t.Errorf("pending refusals raised notices: %+v", got)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening after refused pending entries: %v", err)
	}
}

func carriedPreviewCharges(charges []admission.Charge) []admission.Charge {
	out := append([]admission.Charge(nil), charges...)
	for i := range out {
		out[i].Action = admission.LiveStartPreviewActionID(out[i].Action)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := out[i].Key()
		b, _ := out[j].Key()
		return bytes.Compare(a, b) < 0
	})
	return out
}

// A live start preserves the identity and deadlines of real attempts,
// including failed and unresolved ones, beside its carried previews.
func TestAdmissionLedgerLiveStartPreservesRealCharges(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	for i, disposition := range []admission.Disposition{admission.DispositionApplied, admission.DispositionFailed, admission.DispositionUnknown} {
		result := f.arrive(f.arrival(evidenceSpec{target: fmt.Sprintf("192.0.2.%d", i+10), cursor: "offset=1"}))[0]
		if result.Err != nil || !result.Created {
			t.Fatalf("real arrival: %+v", result)
		}
		f.finishArrival(result.Candidate, f.wall.Add(time.Hour), disposition)
	}
	real := f.charges()
	if len(real) != 3 {
		t.Fatalf("real charges = %d, want 3", len(real))
	}
	_, preview := f.observedArrival("192.0.2.20", "offset=1")
	before := f.ceilingState()
	if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	want := map[admission.ActionID]admission.Charge{}
	for _, c := range real {
		want[c.Action] = c
	}
	want[admission.LiveStartPreviewActionID(preview.Attempt.ID)] = admission.Charge{
		At: preview.Reserved, Action: admission.LiveStartPreviewActionID(preview.Attempt.ID),
		Lane: preview.Lane, Cost: 1, Elapsed: before.Elapsed,
	}
	seed, kept, err := f.l.ForecastSeed()
	if err != nil || seed != before || len(kept) != len(want) {
		t.Fatalf("carried forecast: seed=%+v charges=%+v err=%v", seed, kept, err)
	}
	for _, c := range kept {
		if expected, ok := want[c.Action]; !ok || c != expected {
			t.Errorf("changed real or carried charge: %+v", c)
		}
		delete(want, c.Action)
	}
	if len(want) != 0 {
		t.Fatalf("missing charges: %+v", want)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}
