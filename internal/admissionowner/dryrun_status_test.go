package admissionowner

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/store"
)

func dryRunState(t *testing.T, o *Owner) *health.AdmissionDryRun {
	t.Helper()
	s := o.status()
	if s == nil || s.Owner == nil {
		t.Fatal("no owner status")
	}
	return s.Owner.DryRun
}

// predictionCounts is every prediction name with its count, zeros included.
func predictionCounts(set map[admission.Prediction]uint64) map[string]uint64 {
	out := map[string]uint64{}
	for p := admission.Prediction(1); p.Valid(); p++ {
		out[p.String()] = set[p]
	}
	return out
}

func forecastErrorOf(d *health.AdmissionDryRun) string {
	if d.ForecastError == nil {
		return ""
	}
	return *d.ForecastError
}

func TestOwnerStatusDoesNotExposeCachedForecast(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o, _, _ := policyOwner(t, f, newFakeBlocks(), dryPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	before := dryRunState(t, o)
	id := *before.SessionID
	returned := o.Status().Owner.DryRun
	returned.Picks["capacity_admit"] = 99
	returned.LastHour["capacity_admit"] = 99
	returned.ModelledKinds[0] = "changed"
	*returned.SessionID = "changed"
	returned.Occupancy.Predicted = 99
	returned.Ceiling.Limit = 99
	got := o.Status().Owner.DryRun
	if got.Picks["capacity_admit"] != 1 || got.LastHour["capacity_admit"] != 1 || got.ModelledKinds[0] != "block_ip" ||
		*got.SessionID != id || got.Occupancy.Predicted != 1 || got.Ceiling.Limit != 2000 {
		t.Fatalf("caller mutated the cached forecast: %+v", got)
	}
}

// Spec 3.8: an executable owner in dry run shows its session, the model's
// fixed coverage, real against predicted temporary occupancy with the
// modelled partitions of the automatic slots, the modelled ceiling, every
// prediction counter including zeros, and its process counters. A
// comparison-only owner shows no dry-run object.
func TestOwnerDryRunStatus(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.temp, blocks.limit = 8, 11
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	before := dryRunState(t, o)
	if before == nil || !before.Active || before.SessionID != nil || before.Since != nil || before.ResetReason != nil || before.Occupancy != nil || before.Ceiling != nil {
		t.Fatalf("before a session = %+v", before)
	}
	if !reflect.DeepEqual(before.Picks, predictionCounts(nil)) || !reflect.DeepEqual(before.LastHour, predictionCounts(nil)) {
		t.Fatalf("counters before a session = %v %v", before.Picks, before.LastHour)
	}
	for _, addr := range []string{"192.0.2.10", "2001:db8::10", "192.0.2.11"} {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
	}
	turn(t, o)
	fc := forecastOf(t, o)
	d := dryRunState(t, o)
	if !d.Active || d.SessionID == nil || *d.SessionID != fc.id || d.Since == nil || d.Since.Location() != time.UTC ||
		d.ResetReason == nil || *d.ResetReason != "startup" {
		t.Fatalf("session = %+v", d)
	}
	if !reflect.DeepEqual(d.ModelledKinds, []string{"block_ip"}) || d.PredictionScope != "ceiling_and_temporary_capacity" {
		t.Fatalf("coverage = %v %q", d.ModelledKinds, d.PredictionScope)
	}
	if d.Occupancy == nil || *d.Occupancy != (health.AdmissionDryRunOccupancy{Actual: 8, ShadowOnly: 2, Predicted: 10, Limit: 11, Capacity: 11, Unclaimed: 8,
		General: health.AdmissionDryRunPartition{Size: 2, Used: 2}, Reserved: health.AdmissionDryRunPartition{Size: 1, Free: 1}}) {
		t.Fatalf("occupancy = %+v", d.Occupancy)
	}
	if d.Ceiling == nil || d.Ceiling.Limit != 2000 || d.Ceiling.GeneralUsed+d.Ceiling.ReservedUsed != 2 ||
		d.Ceiling.GeneralBudget != fc.ceiling.Budget(admission.LaneGeneral) || d.Ceiling.ReservedBudget != fc.ceiling.Budget(admission.LaneDirect) {
		t.Fatalf("ceiling = %+v", d.Ceiling)
	}
	want := predictionCounts(map[admission.Prediction]uint64{admission.PredictCapacityAdmit: 2, admission.PredictSetFull: 1})
	if !reflect.DeepEqual(d.Picks, want) || !reflect.DeepEqual(d.LastHour, want) {
		t.Fatalf("picks %v, last hour %v, want %v", d.Picks, d.LastHour, want)
	}
	if d.ExamplesLost != 0 || d.SummariesLost != 0 || d.RecordErrors != 0 || d.ExamplesStale || d.ForecastError != nil || d.LastErrorAt != nil || d.ComparisonIncomplete {
		t.Fatalf("health = %+v", d)
	}
	g := newOwnerFixture(t)
	if s := g.start(previewOptions(g)).status(); s.Owner.DryRun != nil {
		t.Fatalf("a comparison-only owner shows %+v", s.Owner.DryRun)
	}
}

// An unlimited staging set and a model at its bound say so.
func TestOwnerDryRunStatusShowsModelLimits(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if d := dryRunState(t, o); d.Occupancy == nil || !d.Occupancy.Unlimited || d.Occupancy.Limited || d.Occupancy.Predicted != 1 {
		t.Fatalf("unlimited occupancy = %+v", d.Occupancy)
	}
	if err := o.do(func() error {
		for i := len(o.shadow.entries); i < forecastEntries; i++ {
			o.shadow.entries[fmt.Sprintf("model-%d", i)] = shadowEntry{kind: admission.KindBlockIP, expires: f.host.now().Add(time.Hour)}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if d := dryRunState(t, o); d.Occupancy == nil || !d.Occupancy.Limited {
		t.Fatalf("occupancy at the model bound = %+v", d.Occupancy)
	}
}

// Spec 3.8: each cause that stops a forecast is a fixed error code with
// its time. A successful turn clears the code and keeps the time for
// diagnosis; a new session clears both.
func TestOwnerDryRunStatusNamesForecastErrors(t *testing.T) {
	for _, tc := range []struct {
		want  string
		fault func(*testing.T, *Owner, *fakeBlocks, *ownerFixture, *policyReader)
		heal  func(*testing.T, *Owner, *fakeBlocks, *ownerFixture, *policyReader)
	}{
		{"engine_unavailable",
			func(_ *testing.T, _ *Owner, b *fakeBlocks, _ *ownerFixture, _ *policyReader) {
				b.set(func(b *fakeBlocks) { b.checkErr = errors.New("state file unreadable") })
			},
			func(_ *testing.T, _ *Owner, b *fakeBlocks, _ *ownerFixture, _ *policyReader) {
				b.set(func(b *fakeBlocks) { b.checkErr = nil })
			}},
		{"snapshot_mismatch",
			func(_ *testing.T, _ *Owner, b *fakeBlocks, _ *ownerFixture, _ *policyReader) {
				b.set(func(b *fakeBlocks) { b.shortChecks = true })
			},
			func(_ *testing.T, _ *Owner, b *fakeBlocks, _ *ownerFixture, _ *policyReader) {
				b.set(func(b *fakeBlocks) { b.shortChecks = false })
			}},
		{"clock_degraded",
			func(_ *testing.T, _ *Owner, _ *fakeBlocks, f *ownerFixture, _ *policyReader) {
				f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(-time.Minute) })
			},
			func(_ *testing.T, _ *Owner, _ *fakeBlocks, f *ownerFixture, _ *policyReader) {
				f.host.advance(time.Minute + time.Second)
			}},
		{"ledger_unavailable",
			func(t *testing.T, o *Owner, _ *fakeBlocks, _ *ownerFixture, _ *policyReader) {
				failSelection(t, o, true)
			},
			func(t *testing.T, o *Owner, _ *fakeBlocks, _ *ownerFixture, _ *policyReader) {
				failSelection(t, o, false)
			}},
		{"invalid_policy",
			func(_ *testing.T, _ *Owner, _ *fakeBlocks, _ *ownerFixture, r *policyReader) {
				bad := dryPolicy(2)
				bad.VerdictTimeout = 0
				r.publish(bad)
			},
			func(_ *testing.T, _ *Owner, _ *fakeBlocks, _ *ownerFixture, r *policyReader) {
				r.publish(dryPolicy(3))
			}},
	} {
		t.Run(tc.want, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o, r, _ := policyOwner(t, f, blocks, dryPolicy(1))
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.9")
			turn(t, o)
			session := forecastOf(t, o).id
			tc.fault(t, o, blocks, f, r)
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			_ = o.do(o.turn)
			d := dryRunState(t, o)
			if forecastErrorOf(d) != tc.want || d.LastErrorAt == nil || d.LastErrorAt.Location() != time.UTC {
				t.Fatalf("forecast error = %v at %v, want %s", d.ForecastError, d.LastErrorAt, tc.want)
			}
			at := *d.LastErrorAt
			tc.heal(t, o, blocks, f, r)
			turn(t, o)
			d = dryRunState(t, o)
			if d.ForecastError != nil || d.LastErrorAt == nil || !d.LastErrorAt.Equal(at) {
				t.Fatalf("after a good turn: error %v at %v, want none and the time kept", d.ForecastError, d.LastErrorAt)
			}
			if fc := forecastOf(t, o); fc.id != session {
				t.Fatalf("the error started a new session: %s, was %s", fc.id, session)
			}
		})
	}
}

// failSelection makes the forecast's selection fail, or succeed again.
func failSelection(t *testing.T, o *Owner, fail bool) {
	t.Helper()
	next := (*store.AdmissionLedger).SchedulePreview
	if fail {
		next = func(*store.AdmissionLedger, map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
			return nil, errors.New("disk full")
		}
	}
	setOwnerHook(t, o, &previewLedger, next)
}

// A session that cannot be named holds forecasting with its own code; the
// session that starts later clears both the code and its time.
func TestOwnerDryRunStatusNamesASessionIDFailure(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	setOwnerHook(t, o, &sessionRand, io.Reader(strings.NewReader("short")))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err == nil {
		t.Fatal("a forecast started without a session ID")
	}
	if d := dryRunState(t, o); forecastErrorOf(d) != "session_id_unavailable" || d.LastErrorAt == nil || d.SessionID != nil {
		t.Fatalf("status = %+v", d)
	}
	setOwnerHook(t, o, &sessionRand, io.Reader(strings.NewReader(strings.Repeat("a", 16))))
	turn(t, o)
	if d := dryRunState(t, o); d.ForecastError != nil || d.LastErrorAt != nil || d.SessionID == nil || *d.SessionID != strings.Repeat("61", 16) {
		t.Fatalf("status after a session started = %+v", d)
	}
}

// Spec 3.8, 6.4: leaving dry run shows an inactive forecast: no occupancy,
// ceiling or counts, the last session kept for correlation, and process
// counters that a mode flip never resets. Old examples are never shown as
// occupancy. The model failure's own reset names the next session.
func TestOwnerDryRunStatusAfterLeavingDryRun(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, _ := policyOwner(t, f, blocks, dryPolicy(1))
	w := watchExamples(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	w.failWith(errors.New("disk full"))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	session := forecastOf(t, o)
	r.publish(validPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	d := dryRunState(t, o)
	if d.Active || d.SessionID == nil || *d.SessionID != session.id || d.ResetReason == nil || *d.ResetReason != "startup" || d.Since == nil {
		t.Fatalf("session after leaving = %+v", d)
	}
	if d.Occupancy != nil || d.Ceiling != nil || !reflect.DeepEqual(d.Picks, predictionCounts(nil)) || !reflect.DeepEqual(d.LastHour, predictionCounts(nil)) {
		t.Fatalf("forecast after leaving = %+v", d)
	}
	if d.ExamplesLost != 1 || d.RecordErrors != 1 || !d.ExamplesStale || !d.ComparisonIncomplete {
		t.Fatalf("process counters after leaving = %+v", d)
	}
	if f.db.DryRunBlocksCount() != 1 {
		t.Fatalf("fixture: %d stored examples", f.db.DryRunBlocksCount())
	}
	r.publish(dryPolicy(3))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	d = dryRunState(t, o)
	if !d.Active || d.SessionID == nil || *d.SessionID == session.id || *d.ResetReason != "mode_change" {
		t.Fatalf("a new session = %+v", d)
	}
	if d.Occupancy == nil || *d.Occupancy != (health.AdmissionDryRunOccupancy{ShadowOnly: 1, Predicted: 1, Unlimited: true, Capacity: admission.TemporaryCapacity,
		General: health.AdmissionDryRunPartition{Size: 8000, Used: 1, Free: 7999}, Reserved: health.AdmissionDryRunPartition{Size: 2000, Free: 2000}}) {
		t.Fatalf("occupancy of the new session = %+v, with stored examples counted?", d.Occupancy)
	}
}

// Spec 3.6, 3.8: a restart makes the comparison incomplete, since the
// last process's counts and examples may be lost; a first start does not.
func TestOwnerDryRunStatusAfterARestart(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	r := &policyReader{p: dryPolicy(1)}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	if d := dryRunState(t, o); d.ComparisonIncomplete {
		t.Fatalf("a first start = %+v", d)
	}
	o.Stop()
	o = f.start(opts)
	if d := dryRunState(t, o); !d.ComparisonIncomplete {
		t.Fatalf("a restart = %+v", d)
	}
}

// Status divides the automatic slots as the model does: unclaimed entries
// shrink the set, real automatic blocks fill the general partition, each
// forecast block not held by a real one fills its own, and the drain of
// the entries admission never evicts shows in seconds.
func TestShadowOccupancyStatusDividesTheSlots(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	for ip, part := range map[string]admission.Partition{"203.0.113.1": admission.PartitionGeneral, "203.0.113.2": admission.PartitionGeneral, "203.0.113.3": admission.PartitionReserved, "203.0.113.4": admission.PartitionGeneral} {
		s.entries[ip] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: part}
	}
	s.adm = &firewall.BlockAdmission{Temporary: 5, Limit: 20, Unclaimed: 3, Imported: 1, Admission: 1, Drain: 90 * time.Minute, ShadowHeld: map[string]bool{"203.0.113.4": true}}
	want := health.AdmissionDryRunOccupancy{Actual: 5, ShadowOnly: 3, Predicted: 8, Limit: 20, Capacity: 20, Unclaimed: 3, Imported: 1, DrainSeconds: 5400,
		General: health.AdmissionDryRunPartition{Size: 13, Used: 4, Free: 9}, Reserved: health.AdmissionDryRunPartition{Size: 4, Used: 1, Free: 3}}
	if got := s.occupancyStatus(); got == nil || *got != want {
		t.Fatalf("occupancy = %+v, want %+v", got, want)
	}
}

// Address-only execution totals must not hide subnet occupancy in status.
func TestShadowOccupancyStatusIncludesSubnets(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	s.adm = &firewall.BlockAdmission{Temporary: 1, Limit: 5, Unclaimed: 3, Drain: time.Hour}
	s.entries["203.0.113.90"] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: admission.PartitionGeneral}
	got := s.occupancyStatus()
	if got.Actual != 3 || got.ShadowOnly != 1 || got.Predicted != 4 || got.General != (health.AdmissionDryRunPartition{Size: 1, Used: 1}) || got.Reserved != (health.AdmissionDryRunPartition{Size: 1, Free: 1}) {
		t.Fatalf("subnet occupancy: %+v", got)
	}
}

func TestShadowOccupancyStatusKeepsUnknownDrain(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	s.adm = &firewall.BlockAdmission{Temporary: 1, Unclaimed: 1, Drain: -time.Second}
	if got := s.occupancyStatus(); got.DrainSeconds != -1 {
		t.Fatalf("unknown drain lost: %+v", got)
	}
}

// Invalid negative limits follow the zero-limit fallback until validation changes.
func TestShadowOccupancyStatusFiniteFallback(t *testing.T) {
	for _, limit := range []int{0, -1} {
		s := testShadow(t, freshCeiling(t, 2000), nil)
		s.adm = &firewall.BlockAdmission{Limit: limit}
		got := s.occupancyStatus()
		if !got.Unlimited || got.Limit != limit || got.Capacity != admission.TemporaryCapacity || got.General.Size != 8000 || got.Reserved.Size != 2000 {
			t.Fatalf("limit %d: %+v", limit, got)
		}
	}
}
