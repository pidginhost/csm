package admissionowner

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// scopedRank ranks fresh pick n at ip with tier in scope.
func scopedRank(t *testing.T, n byte, ip string, tier admission.Tier, scope string) shadowRank {
	t.Helper()
	r := forecastRank(t, n, ip, tier)
	r.scope, r.fresh = scope, true
	return r
}

// A fresh forecast pick rotates an equal-tier forecast block out of its
// full partition once that block's hold passed on both the admission
// clock and the session's elapsed time, and waits as equal_tier_wait
// before. The new block takes the victim's partition and records its own
// scope, application and elapsed time; the victim's address is answered
// until the victim's expiry. A requester at its share rotates only its
// own scope's block, and a renewal never rotates (spec 5.2, 5.6).
func TestShadowRotatesAnEqualTierBlockAfterTheHold(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	// Limit 3: two general slots and one reserved.
	adm := firewall.BlockAdmission{Limit: 3}
	first, second := scopedRank(t, 1, "203.0.113.1", highTier, "a"), scopedRank(t, 2, "203.0.113.2", highTier, "a")
	admitRanked(t, s, first, generalOnly, shadowT0, adm)
	admitRanked(t, s, second, generalOnly, shadowT0.Add(time.Minute), adm)
	at := shadowT0.Add(admission.RotationHold)
	if p, change := admitRanked(t, s, scopedRank(t, 3, "203.0.113.3", highTier, "b"), generalOnly, at, adm); p != admission.PredictEqualTierWait || change != nil {
		t.Fatalf("pick before the elapsed hold = %v %+v, want equal_tier_wait", p, change)
	}
	if err := tickBy(s, at, admission.RotationHold); err != nil {
		t.Fatal(err)
	}
	used := s.ceiling.General.Used
	p, change := admitRanked(t, s, scopedRank(t, 4, "203.0.113.4", highTier, "b"), generalOnly, at, adm)
	want := admission.EvictionVictim{Action: first.action, Target: first.target, Tier: highTier, Partition: admission.PartitionGeneral,
		ExpiresAt: shadowT0.Add(time.Hour), Scope: "a", Applied: shadowT0, Rotatable: true}
	if p != admission.PredictCapacityRotate || change == nil || change.victim != want {
		t.Fatalf("pick after the hold = %v %+v, want capacity_rotate of %+v", p, change, want)
	}
	got := s.entries["203.0.113.4"]
	if _, gone := s.entries["203.0.113.1"]; gone || len(s.entries) != 2 || got.partition != admission.PartitionGeneral ||
		got.scope != "b" || !got.applied.Equal(at) || got.elapsed != admission.RotationHold {
		t.Fatalf("entries after the rotation: %+v", s.entries)
	}
	if exp, ok := s.answered["203.0.113.1"]; !ok || !exp.Equal(want.ExpiresAt) || len(s.answered) != 1 {
		t.Fatalf("answered = %v", s.answered)
	}
	if s.ceiling.General.Used != used+1 || change.charge.Lane != admission.LaneGeneral {
		t.Fatalf("the rotation charged %+v, used %d", change.charge, s.ceiling.General.Used)
	}
	later := at.Add(time.Minute)
	if err := tickBy(s, later, time.Minute); err != nil {
		t.Fatal(err)
	}
	renewal := scopedRank(t, 5, "203.0.113.5", highTier, "a")
	renewal.fresh = false
	if p, _ := admitRanked(t, s, renewal, generalOnly, later, adm); p != admission.PredictEqualTierWait {
		t.Fatalf("renewal = %v, want equal_tier_wait", p)
	}
	if p, change := admitRanked(t, s, scopedRank(t, 6, "203.0.113.6", highTier, "a"), generalOnly, later, adm); p != admission.PredictCapacityRotate || change == nil || change.victim.Action != second.action {
		t.Fatalf("own-scope pick = %v %+v, want its own block rotated", p, change)
	}
}

// The turn's waiting scopes and the session's cursor share the set: a
// requester that the cursor leaves without a share waits, and one that a
// waiting scope does not crowd out reclaims another scope's borrowing.
// Each turn that shares the set moves the cursor once; one with a free
// slot leaves it (spec 5.6).
func TestShadowSharesTheSetFromTheSessionCursor(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	adm := firewall.BlockAdmission{Limit: 3}
	admitRanked(t, s, scopedRank(t, 1, "203.0.113.1", highTier, "a"), generalOnly, shadowT0, adm)
	s.share(adm, shadowT0, map[admission.Partition][]string{admission.PartitionGeneral: {"b"}})
	if s.cursors != (admission.QueueCursors{}) || !reflect.DeepEqual(s.waiting, map[admission.Partition][]string{admission.PartitionGeneral: {"b"}}) {
		t.Fatalf("a free slot moved the cursor or lost the waiting scopes: %+v %v", s.cursors, s.waiting)
	}
	admitRanked(t, s, scopedRank(t, 2, "203.0.113.2", highTier, "a"), generalOnly, shadowT0, adm)
	for _, want := range []string{"a", "b", "a"} {
		s.share(adm, shadowT0, map[admission.Partition][]string{admission.PartitionGeneral: {"b"}})
		if s.cursors != (admission.QueueCursors{General: want}) {
			t.Fatalf("cursors = %+v, want general %q", s.cursors, want)
		}
	}
	at := shadowT0.Add(admission.RotationHold)
	if err := tickBy(s, at, admission.RotationHold); err != nil {
		t.Fatal(err)
	}
	pick := scopedRank(t, 3, "203.0.113.3", highTier, "b")
	s.cursors = admission.QueueCursors{General: "b"}
	s.waiting = map[admission.Partition][]string{admission.PartitionGeneral: {"c"}}
	if p := s.wait(adm, generalOnly, pick, at); p != admission.PredictEqualTierWait {
		t.Fatalf("a requester the cursor leaves without a share = %v, want equal_tier_wait", p)
	}
	s.cursors = admission.QueueCursors{}
	if p := s.wait(adm, generalOnly, pick, at); p != 0 {
		t.Fatalf("a requester with a share from the first cursor = %v, want room", p)
	}
	s.cursors, s.waiting = admission.QueueCursors{General: "b"}, nil
	if p := s.wait(adm, generalOnly, pick, at); p != 0 {
		t.Fatalf("a requester no waiting scope crowds out = %v, want room", p)
	}
}

// A forecast block that strictly higher work replaces answers its address
// until the block's expiry, keeping the later expiry of two, as a rotated
// one does; a replaced import is remembered by name only (spec 5.2).
func TestShadowAnswersTheAddressesItRemoves(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	imp := firewall.BlockImport{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: shadowT0.Add(30 * time.Minute)}
	adm := firewall.BlockAdmission{Temporary: 1, Limit: 3, Imported: 1, Imports: []firewall.BlockImport{imp}}
	low := scopedRank(t, 1, "203.0.113.1", highTier, "a")
	admitRanked(t, s, low, generalOnly, shadowT0, adm)
	if p, _ := admitRanked(t, s, scopedRank(t, 2, "203.0.113.2", criticalTier, "a"), generalOnly, shadowT0, adm); p != admission.PredictCapacityEvict || len(s.answered) != 0 {
		t.Fatalf("import replacement = %v, answered %v", p, s.answered)
	}
	s.answered["203.0.113.1"] = shadowT0.Add(2 * time.Hour)
	if p, _ := admitRanked(t, s, scopedRank(t, 3, "203.0.113.3", criticalTier, "a"), generalOnly, shadowT0, adm); p != admission.PredictCapacityEvict {
		t.Fatalf("forecast block replacement = %v", p)
	}
	if exp := s.answered["203.0.113.1"]; !exp.Equal(shadowT0.Add(2 * time.Hour)) {
		t.Fatalf("an earlier expiry replaced the answered one: %v", exp)
	}
	top := admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityCritical}
	if p, change := admitRanked(t, s, scopedRank(t, 4, "203.0.113.4", top, "a"), generalOnly, shadowT0, adm); p != admission.PredictCapacityEvict || change.victim.Tier == top {
		t.Fatalf("strictly higher replacement = %v %+v", p, change)
	}
	if exp, ok := s.answered["203.0.113.2"]; !ok || !exp.Equal(shadowT0.Add(time.Hour)) || len(s.answered) != 2 {
		t.Fatalf("a replaced forecast block left its address unanswered: %v", s.answered)
	}
	s.answered["203.0.113.1"] = shadowT0.Add(time.Hour)
	s.expire(shadowT0.Add(time.Hour - time.Nanosecond))
	if _, ok := s.answered["203.0.113.1"]; !ok {
		t.Fatal("the answer ended before its block's expiry")
	}
	s.expire(shadowT0.Add(time.Hour))
	if len(s.answered) != 0 {
		t.Fatalf("the answer outlived its block: %v", s.answered)
	}
}

// waitingOf shares a turn's block picks by the partitions they may
// occupy: every pick's scope waits in general, and a pick with a reserved
// lane also in reserved, each scope once.
func TestWaitingOfSharesPartitionsByLane(t *testing.T) {
	scope := func(e admission.Effect) admission.Candidate {
		return admission.Candidate{Scope: admission.Scope{Effect: e}}
	}
	picks := []execPick{
		{pick: admission.Pick{Lane: admission.LaneGeneral}, c: scope(admission.EffectService)},
		{pick: admission.Pick{Lane: admission.LaneGeneral, Reserved: admission.LaneDirect}, c: scope(admission.EffectAddress)},
		{pick: admission.Pick{Lane: admission.LaneCorroborated}, c: scope(admission.EffectPrefix)},
		{pick: admission.Pick{Lane: admission.LaneGeneral}, c: scope(admission.EffectService)},
	}
	want := map[admission.Partition][]string{
		admission.PartitionGeneral:  {"host/address", "host/prefix", "host/service"},
		admission.PartitionReserved: {"host/address", "host/prefix"},
	}
	if got := waitingOf(picks); !reflect.DeepEqual(got, want) {
		t.Fatalf("waiting = %v, want %v", got, want)
	}
}

// rotationOwner is a dry-run owner whose set has two general slots and
// one reserved, both general ones taken by forecast blocks of 192.0.2.11
// and 192.0.2.12 whose hold has passed on both clocks. The initial
// blocks have ingress episodes, so a return is a linked generation.
func rotationOwner(t *testing.T) (*Owner, *admission.Producer, *ownerFixture) {
	t.Helper()
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit = 3
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	observe(t, o, p, f, "192.0.2.11", "initial-11")
	observe(t, o, p, f, "192.0.2.12", "initial-12")
	turn(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	turn(t, o)
	if fc := forecastOf(t, o); fc.picks[admission.PredictCapacityAdmit] != 2 || fc.picks[admission.PredictEqualTierWait] != 1 || len(fc.entries) != 2 {
		t.Fatalf("forecast before the hold = %+v", fc)
	}
	f.host.advance(admission.RotationHold)
	// An empty turn reads the clock, so later roots are not in its future.
	turn(t, o)
	return o, p, f
}

// A forecast pick of a fresh episode rotates the oldest equal-tier block
// out of the full partition once its hold passed, as live admission would
// (operator ruling T1). The rotated address is answered: its next
// generation waits as equal_tier_wait rather than rotate (spec 5.2).
func TestOwnerForecastRotatesAfterTheHold(t *testing.T) {
	o, p, f := rotationOwner(t)
	written := watchExamples(t, o)
	id := observe(t, o, p, f, "192.0.2.14", "rotate-14")
	turn(t, o)
	fc := forecastOf(t, o)
	_, kept11 := fc.entries["192.0.2.11"]
	_, kept12 := fc.entries["192.0.2.12"]
	gone := "192.0.2.11"
	if kept11 {
		gone = "192.0.2.12"
	}
	if fc.picks[admission.PredictCapacityRotate] != 1 || len(fc.entries) != 2 || kept11 == kept12 || len(fc.answered) != 1 {
		t.Fatalf("forecast after the hold = %+v", fc)
	}
	if _, ok := fc.answered[gone]; !ok {
		t.Fatalf("answered = %v, want %s", fc.answered, gone)
	}
	scope := []string{"host/address"}
	if !reflect.DeepEqual(fc.waiting, map[admission.Partition][]string{admission.PartitionGeneral: scope}) || fc.cursors != (admission.QueueCursors{General: scope[0]}) {
		t.Fatalf("the turn shared the set as %v from %+v", fc.waiting, fc.cursors)
	}
	if d := dryRunState(t, o); d.Picks["capacity_rotate"] != 1 || d.LastHour["capacity_rotate"] != 1 {
		t.Fatalf("status = %+v", d)
	}
	if batches := written.written(); len(batches) != 1 || len(batches[0]) != 1 || batches[0][0].Candidate != id ||
		batches[0][0].Session != fc.id || batches[0][0].IP != "192.0.2.14" || !batches[0][0].ExpiresAt.Equal(fc.entries["192.0.2.14"].expires) {
		t.Fatalf("rotation examples = %+v", batches)
	}
	again := observe(t, o, p, f, gone, "rotate-again")
	if c := candidate(t, o, again); c.Key.Generation <= 1 {
		t.Fatalf("return did not create a linked generation: %+v", c)
	}
	turn(t, o)
	if fc = forecastOf(t, o); fc.picks[admission.PredictCapacityRotate] != 1 || fc.picks[admission.PredictEqualTierWait] != 2 {
		t.Fatalf("the rotated address regained the privilege: %+v", fc)
	}
	if batches := written.written(); len(batches) != 1 {
		t.Fatalf("a wait wrote an example: %+v", batches)
	}
}

// Only work the ledger finds fresh rotates; a failed episode read fails
// the turn as a ledger fault and leaves the pick queued.
func TestOwnerForecastRotatesOnlyFreshWork(t *testing.T) {
	o, p, f := rotationOwner(t)
	var freshErr error
	setOwnerHook(t, o, &freshLedger, func(*store.AdmissionLedger, admission.Candidate) (bool, error) { return false, freshErr })
	observe(t, o, p, f, "192.0.2.14", "rotate-14")
	turn(t, o)
	if fc := forecastOf(t, o); fc.picks[admission.PredictCapacityRotate] != 0 || fc.picks[admission.PredictEqualTierWait] != 2 || len(fc.answered) != 0 {
		t.Fatalf("work the ledger finds stale rotated: %+v", fc)
	}
	freshErr = errors.New("disk full")
	id := observe(t, o, p, f, "192.0.2.15", "rotate-15")
	if err := o.do(o.turn); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("turn with a failed episode read = %v", err)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued {
		t.Fatalf("pick after a failed episode read = %+v", c)
	}
	if code := forecastErrorOf(dryRunState(t, o)); code != string(forecastLedgerUnavailable) {
		t.Fatalf("forecast error = %q", code)
	}
}

// A pick that waits behind an equal-tier block ends as equal_tier_wait
// without a call, as a full set does; a pick that finds room is asked
// first (spec 3.3).
func TestOwnerForecastEqualTierWaitAsksNothing(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit = 3
	panel := newFakePanel("block")
	o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	readyAnswers(t, o, 2)
	turn(t, o)
	if fc := forecastOf(t, o); fc.picks[admission.PredictCapacityAdmit] != 2 {
		t.Fatalf("forecast after the answers = %+v", fc)
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	turn(t, o)
	if state := verdictState(t, o); state.Asked != 2 || state.Pending != 0 {
		t.Fatalf("an equal-tier wait asked the panel: %+v", state)
	}
	if fc := forecastOf(t, o); fc.picks[admission.PredictEqualTierWait] != 1 || len(fc.entries) != 2 {
		t.Fatalf("forecast after the wait = %+v", fc)
	}
}

// A block admitted after session startup uses its own nonzero anchors.
// Neither clock alone passes the hold, and the exact joint boundary does.
func TestShadowRotationUsesBothApplicationAnchors(t *testing.T) {
	for name, tc := range map[string]struct {
		wall, elapsed time.Duration
		want          admission.Prediction
	}{
		"wall short":    {admission.RotationHold - time.Nanosecond, admission.RotationHold, admission.PredictEqualTierWait},
		"elapsed short": {admission.RotationHold, admission.RotationHold - time.Nanosecond, admission.PredictEqualTierWait},
		"both exact":    {admission.RotationHold, admission.RotationHold, admission.PredictCapacityRotate},
	} {
		t.Run(name, func(t *testing.T) {
			s := testShadow(t, freshCeiling(t, 2000), nil)
			applied := shadowT0.Add(time.Hour)
			if err := tickBy(s, applied, time.Hour); err != nil {
				t.Fatal(err)
			}
			adm := firewall.BlockAdmission{Limit: 3}
			admitRanked(t, s, scopedRank(t, 1, "203.0.113.1", highTier, "a"), generalOnly, applied, adm)
			admitRanked(t, s, scopedRank(t, 2, "203.0.113.2", highTier, "a"), generalOnly, applied, adm)
			now := applied.Add(tc.wall)
			if err := tickBy(s, now, tc.elapsed); err != nil {
				t.Fatal(err)
			}
			if got, _ := admitRanked(t, s, scopedRank(t, 3, "203.0.113.3", highTier, "b"), generalOnly, now, adm); got != tc.want {
				t.Fatalf("two-clock rotation = %v, want %v", got, tc.want)
			}
		})
	}
}

// Real coverage contributes occupancy, never a forecast holding scope or
// victim. A pressure turn advances past only the forecast and waiting scopes.
func TestShadowRotationExcludesRealHoldings(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	adm := firewall.BlockAdmission{Limit: 3}
	admitRanked(t, s, scopedRank(t, 1, "203.0.113.1", highTier, "a"), generalOnly, shadowT0, adm)
	admitRanked(t, s, scopedRank(t, 2, "203.0.113.2", highTier, "b"), generalOnly, shadowT0, adm)
	adm.Admission, adm.Temporary = 1, 1
	adm.ShadowHeld = map[string]bool{"203.0.113.2": true}
	s.cursors.General = "a"
	s.share(adm, shadowT0, map[admission.Partition][]string{admission.PartitionGeneral: {"c"}})
	if s.cursors.General != "c" {
		t.Fatalf("real coverage entered the scope cursor: %+v", s.cursors)
	}
}

// Rotation cannot publish a victim removal, answered address, charge,
// counter or example before its ending commits. A retry commits once.
func TestOwnerForecastRotationEndingFailureKeepsVictim(t *testing.T) {
	o, p, f := rotationOwner(t)
	written := watchExamples(t, o)
	id := observe(t, o, p, f, "192.0.2.14", "rotate-14")
	before := forecastOf(t, o)
	end := endDryRunLedger
	fail := errors.New("ending unavailable")
	setOwnerHook(t, o, &endDryRunLedger, func(*store.AdmissionLedger, admission.CandidateID) (admission.Candidate, bool, error) {
		return admission.Candidate{}, false, fail
	})
	if err := o.do(o.turn); !errors.Is(err, fail) {
		t.Fatalf("failed rotation ending = %v", err)
	}
	after := forecastOf(t, o)
	if !reflect.DeepEqual(after.entries, before.entries) || !reflect.DeepEqual(after.answered, before.answered) ||
		after.ceiling != before.ceiling || after.picks != before.picks || len(written.written()) != 0 {
		t.Fatalf("failed ending published a rotation: before %+v after %+v", before, after)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 0 {
		t.Fatalf("failed ending changed the candidate: %+v", c)
	}
	setOwnerHook(t, o, &endDryRunLedger, end)
	turn(t, o)
	turn(t, o)
	after = forecastOf(t, o)
	if after.picks[admission.PredictCapacityRotate] != 1 || len(after.entries) != 2 || len(after.answered) != 1 ||
		after.ceiling.General.Used != before.ceiling.General.Used+1 || liveUsed(t, o) != 0 {
		t.Fatalf("retry did not commit the rotation exactly once: %+v", after)
	}
	if batches := written.written(); len(batches) != 1 || len(batches[0]) != 1 || batches[0][0].Candidate != id {
		t.Fatalf("rotation retry examples = %+v", batches)
	}
}

// Real coverage, usable panel allows and forecast coverage already decide
// a pick. A rotation-only episode read cannot block those decisions.
func TestOwnerForecastReadsFreshnessOnlyForCapacity(t *testing.T) {
	for _, mode := range []string{"actual", "allow", "shadow", "short shadow"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			policy := dryPolicy(1)
			if mode == "allow" {
				policy = dryVerdictPolicy(1, newFakePanel("allow"))
			}
			o, _, _ := policyOwner(t, f, blocks, policy)
			turn(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			want := admission.PredictExistingShadow
			switch mode {
			case "actual":
				blocks.set(func(b *fakeBlocks) { b.refuse["192.0.2.10"] = firewall.BlockRefusedExisting })
				want = admission.PredictExistingActual
			case "allow":
				turn(t, o)
				readyAnswers(t, o, 1)
			default:
				expiry := f.host.now().Add(48 * time.Hour)
				if mode == "short shadow" {
					expiry, want = f.host.now().Add(time.Hour), admission.PredictPendingRecovery
				}
				if err := o.do(func() error {
					o.shadow.entries["192.0.2.10"] = shadowEntry{kind: admission.KindBlockIP, expires: expiry}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			setOwnerHook(t, o, &freshLedger, func(*store.AdmissionLedger, admission.Candidate) (bool, error) {
				return false, errors.New("unexpected rotation proof read")
			})
			turn(t, o)
			c := candidate(t, o, id)
			if mode == "allow" {
				if c.State != admission.StateRefused || c.Reason != admission.ReasonVerdictAllow {
					t.Fatalf("allow ending = %+v", c)
				}
			} else if fc := forecastOf(t, o); c.State != admission.StateDryRun || fc.picks[want] != 1 {
				t.Fatalf("coverage ending = %+v, forecast %+v", c, fc)
			}
		})
	}
}

// The first pick uses the advanced cursor. Later picks in that same turn
// must not advance it again or bypass the young block in their own scope.
func TestOwnerForecastMovesCursorOnceBeforePicks(t *testing.T) {
	o, p, f := rotationOwner(t)
	if err := o.do(func() error {
		first, second := o.shadow.entries["192.0.2.11"], o.shadow.entries["192.0.2.12"]
		first.scope, second.scope = "a", "b"
		o.shadow.entries["192.0.2.11"], o.shadow.entries["192.0.2.12"] = first, second
		o.shadow.cursors = admission.QueueCursors{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	observe(t, o, p, f, "192.0.2.14", "rotate-14")
	observe(t, o, p, f, "192.0.2.15", "rotate-15")
	turn(t, o)
	fc := forecastOf(t, o)
	if fc.cursors.General != "a" || fc.picks[admission.PredictCapacityRotate] != 1 || fc.picks[admission.PredictEqualTierWait] != 2 ||
		len(fc.entries) != 2 || fc.entries["192.0.2.12"].scope != "b" || len(fc.answered) != 1 {
		t.Fatalf("turn did not use one pre-pick cursor move: %+v", fc)
	}
	if _, ok := fc.answered["192.0.2.11"]; !ok {
		t.Fatalf("turn rotated the wrong scope: %v", fc.answered)
	}
}

// Rotation ranks use the candidate's complete fairness key, including
// its effect family, rather than an address or a fixed host scope.
func TestForecastRankUsesCandidateScope(t *testing.T) {
	p := execPick{pick: admission.Pick{Tier: highTier}, c: admission.Candidate{Scope: admission.Scope{Effect: admission.EffectService}}}
	if got := rankOf(p, firewall.BlockMember{}, true); got.scope != "host/service" || !got.fresh || got.tier != highTier {
		t.Fatalf("forecast rank = %+v", got)
	}
}

// Removed blocks retain their rotation answers until expiry. Churn must
// consume the existing forecast budget rather than grow another unbounded map.
func TestShadowRotationAnswersShareTheForecastBound(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	adm := firewall.BlockAdmission{Limit: 4}
	admitRanked(t, s, scopedRank(t, 1, "203.0.113.1", highTier, "a"), generalOnly, shadowT0, adm)
	entry := s.entries["203.0.113.1"]
	entry.expires = shadowT0.Add(2 * time.Hour)
	s.entries["203.0.113.1"] = entry
	for i := 1; i < forecastEntries; i++ {
		s.answered[fmt.Sprintf("2001:db8::%x", i)] = shadowExpiry
	}
	before := s.ceiling
	rank := scopedRank(t, 2, "203.0.113.2", highTier, "b")
	if got, change := admitRanked(t, s, rank, generalOnly, shadowT0, adm); got != admission.PredictForecastLimited || change != nil ||
		len(s.entries) != 1 || len(s.answered) != forecastEntries-1 || s.ceiling != before {
		t.Fatalf("remembered answers escaped the model bound: prediction %v, change %+v, entries %d, answers %d", got, change, len(s.entries), len(s.answered))
	}
	s.expire(shadowExpiry.Add(-time.Nanosecond))
	if !s.limited() || len(s.answered) != forecastEntries-1 {
		t.Fatal("the model released answer memory before its expiry")
	}
	s.expire(shadowExpiry)
	if s.limited() || len(s.answered) != 0 || len(s.entries) != 1 {
		t.Fatalf("expired answers kept the model full: entries %d, answers %d", len(s.entries), len(s.answered))
	}
	if err := tickBy(s, shadowExpiry, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, change := admitRanked(t, s, rank, generalOnly, shadowExpiry, adm); got != admission.PredictCapacityAdmit || change == nil {
		t.Fatalf("expired answers did not release model capacity: %v %+v", got, change)
	}
}
