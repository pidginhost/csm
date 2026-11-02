package admissionowner

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/store"
)

var (
	highTier     = admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityHigh}
	criticalTier = admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityCritical}
)

// forecastRank ranks the forecast block of pick n at ip with tier, as the
// forecast names it: by the pick's next attempt and its address.
func forecastRank(t *testing.T, n byte, ip string, tier admission.Tier) shadowRank {
	t.Helper()
	target, err := admission.CanonicalAddress(ip, admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	return shadowRank{tier: tier, action: admission.ActionID(fmt.Sprintf("act_%032x", n)), target: target}
}

// admitRanked decides and commits a ranked pick lasting an hour from now.
func admitRanked(t *testing.T, s *shadow, r shadowRank, lanes []admission.Lane, now time.Time, adm firewall.BlockAdmission) (admission.Prediction, *shadowChange) {
	t.Helper()
	addr, _ := r.target.Addr()
	p, change, err := s.admit(addr.String(), admission.KindBlockIP, now.Add(time.Hour), lanes, now, adm, r)
	if err != nil {
		t.Fatal(err)
	}
	s.commit(p, change, now)
	return p, change
}

// A forecast block takes the slot of a strictly lower-tier forecast block
// when its partition is full: the lowest tier, then the earliest expiry,
// then the lowest action (spec 5.6). The replaced block leaves the model,
// the new one keeps the replaced block's partition, and the charge is the
// lane's. Work at the same tier waits as set_full.
func TestShadowReplacesALowerTierForecastBlock(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	// Limit 3: two general slots and one reserved.
	adm := firewall.BlockAdmission{Limit: 3}
	first, second := forecastRank(t, 1, "203.0.113.1", highTier), forecastRank(t, 2, "203.0.113.2", highTier)
	for _, r := range []shadowRank{first, second} {
		if p, _ := admitRanked(t, s, r, generalOnly, shadowT0, adm); p != admission.PredictCapacityAdmit {
			t.Fatalf("filling pick = %v", p)
		}
	}
	if p, _ := admitRanked(t, s, forecastRank(t, 3, "203.0.113.3", highTier), generalOnly, shadowT0, adm); p != admission.PredictSetFull {
		t.Fatalf("same-tier pick = %v, want set_full", p)
	}
	used := s.ceiling.General.Used
	p, change := admitRanked(t, s, forecastRank(t, 4, "203.0.113.4", criticalTier), generalOnly, shadowT0, adm)
	want := admission.EvictionVictim{Action: first.action, Target: first.target, Tier: highTier, Partition: admission.PartitionGeneral, ExpiresAt: shadowT0.Add(time.Hour)}
	if p != admission.PredictCapacityEvict || change == nil || change.victim != want {
		t.Fatalf("critical pick = %v %+v, want capacity_evict of %+v", p, change, want)
	}
	if _, gone := s.entries["203.0.113.1"]; gone || len(s.entries) != 2 || s.entries["203.0.113.4"].partition != admission.PartitionGeneral {
		t.Fatalf("entries after the replacement: %+v", s.entries)
	}
	if s.ceiling.General.Used != used+1 || change.charge.Lane != admission.LaneGeneral {
		t.Fatalf("the replacement charged %+v, used %d", change.charge, s.ceiling.General.Used)
	}
}

// Reserved work takes a free reserved slot before it replaces anything.
// With none, it may replace a strictly lower-tier block of either
// partition, charged on its own lane, and the new block keeps the
// replaced block's partition (spec 5.6).
func TestShadowReservedWorkReplacesInPlace(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	adm := firewall.BlockAdmission{Limit: 3}
	first := forecastRank(t, 1, "203.0.113.1", highTier)
	admitRanked(t, s, first, generalOnly, shadowT0, adm)
	admitRanked(t, s, forecastRank(t, 2, "203.0.113.2", highTier), generalOnly, shadowT0, adm)
	if p, change := admitRanked(t, s, forecastRank(t, 3, "203.0.113.3", criticalTier), directGen, shadowT0, adm); p != admission.PredictCapacityAdmit || change.entry.partition != admission.PartitionReserved {
		t.Fatalf("critical pick with a free reserved slot = %v %+v", p, change)
	}
	p, change := admitRanked(t, s, forecastRank(t, 9, "203.0.113.9", criticalTier), []admission.Lane{admission.LaneDirect, admission.LaneGeneral}, shadowT0.Add(time.Minute), adm)
	if p != admission.PredictCapacityEvict || change.victim.Action != first.action || change.charge.Lane != admission.LaneDirect || s.entries["203.0.113.9"].partition != admission.PartitionGeneral {
		t.Fatalf("reserved replacement = %v %+v, entries %+v", p, change, s.entries)
	}
}

// A forecast block without a tier, as an unassessed pick leaves one, is
// never a victim, and a block the real set holds is not modelled at all.
func TestShadowNeverReplacesAnUnrankedBlock(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	adm := firewall.BlockAdmission{Limit: 3, ShadowHeld: map[string]bool{"203.0.113.3": true}}
	s.entries["203.0.113.1"] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: admission.PartitionGeneral}
	admitRanked(t, s, forecastRank(t, 2, "203.0.113.2", admission.Tier{}), generalOnly, shadowT0, adm)
	held := forecastRank(t, 3, "203.0.113.3", highTier)
	s.entries["203.0.113.3"] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: admission.PartitionGeneral, tier: held.tier, action: held.action, target: held.target}
	if p, _ := admitRanked(t, s, forecastRank(t, 9, "203.0.113.9", criticalTier), generalOnly, shadowT0, adm); p != admission.PredictSetFull || len(s.entries) != 3 {
		t.Fatalf("critical pick over unranked blocks = %v, entries %+v", p, s.entries)
	}
}

// A listed import is a (C2, High) victim (spec 6). Once replaced, the
// forecast remembers it until its own expiry: it neither counts it nor
// offers it again while the engine still lists it, and counts it again if
// the list no longer names it.
func TestShadowReplacesAListedImportUntilItExpires(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	imp := firewall.BlockImport{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: shadowT0.Add(30 * time.Minute)}
	adm := firewall.BlockAdmission{Temporary: 1, Limit: 3, Imported: 1, Imports: []firewall.BlockImport{imp}}
	admitRanked(t, s, forecastRank(t, 1, "203.0.113.1", highTier), generalOnly, shadowT0, adm)
	p, change := admitRanked(t, s, forecastRank(t, 2, "203.0.113.2", criticalTier), generalOnly, shadowT0, adm)
	if p != admission.PredictCapacityEvict || change.victim.Action != admission.ActionID(imp.ID) || !change.victim.Imported() {
		t.Fatalf("critical pick = %v %+v, want the import replaced", p, change)
	}
	if exp, ok := s.replaced[admission.ActionID(imp.ID)]; !ok || !exp.Equal(imp.ExpiresAt) || len(s.entries) != 2 {
		t.Fatalf("replaced %v, entries %+v", s.replaced, s.entries)
	}
	s.adm = &adm
	want := health.AdmissionDryRunOccupancy{Actual: 1, ShadowOnly: 2, Replaced: 1, Predicted: 2, Limit: 3, Capacity: 3, Imported: 1,
		General: health.AdmissionDryRunPartition{Size: 2, Used: 2}, Reserved: health.AdmissionDryRunPartition{Size: 1, Free: 1}}
	if got := s.occupancyStatus(); got == nil || *got != want {
		t.Fatalf("occupancy = %+v, want %+v", got, want)
	}
	p, change = admitRanked(t, s, forecastRank(t, 3, "203.0.113.3", criticalTier), generalOnly, shadowT0, adm)
	if p != admission.PredictCapacityEvict || change.victim.Action != forecastRank(t, 1, "203.0.113.1", highTier).action {
		t.Fatalf("the next critical pick = %v %+v, want the high forecast block replaced", p, change)
	}
	unlisted := adm
	unlisted.Imports = nil
	if got := s.occupancy(unlisted); got.General != 3 {
		t.Fatalf("an unlisted import left the count: %+v", got)
	}
	lower := adm
	lower.Imported = 0
	if got := s.occupancy(lower); got.General != 2 {
		t.Fatalf("a count below the list hid a listed import: %+v", got)
	}
	s.expire(imp.ExpiresAt)
	if len(s.replaced) != 0 {
		t.Fatalf("the memory outlived the import: %v", s.replaced)
	}
}

// The forecast replaces a listed import with strictly higher work, as
// live admission would, without claiming it or touching the live ledger
// (operator ruling T1). Returning to previews uses a fresh list.
func TestOwnerForecastReplacesListedImports(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
	blocks.imports = []firewall.BlockImport{{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}}
	o, policies, _ := policyOwner(t, f, blocks, dryPolicy(1))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	used := liveUsed(t, o)
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 {
		t.Fatalf("forecast reserved or previewed its pick: %+v", c)
	}
	fc := forecastOf(t, o)
	if fc == nil || len(fc.entries) != 1 || fc.picks[admission.PredictCapacityEvict] != 1 || fc.picks[admission.PredictSetFull] != 0 || len(fc.replaced) != 1 {
		t.Fatalf("forecast did not replace the import: %+v", fc)
	}
	if d := dryRunState(t, o); d.Occupancy == nil || d.Occupancy.Replaced != 1 || d.Picks["capacity_evict"] != 1 {
		t.Fatalf("status = %+v", d)
	}
	if liveUsed(t, o) != used {
		t.Fatal("forecast spent the live ceiling")
	}
	policies.publish(validPolicy(2))
	id, _ = queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.12")
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateObserved {
		t.Fatalf("preview failed to use the fresh import list: %+v", c)
	}
	policies.publish(dryPolicy(3))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	turn(t, o)
	if fresh := forecastOf(t, o); fresh == nil || fresh.id == fc.id || len(fresh.replaced) != 0 || len(fresh.entries) != 0 || fresh.picks[admission.PredictSetFull] != 1 {
		t.Fatalf("a new session inherited replacement memory: %+v", fresh)
	}
	queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.14")
	turn(t, o)
	if fresh := forecastOf(t, o); len(fresh.replaced) != 1 || fresh.picks[admission.PredictCapacityEvict] != 1 {
		t.Fatalf("a new session could not replace the import again: %+v", fresh)
	}
	if _, applies := blocks.calls(); len(applies) != 0 || len(blocks.retireCalls()) != 0 {
		t.Fatal("forecast or preview changed the firewall")
	}
}

// A pick only a replacement would fund is asked of the panel first (spec
// 3.3): only a full set with nothing lower to replace ends without a call.
// Its answer then admits it with the replacement.
func TestOwnerForecastAsksThePanelAboutAFundedPick(t *testing.T) {
	for _, answer := range []string{"block", "allow"} {
		t.Run(answer, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
			blocks.imports = []firewall.BlockImport{{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}}
			panel := newFakePanel(answer)
			o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
			turn(t, o)
			if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 0 {
				t.Fatalf("pick before its answer = %+v", c)
			}
			if fc := forecastOf(t, o); len(fc.entries) != 0 || len(fc.replaced) != 0 || fc.picks != ([admission.PredictionSlots]uint64{}) || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 0 {
				t.Fatalf("pending answer consumed forecast capacity: %+v", fc)
			}
			readyAnswers(t, o, 1)
			turn(t, o)
			if state := verdictState(t, o); state.Asked != 1 {
				t.Fatalf("a funded pick was not asked exactly once: %+v", state)
			}
			fc := forecastOf(t, o)
			if answer == "allow" {
				if c := candidate(t, o, id); c.Reason != admission.ReasonVerdictAllow || c.Attempts != 0 {
					t.Fatalf("allowed replacement pick = %+v", c)
				}
				if len(fc.entries) != 0 || len(fc.replaced) != 0 || fc.picks != ([admission.PredictionSlots]uint64{}) || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 0 {
					t.Fatalf("panel allow consumed a replacement: %+v", fc)
				}
			} else if fc.picks[admission.PredictCapacityEvict] != 1 || len(fc.entries) != 1 || len(fc.replaced) != 1 {
				t.Fatalf("forecast after the answer = %+v", fc)
			}
		})
	}
}

// Two pending picks can ask about one victim, but answers must compete
// against committed state and the current import list (spec 3.3).
func TestOwnerForecastPendingReplacementsRecheckCapacity(t *testing.T) {
	for _, withdrawn := range []bool{false, true} {
		t.Run(fmt.Sprintf("withdrawn=%t", withdrawn), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
			blocks.imports = []firewall.BlockImport{{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}}
			panel := newFakePanel("block")
			gate := make(chan struct{})
			panel.hold = gate
			o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
			t.Cleanup(func() {
				select {
				case <-gate:
				default:
					close(gate)
				}
			})
			written := watchExamples(t, o)
			used := liveUsed(t, o)
			var ids []admission.CandidateID
			for _, ip := range []string{"192.0.2.11", "192.0.2.12"} {
				id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, ip)
				ids = append(ids, id)
			}
			turn(t, o)
			eventually(t, "both funded picks asked", func() bool {
				asked, _, _, _ := panel.state()
				return len(asked) == 2
			})
			for _, id := range ids {
				if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 0 {
					t.Fatalf("pending replacement = %+v", c)
				}
			}
			if fc := forecastOf(t, o); len(fc.entries) != 0 || len(fc.replaced) != 0 || fc.picks != ([admission.PredictionSlots]uint64{}) || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 0 {
				t.Fatalf("pending replacements consumed capacity: %+v", fc)
			}
			if withdrawn {
				blocks.set(func(b *fakeBlocks) { b.imports = nil })
			}
			close(gate)
			readyAnswers(t, o, 2)
			turn(t, o)
			want := uint64(1)
			if withdrawn {
				want = 0
			}
			fc := forecastOf(t, o)
			if fc.picks[admission.PredictCapacityEvict] != want || fc.picks[admission.PredictSetFull] != 2-want || fc.picks[admission.PredictCapacityAdmit] != 0 || len(fc.entries) != int(want) || len(fc.replaced) != int(want) || uint64(fc.ceiling.General.Used+fc.ceiling.Reserved.Used) != want {
				t.Fatalf("replacement replies reused stale capacity: %+v", fc)
			}
			for _, id := range ids {
				if c := candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 {
					t.Fatalf("answered replacement = %+v", c)
				}
			}
			batches := written.written()
			if (want == 0 && len(batches) != 0) || (want == 1 && (len(batches) != 1 || len(batches[0]) != 1)) {
				t.Fatalf("replacement examples = %+v", batches)
			}
			if state := verdictState(t, o); state.Asked != 2 || state.Ready != 0 || liveUsed(t, o) != used {
				t.Fatalf("replacement replies changed live usage or re-asked: %+v", state)
			}
		})
	}
}

// An ending failure must leave the import available without publishing
// replacement memory, counters, charges or examples (spec 3.5).
func TestOwnerForecastReplacementEndingFailureKeepsVictim(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
	blocks.imports = []firewall.BlockImport{{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}}
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	written := watchExamples(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	used := liveUsed(t, o)
	fail := errors.New("ending failed")
	end := endDryRunLedger
	setOwnerHook(t, o, &endDryRunLedger, func(*store.AdmissionLedger, admission.CandidateID) (admission.Candidate, bool, error) {
		return admission.Candidate{}, false, fail
	})
	if err := o.do(o.turn); !errors.Is(err, fail) {
		t.Fatalf("failed replacement ending = %v", err)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 0 {
		t.Fatalf("failed ending changed the candidate: %+v", c)
	}
	if fc := forecastOf(t, o); len(fc.entries) != 0 || len(fc.replaced) != 0 || fc.picks != ([admission.PredictionSlots]uint64{}) || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 0 || len(written.written()) != 0 {
		t.Fatalf("failed ending published a replacement: %+v", fc)
	}
	setOwnerHook(t, o, &endDryRunLedger, end)
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 {
		t.Fatalf("replacement retry = %+v", c)
	}
	if fc := forecastOf(t, o); len(fc.entries) != 1 || len(fc.replaced) != 1 || fc.picks[admission.PredictCapacityEvict] != 1 || fc.picks[admission.PredictSetFull] != 0 || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 1 {
		t.Fatalf("replacement retry did not commit once: %+v", fc)
	}
	if batches := written.written(); len(batches) != 1 || len(batches[0]) != 1 || batches[0][0].Candidate != id {
		t.Fatalf("replacement retry examples = %+v", batches)
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionDryRun); n != 1 || liveUsed(t, o) != used {
		t.Fatalf("replacement retry outcomes = %d, live usage = %d", n, liveUsed(t, o))
	}
}

// A forecast replacement is a forecast block: it leaves an example and
// counts as passing capacity in the summary, which names replacements
// among its details.
func TestOwnerForecastReplacementLeavesAnExample(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
	blocks.imports = []firewall.BlockImport{{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}}
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	written := watchExamples(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	turn(t, o)
	if batches := written.written(); len(batches) != 1 || len(batches[0]) != 1 || batches[0][0].Candidate != id || batches[0][0].IP != "192.0.2.11" {
		t.Fatalf("examples %+v", batches)
	}
	s := &dryRunSummary{start: f.host.wall, end: f.host.wall, sessions: 1}
	s.counts[admission.PredictCapacityAdmit], s.counts[admission.PredictCapacityEvict] = 2, 1
	if got := summaryFinding(s, f.host.wall); got.Message != "Dry-run capacity forecast: 3 responses passed modelled capacity checks" || !strings.Contains(got.Details, " capacity_evict=1") {
		t.Fatalf("summary %q / %q", got.Message, got.Details)
	}
}
