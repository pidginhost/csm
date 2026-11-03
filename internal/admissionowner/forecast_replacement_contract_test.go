package admissionowner

import (
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// A valid partition and tier are separate prerequisites for a victim.
// A real block never becomes a victim through its forecast entry.
func TestShadowReplacementPoolEligibility(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tier      admission.Tier
		partition admission.Partition
		held      bool
		want      admission.Prediction
	}{
		{"ranked", highTier, admission.PartitionGeneral, false, admission.PredictCapacityEvict},
		{"invalid class", admission.Tier{Severity: admission.SeverityHigh}, admission.PartitionGeneral, false, admission.PredictSetFull},
		{"invalid severity", admission.Tier{Class: admission.ClassC2}, admission.PartitionGeneral, false, admission.PredictSetFull},
		{"invalid partition", highTier, 0, false, admission.PredictSetFull},
		{"real coverage", highTier, admission.PartitionGeneral, true, admission.PredictSetFull},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testShadow(t, freshCeiling(t, 2000), nil)
			r := forecastRank(t, 1, "203.0.113.1", tc.tier)
			s.entries["203.0.113.1"] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: tc.partition, tier: r.tier, action: r.action, target: r.target}
			s.entries["203.0.113.2"] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: admission.PartitionReserved}
			adm := firewall.BlockAdmission{Limit: 3, Imported: 1, ShadowHeld: map[string]bool{"203.0.113.1": tc.held}}
			if tc.held {
				adm.Imported++
			}
			pred, _ := admitRanked(t, s, forecastRank(t, 9, "203.0.113.9", criticalTier), directGen, shadowT0, adm)
			if pred != tc.want {
				t.Fatalf("victim eligibility = %s, want %s", pred, tc.want)
			}
		})
	}
}

// Demand keeps the ledger's cost, eligibility and same-address exclusion.
// Both reserved lanes must be tried when a general turn has no room.
func TestShadowReplacementDemandAndLanes(t *testing.T) {
	r := forecastRank(t, 9, "203.0.113.9", criticalTier)
	for _, kind := range []admission.Kind{admission.KindBlockIP, admission.KindBlockService, admission.KindBlockSubnet, admission.KindPromote, admission.KindChallenge} {
		for _, reserved := range []admission.Lane{0, admission.LaneDirect, admission.LaneCorroborated} {
			lanes := lanesOf(admission.Pick{Lane: admission.LaneGeneral, Reserved: reserved})
			want := admission.SlotDemand{Tier: r.tier, Cost: kind.CeilingCost(), Evicts: kind == admission.KindBlockIP, Reserved: reserved != 0, Target: r.target}
			if got := demand(kind, lanes, r); got != want {
				t.Fatalf("demand for %s on %v = %+v, want %+v", kind, lanes, got, want)
			}
		}
	}
	for _, lane := range []admission.Lane{admission.LaneDirect, admission.LaneCorroborated} {
		s := testShadow(t, freshCeiling(t, 2000), nil)
		victim := forecastRank(t, 1, "203.0.113.1", highTier)
		s.entries["203.0.113.1"] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: admission.PartitionReserved, tier: victim.tier, action: victim.action, target: victim.target}
		adm := firewall.BlockAdmission{Limit: 3, Imported: 2}
		if s.wait(adm, generalOnly, r, shadowT0) == 0 {
			t.Fatal("general-only work can take a reserved victim")
		}
		lanes := lanesOf(admission.Pick{Lane: admission.LaneGeneral, Reserved: lane})
		if s.wait(adm, lanes, r, shadowT0) != 0 {
			t.Fatal("a reserved victim on the second lane was missed")
		}
		pred, change := admitRanked(t, s, r, lanes, shadowT0, adm)
		if pred != admission.PredictCapacityEvict || change == nil || change.charge.Lane != lane || change.victim.Action != victim.action {
			t.Fatalf("second-lane replacement = %s %+v", pred, change)
		}
	}
	s := testShadow(t, freshCeiling(t, 2000), nil)
	adm := firewall.BlockAdmission{Limit: 2}
	low := forecastRank(t, 1, "203.0.113.9", highTier)
	admitRanked(t, s, low, generalOnly, shadowT0, adm)
	if pred, change, err := s.admit("203.0.113.9", admission.KindBlockIP, shadowExpiry, generalOnly, shadowT0, adm, r); err != nil || pred != admission.PredictSetFull || change != nil {
		t.Fatalf("same-address replacement = %s %+v %v", pred, change, err)
	}
}

// The engine's list is proof of actual imports even when its count is
// lower. Status uses the same floor as admission, before and after the
// replacing block expires, so predicted occupancy never becomes negative.
func TestShadowReplacementOccupancyUsesTheImportFloor(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	imp := firewall.BlockImport{ID: "eff_00000000000000000000000000000001", IP: "192.0.2.60", ExpiresAt: shadowT0.Add(2 * time.Hour)}
	adm := firewall.BlockAdmission{Limit: 2, Imports: []firewall.BlockImport{imp}}
	s.adm = &adm
	if got := s.occupancyStatus(); got.Actual != 1 || got.Imported != 1 || got.ShadowOnly != 0 || got.Replaced != 0 || got.Predicted != 1 || got.General.Used != 1 {
		t.Fatalf("listed import floor before replacement: %+v", got)
	}
	pred, _ := admitRanked(t, s, forecastRank(t, 2, "203.0.113.2", criticalTier), generalOnly, shadowT0, adm)
	if got := s.occupancyStatus(); pred != admission.PredictCapacityEvict || got.Actual != 1 || got.Imported != 1 || got.ShadowOnly != 1 || got.Replaced != 1 || got.Predicted != 1 || got.General.Used != 1 {
		t.Fatalf("listed import floor after replacement: %s %+v", pred, got)
	}
	top := forecastRank(t, 3, "203.0.113.3", admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityCritical})
	if pred, change := admitRanked(t, s, top, generalOnly, shadowT0, adm); pred != admission.PredictCapacityEvict || change == nil || change.victim.Action != forecastRank(t, 2, "203.0.113.2", criticalTier).action {
		t.Fatalf("replacing block was not replaced: %s %+v", pred, change)
	}
	if got := s.occupancyStatus(); got.Replaced != 1 || got.Predicted != 1 || got.ShadowOnly != 1 || len(s.replaced) != 1 {
		t.Fatalf("a second replacement forgot the import: %+v, memory %v", got, s.replaced)
	}
	s.expire(shadowExpiry)
	if got := s.occupancyStatus(); got.Actual != 1 || got.ShadowOnly != 0 || got.Replaced != 1 || got.Predicted != 0 || got.General.Used != 0 || len(s.replaced) != 1 {
		t.Fatalf("replacing block expired before its import: %+v, memory %v", got, s.replaced)
	}
	adm.Imported, adm.Imports = 1, nil
	if got := s.occupancyStatus(); got.Actual != 1 || got.Replaced != 0 || got.Predicted != 1 || got.General.Used != 1 {
		t.Fatalf("unlisted replaced import: %+v", got)
	}
	imp.ID = "eff_00000000000000000000000000000002"
	adm.Imports = []firewall.BlockImport{imp}
	if got := s.occupancyStatus(); got.Replaced != 0 || got.Predicted != 1 {
		t.Fatalf("renewal inherited old replacement memory: %+v", got)
	}
	s.expire(imp.ExpiresAt)
	if len(s.replaced) != 0 {
		t.Fatalf("expired import retained in memory: %v", s.replaced)
	}
}

// Deciding a replacement must not change its victim or spend credit until
// committed. A ceiling refusal or the model bound leaves them intact.
func TestShadowReplacementIsSpeculativeAndBounded(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 5), nil)
	adm := firewall.BlockAdmission{Limit: 2}
	low := forecastRank(t, 1, "203.0.113.1", highTier)
	s.entries["203.0.113.1"] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: admission.PartitionGeneral, tier: low.tier, action: low.action, target: low.target}
	before, entries := s.ceiling, maps.Clone(s.entries)
	r := forecastRank(t, 9, "203.0.113.9", criticalTier)
	pred, change, err := s.admit("203.0.113.9", admission.KindBlockIP, shadowExpiry, generalOnly, shadowT0, adm, r)
	if err != nil || pred != admission.PredictCapacityEvict || change == nil || change.victim.Action != low.action {
		t.Fatalf("speculative replacement = %s %+v %v", pred, change, err)
	}
	if s.ceiling != before || !maps.Equal(s.entries, entries) || len(s.replaced) != 0 || len(s.charges) != 0 || s.picks[admission.PredictCapacityEvict] != 0 {
		t.Fatal("an uncommitted replacement changed the forecast")
	}
	s.ceiling, err = s.ceiling.Charge(admission.LaneGeneral, 1)
	if err != nil {
		t.Fatal(err)
	}
	before = s.ceiling
	if pred, change, err = s.admit("203.0.113.9", admission.KindBlockIP, shadowExpiry, generalOnly, shadowT0, adm, r); err != nil || pred != admission.PredictCeiling || change != nil || s.ceiling != before || !maps.Equal(s.entries, entries) {
		t.Fatalf("ceiling-refused replacement = %s %+v %v", pred, change, err)
	}
	for i := 1; i < forecastEntries; i++ {
		s.entries[fmt.Sprintf("2001:db8::%x", i)] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry, partition: admission.PartitionGeneral}
	}
	adm.Limit = forecastEntries * 5 / 4
	if pred, change, err = s.admit("203.0.113.9", admission.KindBlockIP, shadowExpiry, generalOnly, shadowT0, adm, r); err != nil || pred != admission.PredictForecastLimited || change != nil || s.ceiling != before {
		t.Fatalf("bounded replacement = %s %+v %v", pred, change, err)
	}
	r.tier = highTier
	if pred, change, err = s.admit("203.0.113.9", admission.KindBlockIP, shadowExpiry, generalOnly, shadowT0, adm, r); err != nil || pred != admission.PredictSetFull || change != nil {
		t.Fatalf("set-full precedence = %s %+v %v", pred, change, err)
	}
}
