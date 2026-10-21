package admission

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Design C7: the live start charges the legacy hour's units that the
// retained charges in that hour do not already count, dated at the hour's
// end, general lane first up to its room and the rest on the reserved
// allowance. They spend saved credit without a budget check: legacy
// blocking already spent them. Retained charges that cover the count add
// nothing.
func TestCeilingCarryLegacyChargesTheGreaterHour(t *testing.T) {
	end := t0.Add(30 * time.Minute)
	nearlyFull := ceilingAt(t, 100, true)
	nearlyFull.General.Used = 78
	for _, tc := range []struct {
		name     string
		s        CeilingState
		units    uint32
		retained uint32
		want     []Charge
		general  Meter
		reserved Meter
	}{
		{
			name: "legacy counted more", s: ceilingAt(t, 100, true), units: 10, retained: 4,
			want:    []Charge{{At: end, Action: LiveStartActionID(end, 1), Lane: LaneGeneral, Cost: 6}},
			general: Meter{Credit: 7 * unitTicks, Used: 6}, reserved: Meter{Credit: 3 * unitTicks},
		},
		{
			name: "previews counted more", s: ceilingAt(t, 100, true), units: 4, retained: 4,
			general: Meter{Credit: 13 * unitTicks}, reserved: Meter{Credit: 3 * unitTicks},
		},
		{
			name: "spill into reserved", s: nearlyFull, units: 10,
			want: []Charge{
				{At: end, Action: LiveStartActionID(end, 1), Lane: LaneGeneral, Cost: 2},
				{At: end, Action: LiveStartActionID(end, 2), Lane: LaneDirect, Cost: 8},
			},
			general: Meter{Credit: 11 * unitTicks, Used: 80}, reserved: Meter{Used: 8},
		},
		{
			name: "more than one charge", s: ceilingAt(t, 1000, true), units: 130,
			want: []Charge{
				{At: end, Action: LiveStartActionID(end, 1), Lane: LaneGeneral, Cost: 64},
				{At: end, Action: LiveStartActionID(end, 2), Lane: LaneGeneral, Cost: 64},
				{At: end, Action: LiveStartActionID(end, 3), Lane: LaneGeneral, Cost: 2},
			},
			general: Meter{Credit: 3 * unitTicks, Used: 130}, reserved: Meter{Credit: 33 * unitTicks},
		},
	} {
		got, charges, err := tc.s.CarryLegacy(LegacySpend{Units: tc.units, At: end}, tc.retained)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !reflect.DeepEqual(charges, tc.want) {
			t.Errorf("%s: charges = %+v, want %+v", tc.name, charges, tc.want)
		}
		if got.General != tc.general || got.Reserved != tc.reserved || got.Limit != tc.s.Limit || got.Elapsed != tc.s.Elapsed {
			t.Errorf("%s: state = %+v, want general %+v and reserved %+v", tc.name, got, tc.general, tc.reserved)
		}
		if err := got.Validate(); err != nil {
			t.Errorf("%s: carried state is invalid: %v", tc.name, err)
		}
	}
}

// The carried units are capped as an import's are, and every charge keeps
// the ceiling's elapsed time, so it leaves the window after an hour of it.
func TestCeilingCarryLegacyCapsTheCount(t *testing.T) {
	end := t0.Add(30 * time.Minute)
	s := ceilingAt(t, MaxCeiling, true)
	s.Elapsed = 3 * time.Hour
	got, charges, err := s.CarryLegacy(LegacySpend{Units: MaxCeiling + 5, At: end}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sum uint32
	for _, c := range charges {
		if c.Elapsed != s.Elapsed || !c.At.Equal(end) {
			t.Fatalf("charge %+v, want elapsed %v at %v", c, s.Elapsed, end)
		}
		sum += c.Cost
	}
	if sum != MaxCeiling || got.General.Used+got.Reserved.Used != MaxCeiling {
		t.Fatalf("carried %d units, used %d, want %d", sum, got.General.Used+got.Reserved.Used, MaxCeiling)
	}
	// Charges retained outside the hour count against the same bound: a
	// count past every ceiling leaves no budget either way.
	busy := ceilingAt(t, MaxCeiling, true)
	busy.General.Used = MaxCeiling - 10
	got, charges, err = busy.CarryLegacy(LegacySpend{Units: 50, At: end}, 0)
	if err != nil || len(charges) != 1 || charges[0].Cost != 10 || charges[0].Lane != LaneDirect || got.General.Used+got.Reserved.Used != MaxCeiling {
		t.Fatalf("carried past every ceiling: %+v, %+v, %v", got, charges, err)
	}
}

// An unknown legacy count keeps no saved credit, as a failed first import
// grants none; nothing is charged. A ledger without a limit and a count
// without its hour are refused.
func TestCeilingCarryLegacyRefusesFreshCredit(t *testing.T) {
	s := ceilingAt(t, 100, true)
	s.General.Used = 5
	got, charges, err := s.CarryLegacy(LegacySpend{Unknown: true}, 0)
	if err != nil || len(charges) != 0 || got.General != (Meter{Used: 5}) || got.Reserved != (Meter{}) {
		t.Fatalf("unknown count: %+v, %d charges, %v", got, len(charges), err)
	}
	if _, _, err := (CeilingState{}).CarryLegacy(LegacySpend{}, 0); err == nil {
		t.Fatal("a ledger without a limit carried legacy spend")
	}
	if _, _, err := s.CarryLegacy(LegacySpend{Units: 1}, 0); err == nil {
		t.Fatal("a count without the end of its hour was carried")
	}
}

// The live start's charges are named apart from imported legacy charges
// and from every attempt.
func TestLiveStartActionIDsAreDistinct(t *testing.T) {
	at := time.Date(2026, 10, 4, 13, 0, 0, 0, time.UTC)
	seen := map[ActionID]bool{LegacyActionID(at, 1): true, LegacyActionID(at, 2): true}
	for _, id := range []ActionID{LiveStartActionID(at, 1), LiveStartActionID(at, 2), LiveStartActionID(at.Add(time.Hour), 1)} {
		if _, err := ParseActionID(string(id)); err != nil || seen[id] {
			t.Fatalf("live start ID %q: %v", id, err)
		}
		seen[id] = true
	}
}

// The live start record round-trips, needs a time and is sealed.
func TestLiveStartRecord(t *testing.T) {
	data, err := LiveStart{At: t0}.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := UnmarshalLiveStart(data); err != nil || !back.At.Equal(t0) {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	if _, err := (LiveStart{}).MarshalBinary(); err == nil {
		t.Fatal("a live start without a time was encoded")
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":   func() []byte { d := bytes.Clone(data); d[3] ^= 1; return d }(),
		"future version": resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
		"unknown field":  resealForTest(bytes.Replace(body, []byte(`{"v":1`), []byte(`{"x":1,"v":1`), 1)),
		"no time":        resealForTest([]byte(`{"v":1,"at":0}`)),
	} {
		if _, err := UnmarshalLiveStart(tampered); !errors.Is(err, ErrCorruptRecord) {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}
