package admission

import (
	"errors"
	"testing"
	"time"
)

// A pick carries the tier of the item it serves, so a model can decide
// what work it may replace (spec 5.6).
func TestSchedulePicksCarryTheirTier(t *testing.T) {
	items := []ScheduleItem{schedItem("c3", "a", ClassC3, SeverityCritical, time.Minute), schedItem("c1", "b", ClassC1, SeverityWarning, time.Minute)}
	picks, _ := mustSchedule(t, items, ScheduleState{}, wide)
	if len(picks) != 2 {
		t.Fatalf("picks %+v", picks)
	}
	for _, p := range picks {
		want := Tier{Class: ClassC3, Severity: SeverityCritical}
		if p.ID == "c1" {
			want = Tier{Class: ClassC1, Severity: SeverityWarning}
		}
		if p.Tier != want {
			t.Fatalf("pick %s has tier %+v, want %+v", p.ID, p.Tier, want)
		}
	}
}

// Limits is the slot budget the ledger and the forecast share: free slots
// first; once the general partition is full and the set is not overfull,
// the victims of the pool, without those of an overfull partition. The
// pool is read only then.
func TestSetOccupancyLimits(t *testing.T) {
	soon := t0.Add(time.Hour)
	general, reserved := victimAt(t, 1, warning, PartitionGeneral, soon), victimAt(t, 2, warning, PartitionReserved, soon.Add(time.Hour))
	for _, tc := range []struct {
		name                 string
		occ                  SetOccupancy
		pooled               bool
		freeGeneral, freeRes uint32
		victims              []EvictionVictim
	}{
		// Limit 11 with one unclaimed entry: 8 general and 2 reserved slots.
		{name: "free general slot", occ: SetOccupancy{Limit: 11, Unclaimed: 1, General: 7, Reserved: 1}, freeGeneral: 1, freeRes: 1},
		{name: "full general partition", occ: SetOccupancy{Limit: 11, Unclaimed: 1, General: 8, Reserved: 1}, pooled: true, freeRes: 1, victims: []EvictionVictim{general, reserved}},
		{name: "overfull set", occ: SetOccupancy{Limit: 11, Unclaimed: 1, General: 9, Reserved: 2}},
		// With three unclaimed entries: 6 general and 2 reserved slots.
		{name: "overfull general partition", occ: SetOccupancy{Limit: 11, Unclaimed: 3, General: 7, Reserved: 1}, pooled: true, victims: []EvictionVictim{reserved}},
		{name: "overfull reserved partition", occ: SetOccupancy{Limit: 11, Unclaimed: 3, General: 5, Reserved: 3}, pooled: true, victims: []EvictionVictim{general}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			s, err := tc.occ.Limits(func() ([]EvictionVictim, error) {
				called = true
				return []EvictionVictim{general, reserved}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if called != tc.pooled || s.freeGeneral != tc.freeGeneral || s.freeReserved != tc.freeRes || len(s.victims) != len(tc.victims) {
				t.Fatalf("pool read %t, limits %+v", called, s)
			}
			for i, v := range tc.victims {
				if s.victims[i] != v {
					t.Fatalf("victims %+v, want %+v", s.victims, tc.victims)
				}
			}
		})
	}
	boom := errors.New("pool unreadable")
	if _, err := (SetOccupancy{Limit: 11, Unclaimed: 1, General: 8, Reserved: 1}).Limits(func() ([]EvictionVictim, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("pool error = %v", err)
	}
	s, err := (SetOccupancy{Limit: 30000}).Limits(func() ([]EvictionVictim, error) {
		t.Fatal("a set with free slots read the pool")
		return nil, nil
	})
	if err != nil || s.freeGeneral != MaxCeiling || s.freeReserved != 6000 {
		t.Fatalf("a large empty set = %+v, %v; want free general slots clamped to the largest ceiling", s, err)
	}
}
