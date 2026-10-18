package admission

import (
	"errors"
	"testing"
	"time"
)

// A model that does not count a charge uncharges it: its units leave the
// window and its credit returns to its lane, never past the bucket's cap.
// More units than the lane holds, or no lane, is a corrupt record.
func TestCeilingUnchargeReturnsUnitsAndCredit(t *testing.T) {
	s, err := (CeilingState{Fill: true}).SetLimit(60)
	if err != nil {
		t.Fatal(err)
	}
	full := s.General.Credit
	spent, err := s.Charge(LaneGeneral, 2)
	if err != nil {
		t.Fatal(err)
	}
	back, err := spent.Uncharge(LaneGeneral, 2)
	if err != nil || back != s {
		t.Fatalf("uncharge = %+v, %v; want %+v", back, err, s)
	}
	refilled, err := spent.Advance(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	capped, err := refilled.Uncharge(LaneGeneral, 2)
	if err != nil || capped.General.Credit != full || capped.General.Used != 0 {
		t.Fatalf("credit past the cap: %+v, %v", capped.General, err)
	}
	reserved, err := s.Charge(LaneDirect, 1)
	if err != nil {
		t.Fatal(err)
	}
	if back, err = reserved.Uncharge(LaneCorroborated, 1); err != nil || back.Reserved != s.Reserved {
		t.Fatalf("reserved uncharge = %+v, %v", back.Reserved, err)
	}
	for _, lane := range []Lane{LaneGeneral, LaneDirect, LaneCorroborated} {
		charged, chargeErr := s.Charge(lane, 2)
		if chargeErr != nil {
			t.Fatal(chargeErr)
		}
		reduced, limitErr := charged.SetLimit(1)
		if limitErr != nil {
			t.Fatal(limitErr)
		}
		got, unchargeErr := reduced.Uncharge(lane, 2)
		want := reduced
		if lane == LaneGeneral {
			want.General.Used, want.General.Credit = 0, 0
		} else {
			want.Reserved.Used, want.Reserved.Credit = 0, unitTicks
		}
		if unchargeErr != nil || got != want {
			t.Fatalf("reduced-limit lane %v = %+v, %v; want %+v", lane, got, unchargeErr, want)
		}
	}
	if back, err = spent.Uncharge(LaneGeneral, 3); !errors.Is(err, ErrCorruptRecord) || back != spent {
		t.Fatalf("uncharging more than used = %+v, %v", back, err)
	}
	if back, err = spent.Uncharge(Lane(0), 1); !errors.Is(err, ErrCorruptRecord) || back != spent {
		t.Fatalf("uncharging no lane = %+v, %v", back, err)
	}
}
