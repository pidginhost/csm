package admission

import "testing"

func TestAutomaticCapacity(t *testing.T) {
	for _, tc := range []struct{ limit, capacity int }{
		{-1, TemporaryCapacity}, {0, TemporaryCapacity}, {1, 1}, {500, 500},
		{TemporaryCapacity, TemporaryCapacity}, {20000, 20000},
	} {
		if got := AutomaticCapacity(tc.limit); got != tc.capacity {
			t.Errorf("AutomaticCapacity(%d) = %d, want %d", tc.limit, got, tc.capacity)
		}
	}
	if TemporaryCapacity != 10000 {
		t.Errorf("TemporaryCapacity = %d, want the shipped 10000", TemporaryCapacity)
	}
}

func TestPartitionOf(t *testing.T) {
	for _, tc := range []struct {
		lane Lane
		want Partition
	}{
		{LaneGeneral, PartitionGeneral}, {LaneDirect, PartitionReserved},
		{LaneCorroborated, PartitionReserved}, {0, 0}, {laneEnd, 0},
	} {
		if got := PartitionOf(tc.lane); got != tc.want {
			t.Errorf("PartitionOf(%s) = %d, want %d", tc.lane, got, tc.want)
		}
	}
}

func TestSetOccupancySlots(t *testing.T) {
	for _, tc := range []struct {
		name string
		occ  SetOccupancy
		want SetSlots
	}{
		{"empty set", SetOccupancy{Limit: 500},
			SetSlots{Capacity: 500, Available: 500, General: 400, Reserved: 100, FreeGeneral: 400, FreeReserved: 100}},
		{"zero limit is the finite capacity", SetOccupancy{},
			SetSlots{Capacity: 10000, Available: 10000, General: 8000, Reserved: 2000, FreeGeneral: 8000, FreeReserved: 2000}},
		{"the reserve rounds up", SetOccupancy{Limit: 6},
			SetSlots{Capacity: 6, Available: 6, General: 4, Reserved: 2, FreeGeneral: 4, FreeReserved: 2}},
		{"one slot left is reserved", SetOccupancy{Limit: 500, Unclaimed: 499},
			SetSlots{Capacity: 500, Available: 1, Reserved: 1, FreeReserved: 1}},
		{"unclaimed entries over the limit leave nothing", SetOccupancy{Limit: 500, Unclaimed: 600},
			SetSlots{Capacity: 500}},
		{"an overfull general partition keeps the reserve", SetOccupancy{Limit: 10, Unclaimed: 3, General: 6},
			SetSlots{Capacity: 10, Available: 7, General: 5, Reserved: 2, FreeReserved: 1}},
		{"an overfull reserve keeps general slots", SetOccupancy{Limit: 10, General: 2, Reserved: 3},
			SetSlots{Capacity: 10, Available: 10, General: 8, Reserved: 2, FreeGeneral: 5}},
	} {
		if got := tc.occ.Slots(); got != tc.want {
			t.Errorf("%s: %+v.Slots() = %+v, want %+v", tc.name, tc.occ, got, tc.want)
		}
	}
}

func TestSetSlotsFreeByLane(t *testing.T) {
	s := SetSlots{FreeGeneral: 3, FreeReserved: 1}
	for _, tc := range []struct {
		lane Lane
		want int
	}{
		{LaneGeneral, 3}, {LaneDirect, 1}, {LaneCorroborated, 1}, {0, 0},
	} {
		if got := s.Free(tc.lane); got != tc.want {
			t.Errorf("Free(%s) = %d, want %d", tc.lane, got, tc.want)
		}
	}
}

// Target partitions cannot manufacture physical room after a limit reduction.
func TestSetOccupancySharedHeadroom(t *testing.T) {
	for _, tc := range []struct {
		name              string
		occ               SetOccupancy
		general, reserved int
	}{
		{"general overflow", SetOccupancy{Limit: 10, General: 9}, 0, 1},
		{"reserve overflow", SetOccupancy{Limit: 10, General: 2, Reserved: 3}, 5, 0},
		{"full imports", SetOccupancy{Limit: 10, General: 10}, 0, 0},
		{"overfull imports", SetOccupancy{Limit: 10, General: 12}, 0, 0},
		{"manual addition", SetOccupancy{Limit: 10, Unclaimed: 4, General: 6}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.occ.Slots()
			if got.FreeGeneral != tc.general || got.FreeReserved != tc.reserved {
				t.Fatalf("shared headroom: %+v, want free %d general, %d reserved", got, tc.general, tc.reserved)
			}
		})
	}
}
