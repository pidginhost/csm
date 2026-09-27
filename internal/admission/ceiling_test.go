package admission

import "testing"

func TestCeilingLanes(t *testing.T) {
	for _, tc := range []struct{ limit, general, reserved uint32 }{
		{1, 0, 1}, {2, 1, 1}, {5, 4, 1}, {6, 4, 2}, {10, 8, 2}, {11, 8, 3},
		{200, 160, 40}, {2000, 1600, 400}, {MaxCeiling, 16000, 4000},
	} {
		g, r := CeilingLanes(tc.limit)
		if g != tc.general || r != tc.reserved {
			t.Errorf("CeilingLanes(%d) = %d, %d; want %d, %d", tc.limit, g, r, tc.general, tc.reserved)
		}
	}
}

func TestBucketCap(t *testing.T) {
	for _, tc := range []struct{ size, cap uint32 }{
		{0, 0}, {1, 1}, {5, 1}, {6, 1}, {11, 1}, {12, 2}, {40, 6}, {400, 66}, {1600, 266},
	} {
		if got := BucketCap(tc.size); got != tc.cap {
			t.Errorf("BucketCap(%d) = %d, want %d", tc.size, got, tc.cap)
		}
	}
}

func TestCeilingCost(t *testing.T) {
	for k := KindBlockIP; k < kindEnd; k++ {
		want := uint32(1)
		if k == KindChallenge {
			want = 0
		}
		if got := k.CeilingCost(); got != want {
			t.Errorf("%s costs %d, want %d", k, got, want)
		}
	}
}

// Escrow for members costing more than their lane's cap is deferred until
// members cost more than one unit. Until then every charge must fit every
// lane that can run, at every ceiling the ledger accepts.
func TestEveryChargeFitsEveryRunningLane(t *testing.T) {
	for limit := uint32(1); limit <= MaxCeiling; limit++ {
		g, r := CeilingLanes(limit)
		if g+r != limit || r == 0 {
			t.Fatalf("CeilingLanes(%d) = %d, %d", limit, g, r)
		}
		for _, size := range []uint32{g, r} {
			if size == 0 {
				continue
			}
			for k := KindBlockIP; k < kindEnd; k++ {
				if k.CeilingCost() > BucketCap(size) {
					t.Fatalf("limit %d: %s costs more than a lane of %d can save", limit, k, size)
				}
			}
		}
	}
}
