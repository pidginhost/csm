package admission

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

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

// ceilingAt is a state whose first limit is limit: filled like a new
// ledger's, or empty like an upgraded one's.
func ceilingAt(t *testing.T, limit uint32, fill bool) CeilingState {
	t.Helper()
	s, err := CeilingState{Fill: fill}.SetLimit(limit)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func advanceCeiling(t testing.TB, s CeilingState, elapsed time.Duration) CeilingState {
	t.Helper()
	next, err := s.Advance(elapsed)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestCeilingStateFillsOnceAndClips(t *testing.T) {
	s := ceilingAt(t, 2000, true)
	if s.General.Units() != 266 || s.Reserved.Units() != 66 || s.Fill {
		t.Fatalf("first limit of a new ledger: %+v", s)
	}
	lower, err := s.SetLimit(200)
	if err != nil || lower.General.Units() != 26 || lower.Reserved.Units() != 6 {
		t.Fatalf("reduced limit: %+v %v", lower, err)
	}
	raised, err := lower.SetLimit(2000)
	if err != nil || raised.General.Credit != lower.General.Credit || raised.Reserved.Credit != lower.Reserved.Credit {
		t.Fatalf("raised limit topped up credit: %+v %v", raised, err)
	}
	if up := ceilingAt(t, 2000, false); up.General.Credit != 0 || up.Reserved.Credit != 0 {
		t.Fatalf("an upgraded ledger's first limit filled credit: %+v", up)
	}
	for _, bad := range []uint32{0, MaxCeiling + 1} {
		got, err := s.SetLimit(bad)
		wantReason(t, "limit out of range", err, ReasonInvalid)
		if got != s {
			t.Errorf("refused limit %d changed the state", bad)
		}
	}
}

// At a ceiling of 2000 the general lane earns a unit every 2.25 seconds and
// the reserved lane every 9 seconds.
func TestCeilingStateRefillsAtItsRate(t *testing.T) {
	s := advanceCeiling(t, ceilingAt(t, 2000, false), 9*time.Second-time.Nanosecond)
	if s.Reserved.Units() != 0 || s.General.Units() != 3 {
		t.Fatalf("just before 9s: %+v", s)
	}
	s = advanceCeiling(t, s, time.Nanosecond)
	if s.Reserved.Credit != unitTicks || s.General.Credit != 4*unitTicks || s.Elapsed != 9*time.Second {
		t.Fatalf("at 9s: %+v", s)
	}
	s = advanceCeiling(t, s, 1<<62)
	if s.General.Credit != 266*unitTicks || s.Reserved.Credit != 66*unitTicks {
		t.Fatalf("a long gap must saturate at the caps: %+v", s)
	}
	// Refill never rounds up: 401 ticks short of the cap at 400 ticks per
	// nanosecond is still one tick short after a nanosecond.
	short := s
	short.Reserved.Credit -= 401
	if got := advanceCeiling(t, short, time.Nanosecond).Reserved.Credit; got != 66*unitTicks-1 {
		t.Fatalf("refill rounded: credit %d, want %d", got, 66*unitTicks-1)
	}
	for _, none := range []time.Duration{0, -time.Second} {
		if again := advanceCeiling(t, s, none); again != s {
			t.Errorf("advancing by %v changed the state", none)
		}
	}
	one := advanceCeiling(t, ceilingAt(t, 1, false), time.Hour)
	if one.General.Credit != 0 || one.Reserved.Units() != 1 {
		t.Fatalf("a ceiling of 1 runs only the reserved lane: %+v", one)
	}
}

func TestCeilingStateChargesWithinEveryBound(t *testing.T) {
	s := ceilingAt(t, 10, true)
	for _, l := range []Lane{LaneGeneral, LaneDirect, LaneCorroborated} {
		if got := s.Budget(l); got != 1 {
			t.Fatalf("%s budget = %d, want the saved unit", l, got)
		}
	}
	s, err := s.Charge(LaneDirect, 1)
	if err != nil || s.Reserved.Used != 1 || s.General.Used != 0 || s.Budget(LaneCorroborated) != 0 {
		t.Fatalf("direct and corroborated share the reserved allowance: %+v %v", s, err)
	}
	before := s
	refused, err := s.Charge(LaneCorroborated, 1)
	wantReason(t, "spent reserved credit", err, ReasonCeiling)
	if refused != before {
		t.Fatal("refused charge changed the state")
	}
	// Credit refills, but the general allowance of 8 bounds the window.
	for i := 0; i < 8; i++ {
		if s, err = advanceCeiling(t, s, time.Hour).Charge(LaneGeneral, 1); err != nil {
			t.Fatalf("general charge %d: %v", i+1, err)
		}
	}
	if s = advanceCeiling(t, s, time.Hour); s.General.Units() != 1 || s.Budget(LaneGeneral) != 0 {
		t.Fatalf("a full general allowance must stop charges: %+v", s)
	}
	if s, err = s.Release(LaneDirect, 1); err != nil || s.Reserved.Used != 0 {
		t.Fatalf("release: %+v %v", s, err)
	}
	// A reduced limit (G=4, R=1) leaves general usage above both the new
	// general allowance and the whole ceiling: the reserved lane, with
	// credit and room of its own, waits for general charges to age out.
	if s, err = s.SetLimit(5); err != nil {
		t.Fatal(err)
	}
	if s.Reserved.Units() != 1 || s.Budget(LaneDirect) != 0 {
		t.Fatalf("usage above the whole ceiling must stop the reserved lane: %+v", s)
	}
	if s, err = s.Release(LaneGeneral, 3); err != nil || s.General.Used != 5 || s.Budget(LaneDirect) != 0 {
		t.Fatalf("release to the whole ceiling: %+v %v", s, err)
	}
	if s, err = s.Release(LaneGeneral, 1); err != nil || s.Budget(LaneDirect) != 1 || s.Budget(LaneGeneral) != 0 {
		t.Fatalf("room under the whole ceiling: %+v %v", s, err)
	}
	if _, err = s.Release(LaneCorroborated, 1); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("releasing more than was charged: %v", err)
	}
	for name, tc := range map[string]struct {
		s    CeilingState
		lane Lane
		cost uint32
		want Reason
	}{
		"no lane":       {s, 0, 1, ReasonInvalid},
		"free":          {s, LaneDirect, 0, ReasonInvalid},
		"too large":     {s, LaneDirect, MaxMemberCost + 1, ReasonInvalid},
		"ceiling unset": {CeilingState{Fill: true}, LaneGeneral, 1, ReasonEngineUnavailable},
	} {
		_, err := tc.s.Charge(tc.lane, tc.cost)
		wantReason(t, name, err, tc.want)
	}
}

func TestCeilingStateCodec(t *testing.T) {
	charged, err := advanceCeiling(t, ceilingAt(t, 2000, true), time.Minute).Charge(LaneCorroborated, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []CeilingState{{}, {Fill: true}, ceilingAt(t, 1, false), charged} {
		data, err := s.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmarshalCeilingState(data)
		if err != nil || back != s {
			t.Fatalf("round trip %+v: %+v %v", s, back, err)
		}
	}
	for name, bad := range map[string]CeilingState{
		"limit too high":         {Limit: MaxCeiling + 1},
		"fill after a limit":     {Limit: 10, Fill: true},
		"negative elapsed":       {Elapsed: -1},
		"credit without a limit": {General: Meter{Credit: 1}},
		"credit over the cap":    {Limit: 10, Reserved: Meter{Credit: unitTicks + 1}},
		"usage over any ceiling": {General: Meter{Used: MaxCeiling}, Reserved: Meter{Used: 1}},
	} {
		_, err := bad.MarshalBinary()
		wantReason(t, name, err, ReasonInvalid)
	}
	good, _ := charged.MarshalBinary()
	flipped := append([]byte(nil), good...)
	flipped[len(flipped)-1] ^= 1
	unfilled, _ := sealRecord(ceilingStateRecord{V: ceilingStateVersion, Limit: 10, Fill: true})
	future, _ := sealRecord(ceilingStateRecord{V: ceilingStateVersion + 1})
	unknown, _ := sealRecord(map[string]any{"v": ceilingStateVersion, "burst": 1})
	for name, data := range map[string][]byte{"checksum": flipped, "invariant": unfilled, "version": future, "unknown field": unknown} {
		if _, err := UnmarshalCeilingState(data); !errors.Is(err, ErrCorruptRecord) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func testCharge(t *testing.T, at time.Time, seq uint32, lane Lane) Charge {
	t.Helper()
	cand, _ := queuedCandidate(t).ID()
	a, err := NewAttempt(cand, seq)
	if err != nil {
		t.Fatal(err)
	}
	return Charge{At: at, Action: a.ID, Lane: lane, Cost: 1, Elapsed: time.Hour}
}

func TestChargeCodec(t *testing.T) {
	early, late := testCharge(t, t0, 2, LaneGeneral), testCharge(t, t0.Add(time.Nanosecond), 1, LaneDirect)
	keys := map[string]Charge{}
	for _, c := range []Charge{early, late} {
		key, err := c.Key()
		if err != nil || len(key) != chargeKeyLen {
			t.Fatalf("key: %x %v", key, err)
		}
		data, err := c.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmarshalCharge(key, data)
		if err != nil || back != c {
			t.Fatalf("round trip %+v: %+v %v", c, back, err)
		}
		keys[string(key)] = c
	}
	earlyKey, _ := early.Key()
	lateKey, _ := late.Key()
	if bytes.Compare(earlyKey, lateKey) >= 0 {
		t.Fatal("an earlier charge must sort first, whatever its action")
	}
	for name, bad := range map[string]Charge{
		"no time":          {Action: early.Action, Lane: LaneGeneral, Cost: 1},
		"before the epoch": {At: time.Unix(-1, 0), Action: early.Action, Lane: LaneGeneral, Cost: 1},
		"no action":        {At: t0, Lane: LaneGeneral, Cost: 1},
		"no lane":          {At: t0, Action: early.Action, Cost: 1},
		"unknown lane":     {At: t0, Action: early.Action, Lane: laneEnd, Cost: 1},
		"free":             {At: t0, Action: early.Action, Lane: LaneGeneral},
		"too large":        {At: t0, Action: early.Action, Lane: LaneGeneral, Cost: MaxMemberCost + 1},
		"negative elapsed": {At: t0, Action: early.Action, Lane: LaneGeneral, Cost: 1, Elapsed: -1},
	} {
		_, err := bad.MarshalBinary()
		wantReason(t, name, err, ReasonInvalid)
	}
	data, _ := early.MarshalBinary()
	flipped := append([]byte(nil), data...)
	flipped[len(flipped)-1] ^= 1
	future, _ := sealRecord(chargeRecord{V: chargeVersion + 1, Lane: LaneGeneral, Cost: 1})
	unknown, _ := sealRecord(map[string]any{"v": chargeVersion, "lane": LaneGeneral, "cost": 1, "refund": true})
	free, _ := sealRecord(chargeRecord{V: chargeVersion, Lane: LaneGeneral})
	top := append(binary.BigEndian.AppendUint64(nil, 1<<63), early.Action...)
	for name, tc := range map[string]struct{ key, data []byte }{
		"checksum":      {earlyKey, flipped},
		"version":       {earlyKey, future},
		"unknown field": {earlyKey, unknown},
		"invariant":     {earlyKey, free},
		"short key":     {earlyKey[:chargeKeyLen-1], data},
		"key action":    {append(earlyKey[:8:8], "act_zz"+string(early.Action[6:])...), data},
		"key time":      {top, data},
	} {
		if _, err := UnmarshalCharge(tc.key, tc.data); !errors.Is(err, ErrCorruptRecord) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A charge leaves the window only when a full window of wall time and of
// elapsed time have both passed since it was spent.
func TestChargeReleasable(t *testing.T) {
	c := testCharge(t, t0, 1, LaneGeneral)
	for _, tc := range []struct {
		name    string
		now     time.Time
		elapsed time.Duration
		want    bool
	}{
		{"inside the window", t0.Add(CeilingWindow - time.Nanosecond), c.Elapsed + CeilingWindow, false},
		{"at the window's end", t0.Add(CeilingWindow), c.Elapsed + CeilingWindow, true},
		{"wall step or downtime", t0.Add(24 * time.Hour), c.Elapsed + CeilingWindow - time.Nanosecond, false},
		{"elapsed past a future date", t0.Add(CeilingWindow - time.Nanosecond), c.Elapsed + 24*time.Hour, false},
	} {
		if got := c.Releasable(tc.now, tc.elapsed); got != tc.want {
			t.Errorf("%s: Releasable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCeilingStateElapsedOverflow(t *testing.T) {
	const last = time.Duration(1<<63 - 1)
	s := ceilingAt(t, 2000, false)
	full, err := s.Advance(last)
	if err != nil || full.Elapsed != last || full.General.Units() != 266 || full.Reserved.Units() != 66 {
		t.Fatalf("largest delta: %+v %v", full, err)
	}
	s.Elapsed = last - time.Nanosecond
	next, err := s.Advance(time.Nanosecond)
	if err != nil || next.Elapsed != last || next.General.Credit != 1600 || next.Reserved.Credit != 400 {
		t.Fatalf("last representable tick: %+v %v", next, err)
	}
	for _, elapsed := range []time.Duration{2 * time.Nanosecond, last} {
		got, err := s.Advance(elapsed)
		wantReason(t, "elapsed overflow", err, ReasonEngineUnavailable)
		if got != s {
			t.Fatalf("refused advance changed state: %+v", got)
		}
	}
}
