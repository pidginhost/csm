package admission

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"time"
)

func TestHistoryLanes(t *testing.T) {
	general, reserved := HistoryLanes()
	if general+reserved != HistoryBytes || reserved != (HistoryBytes+4)/5 {
		t.Fatalf("HistoryLanes() = %d, %d", general, reserved)
	}
	for _, tc := range []struct {
		size, rate, cap uint64
	}{
		{general, general / 604800, general / 604800 * 600},
		{reserved, reserved / 604800, reserved / 604800 * 600},
	} {
		if got := HistoryRate(tc.size); got != tc.rate {
			t.Errorf("HistoryRate(%d) = %d, want %d", tc.size, got, tc.rate)
		}
		if got := HistoryCap(tc.size); got != tc.cap {
			t.Errorf("HistoryCap(%d) = %d, want %d", tc.size, got, tc.cap)
		}
	}
	// A reservation of the largest candidate must fit each allowance's
	// saved credit, or that lane could never admit it.
	for _, size := range []uint64{general, reserved} {
		if HistoryCap(size) < MaxHistoryBytes {
			t.Errorf("an allowance of %d bytes saves %d, less than the largest candidate", size, HistoryCap(size))
		}
	}
}

// HistoryCost counts every row a candidate can retain, each with its key.
func TestHistoryCost(t *testing.T) {
	c := queuedCandidate(t)
	maxBytes, err := c.MaxBytes()
	if err != nil {
		t.Fatal(err)
	}
	const cand, action, evidence, index = 37, 36, 35, 1 + 19 + 37
	want := cand + maxBytes + cand + MaxHistoryEntryBytes + 3*index + MaxAttempts*(action+MaxAttemptBytes)
	want += 2*3*evidence + 400 + 700 + 2*(MaxReportLinksBytes+MaxEvidenceRefsBytes)
	got, err := HistoryCost(c, []int{400, 700})
	if err != nil || got != uint32(want) {
		t.Fatalf("HistoryCost = %d, %v; want %d", got, err, want)
	}
	for name, sizes := range map[string][]int{
		"missing root":   {400},
		"extra root":     {400, 700, 10},
		"empty evidence": {400, 0},
		"oversized":      {400, MaxEvidenceBytes + 1},
	} {
		if _, costErr := HistoryCost(c, sizes); costErr == nil {
			t.Errorf("%s: HistoryCost accepted it", name)
		}
	}
	sizes := make([]int, MaxRoots)
	for i := range sizes {
		sizes[i] = MaxEvidenceBytes
	}
	largest, err := HistoryCost(largestCandidate(t), sizes)
	if err != nil || largest > MaxHistoryBytes {
		t.Fatalf("largest candidate costs %d, %v; bound %d", largest, err, MaxHistoryBytes)
	}
}

func TestStorageStateStartsFull(t *testing.T) {
	s := NewStorageState()
	general, reserved := HistoryLanes()
	if s.General.Bytes() != HistoryCap(general) || s.Reserved.Bytes() != HistoryCap(reserved) {
		t.Fatalf("new state saves %d and %d bytes", s.General.Bytes(), s.Reserved.Bytes())
	}
	if s.General.Used != 0 || s.Reserved.Used != 0 || s.Recovery != 0 || s.Ended != (RingState{}) || s.Loose != (RingState{}) {
		t.Fatalf("new state is not empty: %+v", s)
	}
	if s.NoticeRecords != FixedNotices || s.AuditSlots != 0 || s.OutboxBytes() != uint64(FixedNotices*NoticeSlotBytes) {
		t.Fatalf("new outbox usage: %+v", s)
	}
	var upgraded StorageState
	if upgraded.HistoryBudget(LaneGeneral, 0) != 0 || upgraded.OutboxBytes() != 0 {
		t.Fatal("an upgraded state has credit or outbox usage")
	}
}

func TestStorageStateRefillsAtItsRate(t *testing.T) {
	general, reserved := HistoryLanes()
	var s StorageState
	var err error
	if s, err = s.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	if s.General.Bytes() != HistoryRate(general) || s.Reserved.Bytes() != HistoryRate(reserved) {
		t.Fatalf("a second earned %d and %d bytes", s.General.Bytes(), s.Reserved.Bytes())
	}
	// Refill is exact: half a second twice earns what a second does.
	var halves StorageState
	for i := 0; i < 2; i++ {
		if halves, err = halves.Advance(time.Second / 2); err != nil {
			t.Fatal(err)
		}
	}
	if halves != s {
		t.Fatalf("two half seconds = %+v, want %+v", halves, s)
	}
	// Credit saturates at the cap however long the gap.
	for _, gap := range []time.Duration{HistoryBurst, 365 * 24 * time.Hour, math.MaxInt64} {
		full, gapErr := StorageState{}.Advance(gap)
		if gapErr != nil || full.General.Bytes() != HistoryCap(general) || full.Reserved.Bytes() != HistoryCap(reserved) {
			t.Fatalf("gap %v: %+v, %v", gap, full, gapErr)
		}
	}
	// One nanosecond short of the cap stays short of it, even when the
	// ticks still needed are not a whole number of nanoseconds of rate.
	short, _ := StorageState{}.Advance(HistoryBurst - time.Nanosecond)
	if short.General.Bytes() >= HistoryCap(general) {
		t.Fatalf("a burst less a nanosecond filled the general allowance: %d", short.General.Bytes())
	}
	var odd StorageState
	odd.General.Credit = 1
	if odd, err = odd.Advance(HistoryBurst - time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if want := 1 + HistoryRate(general)*uint64(HistoryBurst-time.Nanosecond); odd.General.Credit != want {
		t.Fatalf("credit a tick past a whole rate = %d, want %d", odd.General.Credit, want)
	}
	if same, _ := s.Advance(0); same != s {
		t.Fatal("no elapsed time changed the state")
	}
}

func TestStorageStateChargesWithinEveryBound(t *testing.T) {
	general, reserved := HistoryLanes()
	s := NewStorageState()
	next, err := s.ChargeHistory(LaneDirect, 3000)
	if err != nil {
		t.Fatal(err)
	}
	if next.Reserved.Used != 3000 || next.Reserved.Bytes() != HistoryCap(reserved)-3000 || next.General != s.General {
		t.Fatalf("a direct charge spent %+v", next)
	}
	if next, err = next.ChargeHistory(LaneCorroborated, 1000); err != nil || next.Reserved.Used != 4000 {
		t.Fatalf("a corroborated charge: %+v, %v", next.Reserved, err)
	}
	for _, tc := range []struct {
		name   string
		state  StorageState
		lane   Lane
		bytes  uint32
		reason Reason
	}{
		{"no lane", s, 0, 10, ReasonInvalid},
		{"nothing", s, LaneGeneral, 0, ReasonInvalid},
		{"beyond any candidate", s, LaneGeneral, MaxHistoryBytes + 1, ReasonInvalid},
		{"beyond saved credit", StorageState{}, LaneGeneral, 1, ReasonStorageShare},
		{"beyond the allowance", func() StorageState { x := s; x.General.Used = general - 99; return x }(), LaneGeneral, 100, ReasonStorageShare},
		{"reserved allowance spent", func() StorageState { x := s; x.Reserved.Used = reserved; return x }(), LaneDirect, 1, ReasonStorageShare},
	} {
		got, err := tc.state.ChargeHistory(tc.lane, tc.bytes)
		if reason, ok := ReasonOf(err); !ok || reason != tc.reason || got != tc.state {
			t.Errorf("%s: %+v, %v; want refusal %s and no change", tc.name, got, err, tc.reason)
		}
	}
	fits := s
	fits.General.Used = general - 100
	if _, err := fits.ChargeHistory(LaneGeneral, 100); err != nil {
		t.Fatalf("a charge that fills the allowance exactly: %v", err)
	}
}

func TestStorageStateHistoryBudget(t *testing.T) {
	general, reserved := HistoryLanes()
	s := NewStorageState()
	if got := s.HistoryBudget(LaneGeneral, 0); got != HistoryCap(general) {
		t.Fatalf("full general budget = %d", got)
	}
	if got := s.HistoryBudget(LaneCorroborated, 0); got != HistoryCap(reserved) {
		t.Fatalf("full reserved budget = %d", got)
	}
	s.General.Used = general - 500
	if got := s.HistoryBudget(LaneGeneral, 0); got != 500 {
		t.Fatalf("budget near a full allowance = %d, want 500", got)
	}
	if got := s.HistoryBudget(LaneGeneral, 700); got != 1200 {
		t.Fatalf("budget with retirable history = %d, want 1200", got)
	}
	s.General.Used = general + 900
	if got := s.HistoryBudget(LaneGeneral, 700); got != 0 {
		t.Fatalf("budget over the allowance = %d, want 0", got)
	}
	if got := s.HistoryBudget(LaneGeneral, 1000); got != 100 {
		t.Fatalf("budget once retirement clears the excess = %d, want 100", got)
	}
	if s.HistoryBudget(0, 0) != 0 {
		t.Fatal("no lane has a budget")
	}
	if s.HistoryRoom(LaneGeneral) != 0 || s.HistoryCredit(LaneGeneral) != HistoryCap(general) {
		t.Fatalf("an over-full allowance: room %d, credit %d", s.HistoryRoom(LaneGeneral), s.HistoryCredit(LaneGeneral))
	}
	s.General.Used = general - 500
	if s.HistoryRoom(LaneGeneral) != 500 || s.HistoryRoom(LaneDirect) != reserved || s.HistoryCredit(LaneCorroborated) != HistoryCap(reserved) {
		t.Fatalf("rooms %d and %d", s.HistoryRoom(LaneGeneral), s.HistoryRoom(LaneDirect))
	}
	if s.HistoryRoom(0) != 0 || s.HistoryCredit(0) != 0 {
		t.Fatal("no lane has room or credit")
	}
}

func TestStorageStateReleaseAndPin(t *testing.T) {
	s := NewStorageState()
	s.General.Used, s.Reserved.Used = 5000, 3000
	released, err := s.ReleaseHistory(2000, 1000)
	if err != nil || released.General.Used != 3000 || released.Reserved.Used != 2000 || released.General.Credit != s.General.Credit {
		t.Fatalf("release: %+v, %v", released, err)
	}
	pinned, err := s.PinHistory(2000, 1000)
	if err != nil || pinned.General.Used != 3000 || pinned.Reserved.Used != 2000 || pinned.Recovery != 3000 {
		t.Fatalf("pin: %+v, %v", pinned, err)
	}
	for name, err := range map[string]error{
		"release too much general":  func() error { _, err := s.ReleaseHistory(5001, 0); return err }(),
		"release too much reserved": func() error { _, err := s.ReleaseHistory(0, 3001); return err }(),
		"pin too much":              func() error { _, err := s.PinHistory(0, 3001); return err }(),
	} {
		if !errors.Is(err, ErrCorruptRecord) {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
	overflow := pinned
	overflow.Recovery = math.MaxUint64
	if reason, ok := ReasonOf(overflow.CheckRecovery(1)); !ok || reason != ReasonPendingRecovery {
		t.Fatal("recovery arithmetic wrapped")
	}
	if err := pinned.CheckRecovery(RecoveryReserveBytes - 3000); err != nil {
		t.Fatalf("a reservation that fills the reserve exactly: %v", err)
	}
	if reason, ok := ReasonOf(pinned.CheckRecovery(RecoveryReserveBytes - 2999)); !ok || reason != ReasonPendingRecovery {
		t.Fatalf("a reservation beyond the reserve: %v", pinned.CheckRecovery(RecoveryReserveBytes-2999))
	}
}

func TestStoragePinRefusesOverflowWithoutChangingState(t *testing.T) {
	for _, charge := range []struct{ general, reserved uint32 }{{1, 0}, {0, 1}, {1, 1}} {
		s := NewStorageState()
		s.General.Used, s.Reserved.Used = uint64(charge.general), uint64(charge.reserved)
		s.Recovery = math.MaxUint64 - uint64(charge.general) - uint64(charge.reserved) + 1
		data, err := s.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		s, err = UnmarshalStorageState(data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.PinHistory(charge.general, charge.reserved)
		if !errors.Is(err, ErrCorruptRecord) || got != s {
			t.Fatalf("overflow changed history or recovery: %+v, %v; want %+v", got, err, s)
		}
		// Imported unresolved outcomes may exceed the reserve. Pinning
		// must retain those bytes as long as their total is representable.
		s.Recovery--
		got, err = s.PinHistory(charge.general, charge.reserved)
		want := s
		want.General.Used, want.Reserved.Used, want.Recovery = 0, 0, math.MaxUint64
		if err != nil || got != want {
			t.Fatalf("representable pin = %+v, %v; want %+v", got, err, want)
		}
	}
}

func TestStorageStateUntilHistory(t *testing.T) {
	general, reserved := HistoryLanes()
	wait := func(bytes, size uint64) time.Duration {
		rate := HistoryRate(size)
		return time.Duration((bytes*uint64(time.Second) + rate - 1) / rate)
	}
	var s StorageState
	if d, ok := s.UntilHistory(LaneGeneral); !ok || d != wait(HistoryQuantum, general) {
		t.Fatalf("empty general allowance waits %v %v, want %v", d, ok, wait(HistoryQuantum, general))
	}
	if d, ok := s.UntilHistory(LaneCorroborated); !ok || d != wait(HistoryQuantum, reserved) {
		t.Fatalf("empty reserved allowance waits %v %v", d, ok)
	}
	full := NewStorageState()
	if _, ok := full.UntilHistory(LaneGeneral); ok {
		t.Fatal("a full allowance waits for credit")
	}
	near := full
	near.General.Credit -= 1000 * uint64(time.Second)
	if d, ok := near.UntilHistory(LaneGeneral); !ok || d != wait(1000, general) {
		t.Fatalf("an allowance 1000 bytes short of its cap waits %v %v, want %v", d, ok, wait(1000, general))
	}
	if _, ok := s.UntilHistory(0); ok {
		t.Fatal("no lane waits")
	}
}

func TestRingPositions(t *testing.T) {
	var r RingState
	r, first := r.Push()
	r, second := r.Push()
	if first != 1 || second != 2 || r.Count != 2 || r.Last != 2 {
		t.Fatalf("pushes: %d %d %+v", first, second, r)
	}
	r, err := r.Remove()
	if err != nil || r.Count != 1 || r.Last != 2 {
		t.Fatalf("remove: %+v, %v", r, err)
	}
	if _, err := (RingState{}).Remove(); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("removing from an empty ring: %v", err)
	}
}

func TestStorageStateCodec(t *testing.T) {
	general, reserved := HistoryLanes()
	s := NewStorageState()
	s.General.Used, s.Reserved.Used, s.Recovery = 123456, 789, 42
	s.Ended, s.Loose = RingState{Count: 3, Last: 9}, RingState{Count: MaxLooseEvidence, Last: 1 << 40}
	s.AuditSlots, s.NoticeRecords = MaxAuditSlots, MaxNoticeRecords
	if s.OutboxBytes() != MaxAuditSlots*uint64(AuditSlotBytes)+MaxNoticeRecords*uint64(NoticeSlotBytes) {
		t.Fatalf("outbox bytes %d", s.OutboxBytes())
	}
	data, err := s.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := UnmarshalStorageState(data); err != nil || back != s {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*StorageState)
	}{
		{"general credit above its cap", func(s *StorageState) { s.General.Credit = (HistoryCap(general) + 1) * uint64(time.Second) }},
		{"reserved credit above its cap", func(s *StorageState) { s.Reserved.Credit = (HistoryCap(reserved) + 1) * uint64(time.Second) }},
		{"ended ring over its bound", func(s *StorageState) {
			s.Ended = RingState{Count: MaxEndedCandidates + 1, Last: MaxEndedCandidates + 1}
		}},
		{"loose ring over its bound", func(s *StorageState) { s.Loose = RingState{Count: MaxLooseEvidence + 1, Last: MaxLooseEvidence + 1} }},
		{"more entries than positions", func(s *StorageState) { s.Ended = RingState{Count: 4, Last: 3} }},
		{"notice records over their share", func(s *StorageState) { s.NoticeRecords = MaxNoticeRecords + 1 }},
		{"audit slots over the reserve", func(s *StorageState) { s.AuditSlots = MaxAuditSlots + 1 }},
	} {
		bad := s
		tc.mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", tc.name)
		}
		if _, err := bad.MarshalBinary(); err == nil {
			t.Errorf("%s: encoded it", tc.name)
		}
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":   func() []byte { d := bytes.Clone(data); d[5] ^= 1; return d }(),
		"future version": resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
		"unknown field":  resealForTest(bytes.Replace(body, []byte(`{"v":1`), []byte(`{"x":1,"v":1`), 1)),
		"ring overflow":  resealForTest(bytes.Replace(body, []byte(`"ended_count":3`), []byte(`"ended_count":10`), 1)),
	} {
		if _, err := UnmarshalStorageState(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

// A week of flood at the paced rate cannot fill the general allowance
// faster than its rate or touch the reserved one, and history retired after
// the review window keeps general work flowing (spec 5.4).
func TestStorageStateSurvivesAWeekOfFlood(t *testing.T) {
	general, _ := HistoryLanes()
	const cost = 2700
	type held struct {
		at    time.Duration
		bytes uint32
	}
	s := NewStorageState()
	var fifo []held
	var admitted uint64
	var err error
	for now := time.Duration(0); now <= HistoryRetention+time.Hour; now += time.Second {
		for len(fifo) > 0 && now-fifo[0].at >= HistoryRetention {
			if s, err = s.ReleaseHistory(fifo[0].bytes, 0); err != nil {
				t.Fatal(err)
			}
			fifo = fifo[1:]
		}
		for {
			next, chargeErr := s.ChargeHistory(LaneGeneral, cost)
			if chargeErr != nil {
				break
			}
			s = next
			fifo = append(fifo, held{now, cost})
			admitted += cost
		}
		if s.General.Used > general {
			t.Fatalf("at %v the general allowance holds %d bytes", now, s.General.Used)
		}
		if now == time.Hour && admitted > HistoryCap(general)+HistoryRate(general)*3600 {
			t.Fatalf("an hour of flood admitted %d bytes", admitted)
		}
		if _, reservedErr := s.ChargeHistory(LaneDirect, MaxHistoryBytes); reservedErr != nil {
			t.Fatalf("at %v the reserved allowance refused the largest candidate: %v", now, reservedErr)
		}
		if s, err = s.Advance(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if s.General.Used == 0 || len(fifo) == 0 {
		t.Fatal("the flood admitted nothing")
	}
}
