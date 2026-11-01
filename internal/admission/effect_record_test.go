package admission

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"
)

func testEffect(t *testing.T, seq uint32) EffectRecord {
	t.Helper()
	c := queuedCandidate(t)
	cand, err := c.ID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAttempt(cand, seq)
	if err != nil {
		t.Fatal(err)
	}
	return EffectRecord{
		Action: a.ID, Target: mustAddr(t, "192.0.2.10"), Partition: PartitionGeneral, Lane: LaneGeneral,
		Tier: Tier{Class: ClassC2, Severity: SeverityHigh}, Scope: c.Scope.Key(), ExpiresAt: t0.Add(24 * time.Hour),
	}
}

func TestEffectRecordCodec(t *testing.T) {
	pending := testEffect(t, 1)
	verified := pending
	verified.Applied, verified.Elapsed = t0.Add(time.Minute), 90*time.Minute
	reserved := testEffect(t, 2)
	reserved.Target, reserved.Partition, reserved.Lane = mustAddr(t, "2001:db8::7"), PartitionReserved, LaneDirect
	reserved.Tier, reserved.Direct = Tier{Class: ClassC3, Severity: SeverityCritical}, true
	if pending.Verified() || !verified.Verified() {
		t.Fatal("an effect is verified once its application time is recorded")
	}
	for _, e := range []EffectRecord{pending, verified, reserved} {
		key, err := e.Key()
		if err != nil || len(key) != effectKeyLen {
			t.Fatalf("key of %+v: %x %v", e, key, err)
		}
		if binary.BigEndian.Uint64(key[:8]) != uint64(e.ExpiresAt.UnixNano()) {
			t.Fatal("key prefix does not order expiry as big-endian nanoseconds")
		}
		if again, againErr := EffectRecordKey(e.Action, e.ExpiresAt); againErr != nil || !bytes.Equal(again, key) {
			t.Fatalf("key from the action and expiry: %x %v", again, againErr)
		}
		data, err := e.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmarshalEffectRecord(key, data)
		if err != nil || back != e {
			t.Fatalf("round trip %+v: %+v %v", e, back, err)
		}
	}
	sooner := reserved
	sooner.ExpiresAt = pending.ExpiresAt.Add(-time.Nanosecond)
	soonerKey, _ := sooner.Key()
	laterKey, _ := pending.Key()
	if bytes.Compare(soonerKey, laterKey) >= 0 {
		t.Fatal("an effect that ends sooner must sort first, whatever its action")
	}
	key, _ := pending.Key()
	data, _ := pending.MarshalBinary()
	badAction := append(bytes.Clone(key[:8]), "act_"+strings.Repeat("z", 32)...)
	flipped := bytes.Clone(data)
	flipped[len(flipped)-1] ^= 1
	for name, bad := range map[string]struct{ key, data []byte }{
		"a malformed action": {badAction, data},
		"short key":          {key[:len(key)-1], data},
		"flipped checksum":   {key, flipped},
	} {
		if _, err := UnmarshalEffectRecord(bad.key, bad.data); err != ErrCorruptRecord {
			t.Errorf("%s: %v, want a corrupt record", name, err)
		}
	}
}

func TestEffectRecordRefusesImpossibleRecords(t *testing.T) {
	ok := testEffect(t, 1)
	for name, change := range map[string]func(e *EffectRecord){
		"no action":                    func(e *EffectRecord) { e.Action = "" },
		"a prefix target":              func(e *EffectRecord) { e.Target = mustPrefix(t, "198.51.100.0/24") },
		"no target":                    func(e *EffectRecord) { e.Target = Target{} },
		"no partition":                 func(e *EffectRecord) { e.Partition = 0 },
		"no lane":                      func(e *EffectRecord) { e.Lane = 0 },
		"general work in the reserve":  func(e *EffectRecord) { e.Partition = PartitionReserved },
		"no tier":                      func(e *EffectRecord) { e.Tier = Tier{} },
		"both reserved turns":          func(e *EffectRecord) { e.Tier.Class, e.Direct, e.Corroborated = ClassC3, true, true },
		"reserved evidence below C3":   func(e *EffectRecord) { e.Corroborated = true },
		"no scope":                     func(e *EffectRecord) { e.Scope = "" },
		"a scope with a space":         func(e *EffectRecord) { e.Scope = "alice smith" },
		"an oversized scope":           func(e *EffectRecord) { e.Scope = strings.Repeat("s", 129) },
		"no expiry":                    func(e *EffectRecord) { e.ExpiresAt = time.Time{} },
		"expiry at the epoch":          func(e *EffectRecord) { e.ExpiresAt = time.Unix(0, 0) },
		"an expiry before the epoch":   func(e *EffectRecord) { e.ExpiresAt = time.Unix(-1, 0) },
		"overflowing expiry":           func(e *EffectRecord) { e.ExpiresAt = time.Unix(0, math.MaxInt64).Add(time.Nanosecond) },
		"wrapped positive expiry":      func(e *EffectRecord) { e.ExpiresAt = time.Unix(0, 1).AddDate(600, 0, 0) },
		"application at the epoch":     func(e *EffectRecord) { e.Applied = time.Unix(0, 0) },
		"an application before epoch":  func(e *EffectRecord) { e.Applied = time.Unix(-1, 0) },
		"overflowing application":      func(e *EffectRecord) { e.Applied = time.Unix(0, math.MaxInt64).Add(time.Nanosecond) },
		"elapsed time without applied": func(e *EffectRecord) { e.Elapsed = time.Minute },
		"negative elapsed time":        func(e *EffectRecord) { e.Applied, e.Elapsed = t0, -time.Nanosecond },
	} {
		e := ok
		change(&e)
		if _, err := e.Key(); err == nil {
			t.Errorf("%s: key accepted", name)
		}
		if _, err := e.MarshalBinary(); err == nil {
			t.Errorf("%s: record accepted", name)
		}
	}
}

func TestEffectRecordKeyOrderAndBoundaries(t *testing.T) {
	first := ActionID("act_" + strings.Repeat("0", 32))
	last := ActionID("act_" + strings.Repeat("f", 32))
	var previous []byte
	for _, nanos := range []int64{1, 255, 256, 1 << 32, math.MaxInt64} {
		for _, action := range []ActionID{first, last} {
			expires := time.Unix(0, nanos).UTC()
			key, err := EffectRecordKey(action, expires)
			if err != nil || len(key) != effectKeyLen {
				t.Fatalf("key at %d: %x, %v", nanos, key, err)
			}
			if binary.BigEndian.Uint64(key[:8]) != uint64(nanos) || string(key[8:]) != string(action) {
				t.Fatalf("key at %d lost its expiry or action: %x", nanos, key)
			}
			if previous != nil && bytes.Compare(previous, key) >= 0 {
				t.Fatalf("key order is not expiry then action: %x before %x", previous, key)
			}
			previous = key
		}
	}
	for _, expires := range []time.Time{
		{}, time.Unix(0, 0), time.Unix(0, -1),
		time.Unix(0, math.MaxInt64).Add(time.Nanosecond),
		time.Unix(0, 1).AddDate(600, 0, 0),
	} {
		if _, err := EffectRecordKey(first, expires); err == nil {
			t.Errorf("accepted invalid expiry %v", expires)
		}
	}
}

func TestEffectRecordRejectsResealedCorruption(t *testing.T) {
	e := testEffect(t, 1)
	key, rec, err := e.record()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*effectRecordRecord){
		"version":            func(r *effectRecordRecord) { r.V++ },
		"mapped target":      func(r *effectRecordRecord) { r.Target = "ip:::ffff:192.0.2.10" },
		"prefix target":      func(r *effectRecordRecord) { r.Target = "net:198.51.100.0/24" },
		"partition":          func(r *effectRecordRecord) { r.Partition = partitionEnd },
		"lane":               func(r *effectRecordRecord) { r.Lane = laneEnd },
		"general in reserve": func(r *effectRecordRecord) { r.Partition = PartitionReserved },
		"class":              func(r *effectRecordRecord) { r.Class = 0 },
		"severity":           func(r *effectRecordRecord) { r.Severity = 0 },
		"reserved evidence":  func(r *effectRecordRecord) { r.Direct = true },
		"scope":              func(r *effectRecordRecord) { r.Scope = "" },
		"negative applied":   func(r *effectRecordRecord) { r.Applied = -1 },
		"negative elapsed":   func(r *effectRecordRecord) { r.Applied, r.Elapsed = 1, -1 },
		"pending elapsed":    func(r *effectRecordRecord) { r.Elapsed = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := rec
			mutate(&bad)
			data, sealErr := sealRecord(bad)
			if sealErr != nil {
				t.Fatal(sealErr)
			}
			if _, decodeErr := UnmarshalEffectRecord(key, data); decodeErr != ErrCorruptRecord {
				t.Fatalf("accepted resealed corruption: %v", decodeErr)
			}
		})
	}
	data, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, expires := range []uint64{0, 1 << 63, math.MaxUint64} {
		bad := bytes.Clone(key)
		binary.BigEndian.PutUint64(bad[:8], expires)
		if _, err := UnmarshalEffectRecord(bad, data); err != ErrCorruptRecord {
			t.Errorf("accepted invalid key expiry %d: %v", expires, err)
		}
	}
}

func TestEffectRecordWidestFits(t *testing.T) {
	e := testEffect(t, MaxAttempts)
	e.Target, e.Partition, e.Lane = mustAddr(t, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), PartitionReserved, LaneCorroborated
	e.Tier, e.Corroborated = Tier{Class: ClassC3, Severity: SeverityCritical}, true
	e.Scope = strings.Repeat("s", 128)
	e.ExpiresAt = time.Unix(0, 1<<63-1).UTC()
	e.Applied, e.Elapsed = e.ExpiresAt, time.Duration(1<<63-1)
	data, err := e.MarshalBinary()
	if err != nil || len(data) > MaxEffectRecordBytes {
		t.Fatalf("widest effect: %d bytes, %v; bound %d", len(data), err, MaxEffectRecordBytes)
	}
}

func TestEffectTallyCountsPartitions(t *testing.T) {
	var tally EffectTally
	var err error
	for _, step := range []struct {
		p     Partition
		delta int
	}{{PartitionGeneral, 1}, {PartitionGeneral, 1}, {PartitionReserved, 1}, {PartitionGeneral, -1}} {
		if tally, err = tally.Add(step.p, step.delta); err != nil {
			t.Fatal(err)
		}
	}
	if tally != (EffectTally{General: 1, Reserved: 1}) {
		t.Fatalf("tally %+v", tally)
	}
	if got, occupyErr := tally.Occupy(SetOccupancy{Limit: 10, Unclaimed: 2, General: 3}); occupyErr != nil || got != (SetOccupancy{Limit: 10, Unclaimed: 2, General: 4, Reserved: 1}) {
		t.Fatalf("occupancy %+v, %v", got, occupyErr)
	}
	if _, err = tally.Add(PartitionReserved, -2); err == nil {
		t.Fatal("a tally below zero was accepted")
	}
	if _, err = tally.Add(0, 1); err == nil {
		t.Fatal("a tally without a partition was accepted")
	}
	data, err := tally.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalEffectTally(data)
	if err != nil || back != tally {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	data[len(data)-1] ^= 1
	if _, err = UnmarshalEffectTally(data); err != ErrCorruptRecord {
		t.Fatalf("flipped tally: %v", err)
	}
}

func TestEffectTallyAddRefusesUnchanged(t *testing.T) {
	for _, p := range []Partition{PartitionGeneral, PartitionReserved} {
		for _, tc := range []struct {
			name  string
			tally EffectTally
			delta int
		}{
			{"underflow", EffectTally{General: 1, Reserved: 1}, -2},
			{"minimum delta", EffectTally{General: 1, Reserved: 1}, math.MinInt},
			{"overflow", EffectTally{General: math.MaxInt, Reserved: math.MaxInt}, 1},
			{"damaged general", EffectTally{General: -1, Reserved: 1}, 1},
			{"damaged reserved", EffectTally{General: 1, Reserved: -1}, 1},
			{"wrapped underflow", EffectTally{General: -1, Reserved: -1}, math.MinInt},
		} {
			t.Run(p.String()+"/"+tc.name, func(t *testing.T) {
				got, err := tc.tally.Add(p, tc.delta)
				if err != ErrCorruptRecord || got != tc.tally {
					t.Fatalf("Add(%d) = %+v, %v; want unchanged %+v and corrupt record", tc.delta, got, err, tc.tally)
				}
			})
		}
	}
}

func TestEffectTallyOccupyDoesNotWrap(t *testing.T) {
	for _, tally := range []EffectTally{{General: math.MaxInt}, {Reserved: math.MaxInt}} {
		data, err := tally.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmarshalEffectTally(data)
		if err != nil {
			t.Fatal(err)
		}
		before := SetOccupancy{Limit: 10, General: 1, Reserved: 1}
		got, err := back.Occupy(before)
		if err != ErrCorruptRecord || got != before {
			t.Errorf("overflow = %+v, %v; want unchanged %+v and corrupt record", got, err, before)
		}
	}
}

func TestEffectTallyArithmeticBoundaries(t *testing.T) {
	for _, p := range []Partition{PartitionGeneral, PartitionReserved} {
		var tally EffectTally
		for _, delta := range []int{math.MaxInt, 0, -math.MaxInt} {
			var err error
			tally, err = tally.Add(p, delta)
			if err != nil {
				t.Fatal(err)
			}
			want := EffectTally{}
			if delta >= 0 {
				if p == PartitionGeneral {
					want.General = math.MaxInt
				} else {
					want.Reserved = math.MaxInt
				}
			}
			if tally != want {
				t.Fatalf("%s after delta %d: %+v, want %+v", p, delta, tally, want)
			}
		}
	}
	before := SetOccupancy{Limit: 10, Unclaimed: 2, General: 1, Reserved: 1}
	got, err := (EffectTally{General: math.MaxInt - 1, Reserved: math.MaxInt - 1}).Occupy(before)
	want := SetOccupancy{Limit: 10, Unclaimed: 2, General: math.MaxInt, Reserved: math.MaxInt}
	if err != nil || got != want {
		t.Fatalf("largest occupancy = %+v, %v; want %+v", got, err, want)
	}
	if slots := got.Slots(); slots.FreeGeneral != 0 || slots.FreeReserved != 0 {
		t.Fatalf("full partitions reported free slots: %+v", slots)
	}
	for _, tally := range []EffectTally{{General: -1}, {Reserved: -1}} {
		if got, err := tally.Occupy(before); err != ErrCorruptRecord || got != before {
			t.Fatalf("negative tally = %+v, %v; want unchanged %+v and corrupt record", got, err, before)
		}
	}
	for _, occ := range []SetOccupancy{{General: -1}, {Reserved: -1}} {
		if got, err := (EffectTally{General: 1, Reserved: 1}).Occupy(occ); err != ErrCorruptRecord || got != occ {
			t.Fatalf("negative occupancy = %+v, %v; want unchanged %+v and corrupt record", got, err, occ)
		}
	}
}

func TestGapNoticeFullSetOnceLive(t *testing.T) {
	high := Tier{Class: ClassC2, Severity: SeverityHigh}
	warning := Tier{Class: ClassC1, Severity: SeverityWarning}
	crit := Tier{Class: ClassC2, Severity: SeverityCritical}
	for _, tc := range []struct {
		name   string
		reason Reason
		tier   Tier
		live   bool
		want   NoticeKind
	}{
		{"live high work on a full set", ReasonSetFull, high, true, NoticeCapacity},
		{"live warning work on a full set", ReasonSetFull, warning, true, NoticeCapacity},
		{"live critical work on a full set", ReasonSetFull, crit, true, NoticeCapacity},
		{"previewed high work on a full set", ReasonSetFull, high, false, 0},
		{"previewed critical work on a full set", ReasonSetFull, crit, false, NoticeCapacity},
		{"live high work on the ceiling", ReasonCeiling, high, true, 0},
		{"live unassessed work on a full set", ReasonSetFull, Tier{}, true, 0},
	} {
		if got := GapNotice(GapDeferred, tc.reason, 0, tc.tier, tc.live); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := GapNotice(GapEnded, ReasonSetFull, 0, high, true); got != 0 {
		t.Errorf("a full set ends nothing: %v", got)
	}
}

func TestGapNoticeLiveOnlyBroadensFullSetDeferrals(t *testing.T) {
	for class := ClassC1; class <= ClassC3; class++ {
		for severity := SeverityWarning; severity <= SeverityCritical; severity++ {
			tier := Tier{Class: class, Severity: severity}
			for reason := ReasonCeiling; reason < reasonEnd; reason++ {
				for event := GapDeferred; event <= GapOutcome; event++ {
					for outcome := Disposition(0); outcome < dispositionEnd; outcome++ {
						preview := GapNotice(event, reason, outcome, tier, false)
						want := preview
						if event == GapDeferred && reason == ReasonSetFull {
							want = NoticeCapacity
							if severity != SeverityCritical && preview != 0 {
								t.Fatalf("preview raised a full-set notice for %v", tier)
							}
						}
						if got := GapNotice(event, reason, outcome, tier, true); got != want {
							t.Fatalf("live event %v, reason %v, outcome %v, tier %v: %v, want %v", event, reason, outcome, tier, got, want)
						}
					}
				}
			}
		}
	}
}

// An eviction is kept on both records: the pending block names the
// verified record it claimed, and the victim names the block that claimed
// it until that block's verified outcome marks it evicted. Records
// without either keep the version 1 encoding.
func TestEffectRecordCarriesItsEviction(t *testing.T) {
	victim := testEffect(t, 1)
	victim.Applied, victim.Elapsed = t0.Add(time.Minute), time.Minute
	plain, err := victim.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	member := testEffect(t, 2)
	member.Target, member.Tier = mustAddr(t, "192.0.2.20"), Tier{Class: ClassC2, Severity: SeverityCritical}
	member.Victim = EffectRef{Action: victim.Action, ExpiresAt: victim.ExpiresAt}
	claimed := victim
	claimed.EvictedBy = member.Action
	evicted := claimed
	evicted.Evicted = true
	for _, e := range []EffectRecord{member, claimed, evicted} {
		key, keyErr := e.Key()
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		data, encodeErr := e.MarshalBinary()
		if encodeErr != nil || !bytes.Contains(data, []byte(`"v":2`)) {
			t.Fatalf("%+v: %s %v", e, data, encodeErr)
		}
		back, decodeErr := UnmarshalEffectRecord(key, data)
		if decodeErr != nil || back != e {
			t.Fatalf("round trip %+v: %+v %v", e, back, decodeErr)
		}
	}
	if !bytes.Contains(plain, []byte(`"v":1`)) {
		t.Fatalf("a record without an eviction changed its encoding: %s", plain)
	}
	ref, err := member.Victim.Key()
	if want, _ := victim.Key(); err != nil || !bytes.Equal(ref, want) {
		t.Fatalf("victim reference key %x %v, want %x", ref, err, want)
	}
	if claimed.Holds() != true || evicted.Holds() != false || member.Holds() != true {
		t.Fatal("only an evicted record gives up its slot")
	}
}

func TestEffectRecordRefusesImpossibleEvictions(t *testing.T) {
	other := testActionID(t, 9)
	for name, mutate := range map[string]func(*EffectRecord){
		"verified block names a victim": func(e *EffectRecord) {
			e.Applied = t0
			e.Victim = EffectRef{Action: other, ExpiresAt: t0}
		},
		"victim names itself":      func(e *EffectRecord) { e.Victim = EffectRef{Action: e.Action, ExpiresAt: t0} },
		"victim has no expiry":     func(e *EffectRecord) { e.Victim = EffectRef{Action: other} },
		"victim has no action":     func(e *EffectRecord) { e.Victim = EffectRef{ExpiresAt: t0} },
		"pending block is evicted": func(e *EffectRecord) { e.EvictedBy = other },
		"evicted by itself": func(e *EffectRecord) {
			e.Applied, e.EvictedBy = t0, e.Action
		},
		"evicted by nothing": func(e *EffectRecord) {
			e.Applied, e.Evicted = t0, true
		},
		"malformed evictor": func(e *EffectRecord) { e.Applied, e.EvictedBy = t0, "act_x" },
	} {
		e := testEffect(t, 1)
		mutate(&e)
		_, err := e.MarshalBinary()
		wantReason(t, name, err, ReasonInvalid)
	}
	plain := testEffect(t, 1)
	claimed := plain
	claimed.Applied, claimed.EvictedBy = t0, other
	for name, e := range map[string]EffectRecord{"version 2 without an eviction": plain, "version 1 with an eviction": claimed} {
		key, rec, err := e.record()
		if err != nil {
			t.Fatal(err)
		}
		rec.V = 3 - rec.V
		data, err := sealRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = UnmarshalEffectRecord(key, data); err != ErrCorruptRecord {
			t.Errorf("%s decoded: %v", name, err)
		}
	}
}

func TestEffectRecordWidestEvictionFits(t *testing.T) {
	far := time.Unix(0, 1<<63-1).UTC()
	member := testEffect(t, MaxAttempts)
	member.Target, member.Partition, member.Lane = mustAddr(t, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), PartitionGeneral, LaneCorroborated
	member.Tier, member.Corroborated = Tier{Class: ClassC3, Severity: SeverityCritical}, true
	member.Scope, member.ExpiresAt = strings.Repeat("s", 128), far
	member.Victim = EffectRef{Action: testActionID(t, 9), ExpiresAt: far}
	evicted := member
	evicted.Victim = EffectRef{}
	evicted.Applied, evicted.Elapsed = far, time.Duration(1<<63-1)
	evicted.EvictedBy, evicted.Evicted = testActionID(t, 9), true
	inv, err := NewInventory(map[string]uint64{strings.Repeat("a", 64): ^uint64(0)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	canonical := Scope{Owner: inv.Resolve(Claim{Kind: ClaimAccount, Value: strings.Repeat("a", 64)}), Effect: EffectAddress}.Key()
	for _, e := range []EffectRecord{member, evicted} {
		for _, scope := range []string{strings.Repeat("s", 128), canonical} {
			e.Scope = scope
			data, err := e.MarshalBinary()
			// A documentation IPv6 address is one byte shorter than the
			// maximum canonical address. Reserve that byte as well.
			if err != nil || len(data)+1 > 512 || MaxEffectRecordBytes != 512 {
				t.Fatalf("widest effect: %d bytes, %v; bound %d", len(data), err, MaxEffectRecordBytes)
			}
			key, err := e.Key()
			if err != nil {
				t.Fatal(err)
			}
			back, err := UnmarshalEffectRecord(key, data)
			if err != nil || back != e {
				t.Fatalf("widest round trip: %+v %v", back, err)
			}
		}
	}
}
