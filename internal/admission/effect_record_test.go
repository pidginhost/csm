package admission

import (
	"bytes"
	"encoding/binary"
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
		"an expiry before the epoch":   func(e *EffectRecord) { e.ExpiresAt = time.Unix(-1, 0) },
		"an application before epoch":  func(e *EffectRecord) { e.Applied = time.Unix(-1, 0) },
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
	if got := tally.Occupy(SetOccupancy{Limit: 10, Unclaimed: 2, General: 3}); got != (SetOccupancy{Limit: 10, Unclaimed: 2, General: 4, Reserved: 1}) {
		t.Fatalf("occupancy %+v", got)
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
