package admission

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"
)

// A gone record holds no slot and keeps everything else it recorded; its
// encoding is its own version, so an older build cannot read the field as
// absent.
func TestEffectRecordGoneHoldsNoSlot(t *testing.T) {
	verified := testEffect(t, 1)
	verified.Applied, verified.Elapsed = t0.Add(time.Minute), time.Hour
	gone := verified
	gone.Gone = t0.Add(time.Hour)
	evicted := verified
	evicted.EvictedBy, evicted.Evicted, evicted.Gone = testActionID(t, 9), true, t0.Add(2*time.Hour)
	if !verified.Holds() || gone.Holds() || evicted.Holds() {
		t.Fatal("a verified record holds its slot until it is evicted or gone")
	}
	for _, e := range []EffectRecord{gone, evicted} {
		key, err := e.Key()
		if err != nil {
			t.Fatal(err)
		}
		data, err := e.MarshalBinary()
		if err != nil || !bytes.Contains(data, []byte(`"v":3`)) || !bytes.Contains(data, []byte(`"gone":`)) {
			t.Fatalf("%+v: %s %v", e, data, err)
		}
		back, err := UnmarshalEffectRecord(key, data)
		if err != nil || back != e {
			t.Fatalf("round trip %+v: %+v %v", e, back, err)
		}
	}
	if data, err := verified.MarshalBinary(); err != nil || bytes.Contains(data, []byte(`"gone"`)) || !bytes.Contains(data, []byte(`"v":1`)) {
		t.Fatalf("a record that is not gone changed its encoding: %s %v", data, err)
	}
}

// Only a verified block can be gone, at a representable time after the
// epoch, and a victim a pending block claimed stays until that block's
// outcome decides it.
func TestEffectRecordRefusesImpossibleGone(t *testing.T) {
	other := testActionID(t, 9)
	for name, mutate := range map[string]func(*EffectRecord){
		"a pending block":       func(e *EffectRecord) { e.Applied, e.Gone = time.Time{}, t0 },
		"a claimed victim":      func(e *EffectRecord) { e.EvictedBy, e.Gone = other, t0 },
		"gone at the epoch":     func(e *EffectRecord) { e.Gone = time.Unix(0, 0) },
		"gone before the epoch": func(e *EffectRecord) { e.Gone = time.Unix(-1, 0) },
		"gone past the range":   func(e *EffectRecord) { e.Gone = time.Unix(0, math.MaxInt64).Add(time.Nanosecond) },
	} {
		e := testEffect(t, 1)
		e.Applied = t0
		mutate(&e)
		_, err := e.MarshalBinary()
		wantReason(t, name, err, ReasonInvalid)
	}
	e := testEffect(t, 1)
	e.Applied, e.Gone = t0, t0.Add(time.Hour)
	key, rec, err := e.record()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*effectRecordRecord){
		"version 1":        func(r *effectRecordRecord) { r.V = effectRecordVersion },
		"version 2":        func(r *effectRecordRecord) { r.V = evictionRecordVersion },
		"negative gone":    func(r *effectRecordRecord) { r.Gone = -1 },
		"gone unapplied":   func(r *effectRecordRecord) { r.Applied, r.Elapsed = 0, 0 },
		"gone and claimed": func(r *effectRecordRecord) { r.EvictedBy = other },
	} {
		bad := rec
		mutate(&bad)
		data, sealErr := sealRecord(bad)
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		if _, decodeErr := UnmarshalEffectRecord(key, data); decodeErr != ErrCorruptRecord {
			t.Errorf("%s decoded: %v", name, decodeErr)
		}
	}
}

// The widest gone record, an evicted one with every field at its bound,
// still fits the record bound.
func TestEffectRecordWidestGoneFits(t *testing.T) {
	far := time.Unix(0, 1<<63-1).UTC()
	e := testEffect(t, MaxAttempts)
	e.Target, e.Partition, e.Lane = mustAddr(t, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), PartitionGeneral, LaneCorroborated
	e.Tier, e.Corroborated = Tier{Class: ClassC3, Severity: SeverityCritical}, true
	e.Scope, e.ExpiresAt = strings.Repeat("s", 128), far
	e.Applied, e.Elapsed = far, time.Duration(1<<63-1)
	e.EvictedBy, e.Evicted, e.Gone = testActionID(t, 9), true, far
	inv, err := NewInventory(map[string]uint64{strings.Repeat("a", 64): ^uint64(0)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	canonical := Scope{Owner: inv.Resolve(Claim{Kind: ClaimAccount, Value: strings.Repeat("a", 64)}), Effect: EffectAddress}.Key()
	for _, scope := range []string{strings.Repeat("s", 128), canonical} {
		e.Scope = scope
		data, err := e.MarshalBinary()
		// A documentation IPv6 address is one byte shorter than the widest
		// canonical address; reserve that byte too.
		if err != nil || len(data)+1 > MaxEffectRecordBytes {
			t.Fatalf("widest gone effect: %d bytes, %v; bound %d", len(data), err, MaxEffectRecordBytes)
		}
	}
}
