package admission

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestQueueEntryRoundTripsAndInvariants(t *testing.T) {
	later := t0.Add(time.Hour)
	for name, q := range map[string]QueueEntry{
		"unassessed":   {Partition: PartitionGeneral},
		"general":      {Partition: PartitionGeneral, Tier: c2h, NextChange: later},
		"eligible":     {Partition: PartitionGeneral, Tier: c3c, Corroborated: true, NextChange: later},
		"direct":       {Partition: PartitionReserved, Tier: c3c, Direct: true, NextChange: later},
		"corroborated": {Partition: PartitionReserved, Tier: Tier{ClassC3, SeverityWarning}, Corroborated: true, NextChange: later},
	} {
		data, err := q.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if back, err := UnmarshalQueueEntry(data); err != nil || back != q {
			t.Fatalf("%s: round trip = %+v, %v", name, back, err)
		}
	}
	for name, q := range map[string]QueueEntry{
		"no partition":            {Tier: c2h, NextChange: later},
		"unassessed with a lane":  {Partition: PartitionGeneral, Direct: true},
		"unassessed with a time":  {Partition: PartitionGeneral, NextChange: later},
		"unassessed reserved":     {Partition: PartitionReserved},
		"invalid tier":            {Partition: PartitionGeneral, Tier: Tier{Class: ClassC2}, NextChange: later},
		"both lanes":              {Partition: PartitionReserved, Tier: c3c, Direct: true, Corroborated: true, NextChange: later},
		"eligible below C3":       {Partition: PartitionGeneral, Tier: c2h, Corroborated: true, NextChange: later},
		"ineligible reserved":     {Partition: PartitionReserved, Tier: c3c, NextChange: later},
		"assessed without a time": {Partition: PartitionGeneral, Tier: c2h},
	} {
		if _, err := q.MarshalBinary(); err == nil {
			t.Errorf("%s: encoded", name)
		}
		wantReason(t, name, q.Validate(), ReasonInvalid)
	}
	data, _ := QueueEntry{Partition: PartitionReserved, Tier: c3c, Direct: true, NextChange: later}.MarshalBinary()
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":        func() []byte { d := bytes.Clone(data); d[3] ^= 1; return d }(),
		"future version":      resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
		"unknown field":       resealForTest(bytes.Replace(body, []byte(`{"v":1`), []byte(`{"x":1,"v":1`), 1)),
		"reserved ineligible": resealForTest(bytes.Replace(body, []byte(`,"direct":true`), nil, 1)),
		"explicit false":      resealForTest(bytes.Replace(body, []byte(`"direct":true`), []byte(`"direct":true,"corroborated":false`), 1)),
	} {
		if _, err := UnmarshalQueueEntry(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

func TestQueueStateRoundTrips(t *testing.T) {
	for name, s := range map[string]QueueState{
		"empty": {},
		"full":  {NextSweep: t0, Cursors: QueueCursors{General: "acct:alice#1/address", Reserved: "host/address"}},
	} {
		data, err := s.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if back, err := UnmarshalQueueState(data); err != nil || back != s {
			t.Fatalf("%s: round trip = %+v, %v", name, back, err)
		}
	}
	if _, err := (QueueState{Cursors: QueueCursors{General: "a b"}}).MarshalBinary(); err == nil {
		t.Fatal("malformed cursor encoded")
	}
	data, _ := QueueState{NextSweep: t0}.MarshalBinary()
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":   func() []byte { d := bytes.Clone(data); d[3] ^= 1; return d }(),
		"future version": resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
		"spaced cursor":  resealForTest(bytes.Replace(body, []byte(`}`), []byte(`,"general":"a b"}`), 1)),
		"empty cursor":   resealForTest(bytes.Replace(body, []byte(`}`), []byte(`,"general":""}`), 1)),
	} {
		if _, err := UnmarshalQueueState(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

func TestQueueCountersCountAndRoundTrip(t *testing.T) {
	var q QueueCounters
	dropped := CountKey{Event: EventEnded, Reason: ReasonQueueOverflow, Class: ClassC2, Severity: SeverityHigh}
	refused := CountKey{Event: EventRefused, Reason: ReasonStale}
	for _, k := range []CountKey{dropped, dropped, refused} {
		if err := q.Add(k); err != nil {
			t.Fatal(err)
		}
	}
	if q.Count(dropped) != 2 || q.Count(refused) != 1 || q.Count(CountKey{Event: EventDeferred, Reason: ReasonCeiling}) != 0 {
		t.Fatalf("counts = %+v", q.counts)
	}
	for name, k := range map[string]CountKey{
		"no event":           {Reason: ReasonStale},
		"no reason":          {Event: EventEnded},
		"class alone":        {Event: EventEnded, Reason: ReasonStale, Class: ClassC2},
		"severity alone":     {Event: EventEnded, Reason: ReasonStale, Severity: SeverityHigh},
		"unknown event":      {Event: queueEventEnd, Reason: ReasonStale},
		"out of range class": {Event: EventEnded, Reason: ReasonStale, Class: 4, Severity: SeverityHigh},
	} {
		wantReason(t, name, q.Add(k), ReasonInvalid)
	}
	full := QueueCounters{counts: map[CountKey]uint64{dropped: ^uint64(0)}}
	if err := full.Add(dropped); err != nil || full.Count(dropped) != ^uint64(0) {
		t.Fatal("counter wrapped")
	}
	data, err := q.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := UnmarshalQueueCounters(data); err != nil || !reflect.DeepEqual(back, q) {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	var empty QueueCounters
	if data, err := empty.MarshalBinary(); err != nil {
		t.Fatal(err)
	} else if back, err := UnmarshalQueueCounters(data); err != nil || back.Count(dropped) != 0 {
		t.Fatalf("empty round trip: %v", err)
	}
	for name, raw := range map[string]string{
		"null rows":     `{"v":1,"rows":null}`,
		"zero count":    `{"v":1,"rows":[{"e":3,"r":16,"c":2,"s":2,"n":0}]}`,
		"unsorted":      `{"v":1,"rows":[{"e":3,"r":16,"c":2,"s":2,"n":1},{"e":1,"r":17,"n":1}]}`,
		"repeated":      `{"v":1,"rows":[{"e":1,"r":17,"n":1},{"e":1,"r":17,"n":1}]}`,
		"half assessed": `{"v":1,"rows":[{"e":1,"r":17,"c":2,"n":1}]}`,
		"future":        `{"v":2,"rows":[]}`,
	} {
		if _, err := UnmarshalQueueCounters(resealForTest([]byte(raw))); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

func TestIngressStateRoundTrips(t *testing.T) {
	for name, s := range map[string]IngressState{
		"fresh":        {},
		"open":         {Generation: 3, Open: true, Persisted: 12, Interrupted: 2},
		"closed":       {Generation: 1},
		"interrupted":  {Generation: 2, Interrupted: 1},
		"resumed":      {Generation: 3, Open: true, Interrupted: 1, Resumed: 3},
		"resumed once": {Generation: 4, Interrupted: 1, Resumed: 2},
	} {
		data, err := s.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if back, err := UnmarshalIngressState(data); err != nil || back != s {
			t.Fatalf("%s: round trip = %+v, %v", name, back, err)
		}
	}
	for name, s := range map[string]IngressState{
		"open before the first":      {Open: true},
		"persisted before the first": {Persisted: 1},
		"current one interrupted":    {Generation: 2, Interrupted: 2},
		"resumed later":              {Generation: 2, Interrupted: 1, Resumed: 3},
		"resumed without a loss":     {Generation: 2, Resumed: 2},
		"resumed the first":          {Generation: 2, Interrupted: 1, Resumed: 1},
	} {
		if _, err := s.MarshalBinary(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	data, _ := IngressState{Generation: 2, Open: true}.MarshalBinary()
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":   func() []byte { d := bytes.Clone(data); d[3] ^= 1; return d }(),
		"future version": resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
		"interrupted":    resealForTest(bytes.Replace(body, []byte(`}`), []byte(`,"interrupted":5}`), 1)),
	} {
		if _, err := UnmarshalIngressState(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

func TestIngressCheckpointCodec(t *testing.T) {
	var counts QueueCounters
	_ = counts.Add(CountKey{Event: EventRefused, Reason: ReasonQueueOverflow, Class: ClassC2, Severity: SeverityHigh})
	raw, err := counts.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	cp := IngressCheckpoint{Generation: 1, Sequence: 2, Cursors: QueueCursors{General: "host/address"}, Counters: raw}
	state := IngressState{Generation: 1, Open: true, Checkpoint: &cp}
	data, err := state.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalIngressState(data)
	if err != nil || !reflect.DeepEqual(back, state) {
		t.Fatalf("checkpoint round trip = %+v %v", back, err)
	}
	for _, change := range []func(*IngressCheckpoint){
		func(c *IngressCheckpoint) { c.Generation = 0 },
		func(c *IngressCheckpoint) { c.Generation = 2 },
		func(c *IngressCheckpoint) { c.Cursors.General = "bad cursor" },
		func(c *IngressCheckpoint) { c.Counters = []byte("damaged") },
	} {
		bad := cp
		change(&bad)
		state.Checkpoint = &bad
		if _, err = state.MarshalBinary(); err == nil {
			t.Fatal("invalid checkpoint encoded")
		}
	}
	bad := cp
	bad.Sequence++
	bad.Counters, _ = (QueueCounters{}).MarshalBinary()
	if err = bad.Validate(&cp, 1); err != ErrTransitionConflict {
		t.Fatal("counter regression accepted")
	}
	bad = cp
	bad.Cursors.General = "acct:alice#1/address"
	if err = bad.Validate(&cp, 1); err != ErrTransitionConflict {
		t.Fatal("same sequence changed decision")
	}
}

func TestQueueCountersRows(t *testing.T) {
	var q QueueCounters
	var want []QueueCount
	for _, e := range []QueueEvent{EventRefused, EventDeferred, EventEnded} {
		for _, r := range []Reason{ReasonCeiling, ReasonStale} {
			want = append(want, QueueCount{Key: CountKey{Event: e, Reason: r, Class: ClassC2, Severity: SeverityHigh}, N: uint64(len(want) + 1)})
		}
	}
	// Counted in reverse, so neither insertion order nor a rotation of it
	// is the key order.
	for i := len(want) - 1; i >= 0; i-- {
		for n := uint64(0); n < want[i].N; n++ {
			if err := q.Add(want[i].Key); err != nil {
				t.Fatal(err)
			}
		}
	}
	if rows := q.Rows(); !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %+v\nwant %+v", rows, want)
	}
}
