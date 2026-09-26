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
