package admission

import (
	"bytes"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestOutcomeKeysAreFixedDimensional(t *testing.T) {
	crit := Tier{Class: ClassC3, Severity: SeverityCritical}
	for _, k := range []OutcomeKey{
		QueueOutcome(EventDeferred, ReasonCeiling, crit),
		QueueOutcome(EventRefused, ReasonInvalid, Tier{}),
		AttemptOutcome(DispositionApplied, crit),
		AttemptOutcome(DispositionUnknown, Tier{}),
	} {
		if !k.Valid() {
			t.Errorf("%+v refused", k)
		}
	}
	for name, k := range map[string]OutcomeKey{
		"event without a reason":       {Event: EventEnded},
		"event with an outcome":        {Event: EventEnded, Reason: ReasonStale, Outcome: DispositionApplied},
		"outcome with a reason":        {Reason: ReasonStale, Outcome: DispositionFailed},
		"a preview is no outcome":      {Outcome: DispositionDryRun},
		"a queue ending is no outcome": {Outcome: DispositionDropped},
		"half a tier":                  {Outcome: DispositionApplied, Class: ClassC1},
		"nothing":                      {},
	} {
		if k.Valid() {
			t.Errorf("%s: %+v accepted", name, k)
		}
	}
}

func TestOutcomeCountsAddMergeAndRoundTrip(t *testing.T) {
	a := QueueOutcome(EventEnded, ReasonStale, Tier{Class: ClassC2, Severity: SeverityHigh})
	b := AttemptOutcome(DispositionApplied, Tier{})
	var c OutcomeCounts
	for i := 0; i < 3; i++ {
		if err := c.Add(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Add(b); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(OutcomeKey{}); err == nil {
		t.Fatal("an invalid key was counted")
	}
	if c.Count(a) != 3 || c.Count(b) != 1 {
		t.Fatalf("counts %d %d", c.Count(a), c.Count(b))
	}
	var sum OutcomeCounts
	sum.Merge(c)
	sum.Merge(c)
	if sum.Count(a) != 6 || c.Count(a) != 3 {
		t.Fatal("merge did not add into a copy")
	}
	rows := sum.Rows()
	if len(rows) != 2 || rows[0].Key != b || rows[1].Key != a || rows[1].N != 6 {
		t.Fatalf("rows %+v", rows)
	}
	sat := OutcomeCounts{}
	sat.counts = map[OutcomeKey]uint64{a: math.MaxUint64}
	_ = sat.Add(a)
	sum.Merge(sat)
	if sat.Count(a) != math.MaxUint64 || sum.Count(a) != math.MaxUint64 {
		t.Fatal("a count wrapped")
	}
	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalOutcomeCounts(data)
	if err != nil || !reflect.DeepEqual(back.Rows(), c.Rows()) {
		t.Fatalf("round trip = %+v, %v", back.Rows(), err)
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"zero count":    resealForTest(bytes.Replace(body, []byte(`"n":3`), []byte(`"n":0`), 1)),
		"invalid key":   resealForTest(bytes.Replace(body, []byte(`"r":17`), []byte(`"r":0`), 1)),
		"unsorted rows": resealForTest(swapRows(t, body)),
		"no rows":       resealForTest([]byte(`{"v":1}`)),
	} {
		if _, err := UnmarshalOutcomeCounts(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

// swapRows reverses a two-row record's rows.
func swapRows(t *testing.T, body []byte) []byte {
	t.Helper()
	i := bytes.Index(body, []byte(`[`))
	j := bytes.Index(body, []byte(`},{`))
	k := bytes.LastIndex(body, []byte(`]`))
	if i < 0 || j < 0 || k < 0 {
		t.Fatalf("unexpected record %s", body)
	}
	out := append([]byte(nil), body[:i+1]...)
	out = append(out, body[j+2:k]...)
	out = append(out, ',')
	out = append(out, body[i+1:j+1]...)
	return append(out, body[k:]...)
}

// The windows are ledger state with a fixed worst case: every key of the
// fixed key space in every bucket.
func TestOutcomeCountsFitTheirBound(t *testing.T) {
	var c OutcomeCounts
	tiers := []Tier{{}}
	for class := ClassC1; class <= ClassC3; class++ {
		for sev := SeverityWarning; sev <= SeverityCritical; sev++ {
			tiers = append(tiers, Tier{Class: class, Severity: sev})
		}
	}
	for _, tier := range tiers {
		for e := EventRefused; e < queueEventEnd; e++ {
			for r := ReasonCeiling; r < reasonEnd; r++ {
				c.counts = mapWith(c.counts, QueueOutcome(e, r, tier))
			}
		}
		for _, d := range []Disposition{DispositionApplied, DispositionNarrowed, DispositionFailed, DispositionUnknown} {
			c.counts = mapWith(c.counts, AttemptOutcome(d, tier))
		}
	}
	if len(c.counts) != MaxOutcomeKeys {
		t.Fatalf("key space %d, want %d", len(c.counts), MaxOutcomeKeys)
	}
	data, err := c.MarshalBinary()
	if err != nil || len(data) > MaxOutcomeBucketBytes {
		t.Fatalf("full bucket: %d bytes (bound %d), %v", len(data), MaxOutcomeBucketBytes, err)
	}
}

func mapWith(m map[OutcomeKey]uint64, k OutcomeKey) map[OutcomeKey]uint64 {
	if m == nil {
		m = map[OutcomeKey]uint64{}
	}
	m[k] = math.MaxUint64
	return m
}

func TestOutcomeWindowsAlignAndExpire(t *testing.T) {
	at := time.Date(2026, 9, 28, 13, 47, 31, 5, time.UTC)
	for _, tc := range []struct {
		span    Span
		width   time.Duration
		buckets int
		start   time.Time
	}{
		{SpanFiveMinutes, 5 * time.Minute, 12, time.Date(2026, 9, 28, 13, 45, 0, 0, time.UTC)},
		{SpanHour, time.Hour, 24, time.Date(2026, 9, 28, 13, 0, 0, 0, time.UTC)},
		{SpanDay, 24 * time.Hour, 30, time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)},
	} {
		if tc.span.Width() != tc.width || tc.span.Buckets() != tc.buckets {
			t.Fatalf("%v: %v x %d", tc.span, tc.span.Width(), tc.span.Buckets())
		}
		start := tc.span.Start(at)
		if !start.Equal(tc.start) {
			t.Fatalf("%v start %v, want %v", tc.span, start, tc.start)
		}
		oldest := tc.span.Oldest(at)
		if !oldest.Equal(start.Add(-time.Duration(tc.buckets-1) * tc.width)) {
			t.Fatalf("%v oldest %v", tc.span, oldest)
		}
		k := tc.span.Key(start)
		span, back, err := ParseSpanKey(k)
		if err != nil || span != tc.span || !back.Equal(start) {
			t.Fatalf("%v key %q parsed %v %v %v", tc.span, k, span, back, err)
		}
		if bytes.Compare(tc.span.Key(oldest), k) >= 0 {
			t.Fatalf("%v keys do not order by time", tc.span)
		}
	}
	if len(Spans()) != 3 {
		t.Fatal("spans")
	}
	for _, bad := range [][]byte{nil, []byte("w1"), []byte("w\x091790000000000000000"), []byte("w\x021790000000000000001"), []byte("w\x020000000000000000000"), []byte("w\x02+790000000000000000")} {
		if _, _, err := ParseSpanKey(bad); err == nil {
			t.Errorf("malformed key %q parsed", bad)
		}
	}
}

func TestOutcomeCountsAddCounts(t *testing.T) {
	k := QueueOutcome(EventRefused, ReasonQueueOverflow, Tier{})
	var c OutcomeCounts
	if err := c.AddCount(k, 0); err != nil || len(c.Rows()) != 0 {
		t.Fatalf("adding none stored a row: %+v, %v", c.Rows(), err)
	}
	if err := c.AddCount(k, 5); err != nil || c.Count(k) != 5 {
		t.Fatalf("count %d, %v", c.Count(k), err)
	}
	if err := c.AddCount(k, math.MaxUint64); err != nil || c.Count(k) != math.MaxUint64 {
		t.Fatal("a count wrapped")
	}
	if err := c.AddCount(OutcomeKey{}, 1); err == nil {
		t.Fatal("an invalid key was counted")
	}
}
