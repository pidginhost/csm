package admission

import (
	"fmt"
	"sort"
	"strconv"
	"time"
)

// OutcomeKey is one fixed dimension of the windowed outcome counts (spec
// 5.17, ruling 13): a queue event with its reason, or an attempt outcome,
// by the candidate's last assessment. It never names an address, account
// or check.
type OutcomeKey struct {
	Event    QueueEvent
	Reason   Reason
	Outcome  Disposition
	Class    Class
	Severity Severity
}

// QueueOutcome is the key of a queue event.
func QueueOutcome(e QueueEvent, r Reason, t Tier) OutcomeKey {
	return OutcomeKey{Event: e, Reason: r, Class: t.Class, Severity: t.Severity}
}

// AttemptOutcome is the key of an attempt outcome.
func AttemptOutcome(d Disposition, t Tier) OutcomeKey {
	return OutcomeKey{Outcome: d, Class: t.Class, Severity: t.Severity}
}

// Valid reports whether k is a queue event with a reason, or an attempt
// outcome, with a whole tier or none.
func (k OutcomeKey) Valid() bool {
	unassessed := k.Class == 0 && k.Severity == 0
	if !unassessed && (!k.Class.Valid() || !k.Severity.Valid()) {
		return false
	}
	if k.Event != 0 {
		return k.Event.Valid() && k.Reason.Valid() && k.Outcome == 0
	}
	switch k.Outcome {
	case DispositionApplied, DispositionNarrowed, DispositionFailed, DispositionUnknown:
		return k.Reason == 0
	}
	return false
}

func (k OutcomeKey) less(o OutcomeKey) bool {
	switch {
	case k.Event != o.Event:
		return k.Event < o.Event
	case k.Reason != o.Reason:
		return k.Reason < o.Reason
	case k.Outcome != o.Outcome:
		return k.Outcome < o.Outcome
	case k.Class != o.Class:
		return k.Class < o.Class
	}
	return k.Severity < o.Severity
}

// MaxOutcomeKeys is the size of the key space: every queue event with
// every reason and the four attempt outcomes, unassessed or at each tier.
const MaxOutcomeKeys = (int(queueEventEnd-EventRefused)*int(reasonEnd-ReasonCeiling) + 4) * (1 + 3*3)

// MaxOutcomeBucketBytes bounds one encoded bucket: every key at its
// largest count.
const MaxOutcomeBucketBytes = 29 << 10

// OutcomeCounts are saturating counts by OutcomeKey. The zero value is
// empty and ready to use.
type OutcomeCounts struct {
	counts map[OutcomeKey]uint64
}

// OutcomeRow is one count.
type OutcomeRow struct {
	Key OutcomeKey
	N   uint64
}

// Add counts one event.
func (c *OutcomeCounts) Add(k OutcomeKey) error {
	if !k.Valid() {
		return refuse(ReasonInvalid, "outcome key is invalid")
	}
	if c.counts == nil {
		c.counts = map[OutcomeKey]uint64{}
	}
	if c.counts[k] != ^uint64(0) {
		c.counts[k]++
	}
	return nil
}

// Count returns the count for k.
func (c OutcomeCounts) Count(k OutcomeKey) uint64 { return c.counts[k] }

// Merge adds o's counts, saturating.
func (c *OutcomeCounts) Merge(o OutcomeCounts) {
	for k, n := range o.counts {
		if c.counts == nil {
			c.counts = map[OutcomeKey]uint64{}
		}
		c.counts[k] += min(n, ^uint64(0)-c.counts[k])
	}
}

// Rows are the counts in key order.
func (c OutcomeCounts) Rows() []OutcomeRow {
	rows := make([]OutcomeRow, 0, len(c.counts))
	for k, n := range c.counts {
		rows = append(rows, OutcomeRow{k, n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key.less(rows[j].Key) })
	return rows
}

const outcomeCountsVersion = 1

type outcomeRowRecord struct {
	Event    QueueEvent  `json:"e,omitempty"`
	Reason   Reason      `json:"r,omitempty"`
	Outcome  Disposition `json:"o,omitempty"`
	Class    Class       `json:"c,omitempty"`
	Severity Severity    `json:"s,omitempty"`
	N        uint64      `json:"n"`
}

type outcomeCountsRecord struct {
	V    uint8              `json:"v"`
	Rows []outcomeRowRecord `json:"rows"`
}

func (c OutcomeCounts) MarshalBinary() ([]byte, error) {
	rows := c.Rows()
	rec := outcomeCountsRecord{V: outcomeCountsVersion, Rows: make([]outcomeRowRecord, 0, len(rows))}
	for _, r := range rows {
		if !r.Key.Valid() || r.N == 0 {
			return nil, refuse(ReasonInvalid, "outcome count is invalid")
		}
		k := r.Key
		rec.Rows = append(rec.Rows, outcomeRowRecord{Event: k.Event, Reason: k.Reason, Outcome: k.Outcome, Class: k.Class, Severity: k.Severity, N: r.N})
	}
	return sealRecord(rec)
}

// UnmarshalOutcomeCounts decodes a stored bucket.
func UnmarshalOutcomeCounts(data []byte) (OutcomeCounts, error) {
	var rec outcomeCountsRecord
	if err := openRecord(data, &rec); err != nil {
		return OutcomeCounts{}, err
	}
	if rec.V != outcomeCountsVersion || rec.Rows == nil {
		return OutcomeCounts{}, ErrCorruptRecord
	}
	c := OutcomeCounts{counts: make(map[OutcomeKey]uint64, len(rec.Rows))}
	var prev OutcomeKey
	for i, r := range rec.Rows {
		k := OutcomeKey{Event: r.Event, Reason: r.Reason, Outcome: r.Outcome, Class: r.Class, Severity: r.Severity}
		if !k.Valid() || r.N == 0 || (i > 0 && !prev.less(k)) {
			return OutcomeCounts{}, ErrCorruptRecord
		}
		c.counts[k], prev = r.N, k
	}
	return c, nil
}

// Span is one resolution of the outcome windows.
type Span uint8

const (
	// SpanFiveMinutes: twelve buckets, the last hour.
	SpanFiveMinutes Span = iota + 1
	// SpanHour: 24 buckets, the last day.
	SpanHour
	// SpanDay: 30 buckets, the last 30 days.
	SpanDay
	spanEnd
)

// Spans lists every resolution.
func Spans() []Span { return []Span{SpanFiveMinutes, SpanHour, SpanDay} }

func (s Span) Valid() bool { return s >= SpanFiveMinutes && s < spanEnd }

func (s Span) String() string {
	switch s {
	case SpanFiveMinutes:
		return "5m"
	case SpanHour:
		return "1h"
	case SpanDay:
		return "1d"
	}
	return fmt.Sprintf("span(%d)", uint8(s))
}

// Width is one bucket's length.
func (s Span) Width() time.Duration {
	switch s {
	case SpanFiveMinutes:
		return 5 * time.Minute
	case SpanHour:
		return time.Hour
	}
	return 24 * time.Hour
}

// Buckets is how many buckets the span keeps.
func (s Span) Buckets() int {
	switch s {
	case SpanFiveMinutes:
		return 12
	case SpanHour:
		return 24
	}
	return 30
}

// Start is the start of the bucket holding at, aligned to the Unix epoch.
func (s Span) Start(at time.Time) time.Time { return at.UTC().Truncate(s.Width()) }

// Oldest is the start of the oldest bucket kept at time now.
func (s Span) Oldest(now time.Time) time.Time {
	return s.Start(now).Add(-time.Duration(s.Buckets()-1) * s.Width())
}

// windowKind is the key kind of outcome buckets.
const windowKind = 'w'

// Key is the stored key of the bucket starting at start: the span and the
// start as 19 decimal digits of nanoseconds, so a span's buckets sort by
// time, as history retirement keys do.
func (s Span) Key(start time.Time) []byte {
	return fmt.Appendf([]byte{windowKind, byte(s)}, "%019d", start.UnixNano())
}

// ParseSpanKey decodes a bucket key and checks its alignment.
func ParseSpanKey(k []byte) (Span, time.Time, error) {
	if len(k) != 21 || k[0] != windowKind || !Span(k[1]).Valid() {
		return 0, time.Time{}, ErrCorruptRecord
	}
	s := Span(k[1])
	n, err := strconv.ParseInt(string(k[2:]), 10, 64)
	if err != nil || n <= 0 || fmt.Sprintf("%019d", n) != string(k[2:]) {
		return 0, time.Time{}, ErrCorruptRecord
	}
	start := time.Unix(0, n).UTC()
	if !s.Start(start).Equal(start) {
		return 0, time.Time{}, ErrCorruptRecord
	}
	return s, start, nil
}
