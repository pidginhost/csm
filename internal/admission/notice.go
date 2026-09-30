package admission

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// Notice bounds of spec 5.17. Response notices coalesce into one record per
// key in the outbox; each record is charged a fixed slot.
const (
	// MaxNoticeExamples bounds the example candidates one record keeps.
	MaxNoticeExamples = 20
	// MaxNoticeRecordBytes bounds one encoded notice record.
	MaxNoticeRecordBytes = 2048
	// NoticeKeyMaxLen is the longest notice key: a kind byte, the notice
	// kind, reason, outcome and effect, and a check name of at most 64
	// bytes.
	NoticeKeyMaxLen = 5 + 64
	// NoticeQuietKeyMaxLen is the longest quiet index key: a kind byte, a
	// time as 19 decimal digits and the record's key.
	NoticeQuietKeyMaxLen = 1 + 19 + NoticeKeyMaxLen
	// NoticeSlotBytes is what one record holds in the outbox, with its key
	// and its quiet index key.
	NoticeSlotBytes = NoticeKeyMaxLen + NoticeQuietKeyMaxLen + MaxNoticeRecordBytes
	// NoticeBytes is the share of the recovery and outbox reserve notice
	// records may hold. Keys combine a reason with any registered check, so
	// an attacker choosing which checks fire could otherwise fill the
	// reserve and stop admission. An event whose key finds no room is
	// counted in its kind's overflow record.
	NoticeBytes = 8 << 20
	// FixedNotices is the records every ledger keeps from its creation: an
	// overflow record per keyed kind and the two summaries. They are
	// charged in advance and never refused.
	FixedNotices = 5
)

// noticeKind is the outbox key kind of notice records.
const noticeKind = 'n'

// NoticeKind is what a notice record reports.
type NoticeKind uint8

const (
	// NoticeWithheld: Critical work did not receive its response.
	NoticeWithheld NoticeKind = iota + 1
	// NoticeWithheldWarning: C3 work below Critical did not receive it.
	NoticeWithheldWarning
	// NoticeCapacity: Critical work waits on capacity, or Critical or
	// reserved work was lost to it.
	NoticeCapacity
	// NoticeCriticalSummary counts every Critical notice event, so a flood
	// of other keys cannot delay the first Critical gap.
	NoticeCriticalSummary
	// NoticeAppliedSummary counts verified responses.
	NoticeAppliedSummary
	noticeKindEnd
)

var noticeKindNames = [...]string{"", "withheld", "withheld_warning", "capacity", "critical_summary", "applied_summary"}

func (k NoticeKind) Valid() bool { return k >= NoticeWithheld && k < noticeKindEnd }

func (k NoticeKind) String() string {
	if k.Valid() {
		return noticeKindNames[k]
	}
	return fmt.Sprintf("notice(%d)", uint8(k))
}

// Keyed reports whether records of k are kept per key rather than fixed.
func (k NoticeKind) Keyed() bool { return k >= NoticeWithheld && k <= NoticeCapacity }

// Critical reports whether an event of k is a Critical response gap.
func (k NoticeKind) Critical() bool { return k == NoticeWithheld || k == NoticeCapacity }

// Check is the registered check a notice of k is delivered as.
func (k NoticeKind) Check() string {
	switch k {
	case NoticeCapacity:
		return "response_capacity_exhausted"
	case NoticeAppliedSummary:
		return "auto_block"
	}
	return "auto_response_withheld"
}

// Severity is the severity a notice of k is delivered with.
func (k NoticeKind) Severity() Severity {
	if k == NoticeWithheldWarning || k == NoticeAppliedSummary {
		return SeverityWarning
	}
	return SeverityCritical
}

// Interval is the least time between two deliveries of one record: an
// hour per key, a minute for each summary.
func (k NoticeKind) Interval() time.Duration {
	if k.Keyed() {
		return time.Hour
	}
	return time.Minute
}

// Capacity reports whether r is a capacity reason: the response waits on,
// or was lost to, a bound the ledger enforces.
func (r Reason) Capacity() bool {
	switch r {
	case ReasonCeiling, ReasonSetFull, ReasonStorageShare, ReasonPendingRecovery, ReasonQueueOverflow:
		return true
	}
	return false
}

// GapEvent is the kind of event a notice can follow.
type GapEvent uint8

const (
	// GapDeferred: a queued candidate took a new deferral reason.
	GapDeferred GapEvent = iota + 1
	// GapEnded: a candidate or arrival ended without an attempt outcome.
	GapEnded
	// GapOutcome: an attempt recorded its outcome.
	GapOutcome
)

// GapNotice is the notice an event raises (spec 5.17), or zero. tier is
// the last assessment, zero for unassessed work, which raises none. C3 is
// exactly the work the reserved lane serves, so a lost C3 candidate is
// lost reserved work. Capacity reasons raise only the capacity notice. Only a
// failure that ends the candidate or an unknown outcome is a gap; an
// existing verified effect is not.
func GapNotice(event GapEvent, reason Reason, outcome Disposition, tier Tier) NoticeKind {
	critical, c3 := tier.Severity == SeverityCritical, tier.Class == ClassC3
	switch event {
	case GapDeferred:
		switch {
		case !critical:
			return 0
		case reason.Capacity():
			return NoticeCapacity
		}
		return NoticeWithheld
	case GapEnded:
		switch {
		case reason == ReasonExistingEffect:
			return 0
		case reason.Capacity():
			if critical || c3 {
				return NoticeCapacity
			}
			return 0
		}
	case GapOutcome:
		if outcome != DispositionFailed && outcome != DispositionUnknown {
			return 0
		}
	default:
		return 0
	}
	switch {
	case critical:
		return NoticeWithheld
	case c3:
		return NoticeWithheldWarning
	}
	return 0
}

// NoticeKey coalesces notice events: one record per fixed reason,
// registered check and action family (spec 5.17). An attempt that failed
// for good or ended unknown has no reason; its outcome takes the reason's
// place. Check and Effect are empty for an arrival lost before admission,
// which names no candidate. A keyed kind with neither reason nor outcome
// is that kind's overflow record; a summary has only its kind.
type NoticeKey struct {
	Kind    NoticeKind
	Reason  Reason
	Outcome Disposition
	Check   string
	Effect  Effect
}

// OverflowKey is the record that counts events of kind k whose own key
// found no room.
func OverflowKey(k NoticeKind) NoticeKey { return NoticeKey{Kind: k} }

// FixedNoticeKeys are the records every ledger keeps.
func FixedNoticeKeys() []NoticeKey {
	return []NoticeKey{
		OverflowKey(NoticeWithheld), OverflowKey(NoticeWithheldWarning), OverflowKey(NoticeCapacity),
		{Kind: NoticeCriticalSummary}, {Kind: NoticeAppliedSummary},
	}
}

// Fixed reports whether the record under k is one every ledger keeps.
func (k NoticeKey) Fixed() bool { return k.Reason == 0 && k.Outcome == 0 }

func (k NoticeKey) validate() error {
	bad := func(detail string) error { return refuse(ReasonInvalid, detail) }
	switch {
	case !k.Kind.Valid():
		return bad("notice kind is unknown")
	case k.Fixed():
		if k.Check != "" || k.Effect != 0 {
			return bad("a fixed notice record names a check or an effect")
		}
		return nil
	case !k.Kind.Keyed():
		return bad("a summary has no reason")
	case k.Outcome != 0:
		if k.Reason != 0 || k.Kind == NoticeCapacity || (k.Outcome != DispositionFailed && k.Outcome != DispositionUnknown) {
			return bad("notice outcome is not a withheld response")
		}
	case !k.Reason.Valid() || k.Reason == ReasonExistingEffect:
		return bad("notice reason is not a response gap")
	case k.Reason.Capacity() != (k.Kind == NoticeCapacity):
		return bad("notice kind does not match its reason")
	}
	switch {
	case k.Check != "" && !boundedToken(k.Check, 64):
		return bad("notice check is malformed")
	case k.Effect != 0 && !k.Effect.Valid():
		return bad("notice effect is unknown")
	}
	return nil
}

// Bytes is the key's outbox key.
func (k NoticeKey) Bytes() ([]byte, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	return append([]byte{noticeKind, byte(k.Kind), byte(k.Reason), byte(k.Outcome), byte(k.Effect)}, k.Check...), nil
}

// ParseNoticeKey decodes an outbox key written by Bytes.
func ParseNoticeKey(b []byte) (NoticeKey, error) {
	if len(b) < 5 || len(b) > NoticeKeyMaxLen || b[0] != noticeKind {
		return NoticeKey{}, ErrCorruptRecord
	}
	k := NoticeKey{Kind: NoticeKind(b[1]), Reason: Reason(b[2]), Outcome: Disposition(b[3]), Effect: Effect(b[4]), Check: string(b[5:])}
	if k.validate() != nil {
		return NoticeKey{}, ErrCorruptRecord
	}
	return k, nil
}

// NoticeExample is one event's candidate. Ordinal is the event's position
// in the record's count, so an acknowledgement drops exactly the examples
// it covered.
type NoticeExample struct {
	Candidate   CandidateID
	Transitions uint32
	Ordinal     uint64
}

// NoticeRecord is one coalesced notice: a saturating count of events, the
// first and last event times, up to MaxNoticeExamples undelivered examples
// and the delivery state. Acked counts the events the last delivery
// covered; events after it stay pending.
type NoticeRecord struct {
	Key         NoticeKey
	Count       uint64
	Acked       uint64
	First, Last time.Time
	// Sent is when the last delivery was acknowledged; zero before one.
	Sent     time.Time
	Examples []NoticeExample
}

// NewNoticeRecord is an empty record for k.
func NewNoticeRecord(k NoticeKey) NoticeRecord { return NoticeRecord{Key: k} }

// Unsent is the events no delivery has covered.
func (r NoticeRecord) Unsent() uint64 { return r.Count - r.Acked }

// Add records one event at time at. A zero candidate adds no example; so
// does a record whose examples are full or whose count has saturated.
func (r NoticeRecord) Add(at time.Time, candidate CandidateID, transitions uint32) (NoticeRecord, error) {
	if _, err := r.record(true); err != nil {
		return r, err
	}
	if _, ok := unixNano(at); !ok {
		return r, refuse(ReasonInvalid, "notice event has no time")
	}
	if at.Before(r.Last) || at.Before(r.Sent) {
		return r, refuse(ReasonInvalid, "notice event time moved backward")
	}
	if candidate != "" {
		if _, err := ParseCandidateID(string(candidate)); err != nil || transitions == 0 {
			return r, refuse(ReasonInvalid, "notice example is malformed")
		}
	}
	if r.Count == 0 {
		r.First = at
	}
	if at.After(r.Last) {
		r.Last = at
	}
	if r.Count == math.MaxUint64 {
		return r, nil
	}
	r.Count++
	if candidate != "" && len(r.Examples) < MaxNoticeExamples {
		r.Examples = append(append([]NoticeExample(nil), r.Examples...), NoticeExample{Candidate: candidate, Transitions: transitions, Ordinal: r.Count})
	}
	return r, nil
}

// AddCount records n events at time at without examples, as a checkpoint
// reports them. The count saturates.
func (r NoticeRecord) AddCount(at time.Time, n uint64) (NoticeRecord, error) {
	if _, err := r.record(true); err != nil {
		return r, err
	}
	if _, ok := unixNano(at); !ok {
		return r, refuse(ReasonInvalid, "notice event has no time")
	}
	if at.Before(r.Last) || at.Before(r.Sent) {
		return r, refuse(ReasonInvalid, "notice event time moved backward")
	}
	if n == 0 {
		return r, nil
	}
	if r.Count == 0 {
		r.First = at
	}
	if at.After(r.Last) {
		r.Last = at
	}
	r.Count += min(n, math.MaxUint64-r.Count)
	return r, nil
}

// Due reports whether the record has undelivered events and its kind's
// interval has passed since the last delivery.
func (r NoticeRecord) Due(now time.Time) bool {
	return r.Count > r.Acked && (r.Sent.IsZero() || !now.Before(r.Sent.Add(r.Key.Kind.Interval())))
}

// Ack records a delivery that covered the first count events, at time at.
// A repeated or older acknowledgement changes nothing.
func (r NoticeRecord) Ack(count uint64, at time.Time) (NoticeRecord, error) {
	if _, err := r.record(true); err != nil {
		return r, err
	}
	if count > r.Count {
		return r, refuse(ReasonInvalid, "acknowledgement covers events the record does not hold")
	}
	if count <= r.Acked {
		return r, nil
	}
	if _, ok := unixNano(at); !ok {
		return r, refuse(ReasonInvalid, "acknowledgement has no time")
	}
	if at.Before(r.Last) || at.Before(r.Sent) {
		return r, refuse(ReasonInvalid, "notice acknowledgement time moved backward")
	}
	r.Acked, r.Sent = count, at
	var kept []NoticeExample
	for _, e := range r.Examples {
		if e.Ordinal > count {
			kept = append(kept, e)
		}
	}
	r.Examples = kept
	return r, nil
}

// QuietAt is when a keyed record whose events were all delivered becomes
// quiet; zero while an event is pending, before any delivery or for a
// fixed record.
func (r NoticeRecord) QuietAt() time.Time {
	if r.Key.Fixed() || r.Count != r.Acked || r.Sent.IsZero() {
		return time.Time{}
	}
	return r.Sent.Add(r.Key.Kind.Interval())
}

// quietKind is the outbox key kind of the quiet index.
const quietKind = 'q'

// QuietKey is the quiet index key of the record under k, quiet from at:
// the time as 19 decimal digits, so the index sorts by it, and the key.
func QuietKey(at time.Time, k NoticeKey) ([]byte, error) {
	kb, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	n, ok := unixNano(at)
	if !ok || n <= 0 || k.Fixed() {
		return nil, refuse(ReasonInvalid, "quiet key needs a keyed record and a time after the epoch")
	}
	return append(fmt.Appendf([]byte{quietKind}, "%019d", n), kb...), nil
}

// ParseQuietKey decodes a key written by QuietKey.
func ParseQuietKey(b []byte) (time.Time, NoticeKey, error) {
	if len(b) < 20 || len(b) > NoticeQuietKeyMaxLen || b[0] != quietKind {
		return time.Time{}, NoticeKey{}, ErrCorruptRecord
	}
	n, err := strconv.ParseInt(string(b[1:20]), 10, 64)
	if err != nil || n <= 0 || fmt.Sprintf("%019d", n) != string(b[1:20]) {
		return time.Time{}, NoticeKey{}, ErrCorruptRecord
	}
	k, err := ParseNoticeKey(b[20:])
	if err != nil || k.Fixed() {
		return time.Time{}, NoticeKey{}, ErrCorruptRecord
	}
	return time.Unix(0, n).UTC(), k, nil
}

// NoticeAck acknowledges Count events of the record read under Key.
// First fences a repeated acknowledgement from a later record under the
// same key: quiet removal requires the clock to advance past delivery.
type NoticeAck struct {
	Key   NoticeKey
	First time.Time
	Count uint64
}

// Quiet reports whether a keyed record may be removed: everything was
// delivered and its interval has passed since, so a new record for the
// key could not deliver sooner than this one would.
func (r NoticeRecord) Quiet(now time.Time) bool {
	return !r.Key.Fixed() && r.Count == r.Acked && !r.Sent.IsZero() && !now.Before(r.Sent.Add(r.Key.Kind.Interval()))
}

const noticeRecordVersion = 2

type noticeExampleRecord struct {
	Candidate   CandidateID `json:"c"`
	Transitions uint32      `json:"t"`
	Ordinal     uint64      `json:"o"`
}

type noticeRecordRecord struct {
	V       uint8       `json:"v"`
	Kind    NoticeKind  `json:"kind"`
	Reason  Reason      `json:"reason,omitempty"`
	Outcome Disposition `json:"outcome,omitempty"`
	// Base64 bounds printable check names without JSON escape expansion.
	Check    []byte                `json:"check,omitempty"`
	Effect   Effect                `json:"effect,omitempty"`
	Count    uint64                `json:"count,omitempty"`
	Acked    uint64                `json:"acked,omitempty"`
	First    int64                 `json:"first,omitempty"`
	Last     int64                 `json:"last,omitempty"`
	Sent     int64                 `json:"sent,omitempty"`
	Examples []noticeExampleRecord `json:"examples,omitempty"`
}

func (r NoticeRecord) record(allowEmpty bool) (noticeRecordRecord, error) {
	bad := func(detail string) (noticeRecordRecord, error) {
		return noticeRecordRecord{}, refuse(ReasonInvalid, detail)
	}
	if err := r.Key.validate(); err != nil {
		return noticeRecordRecord{}, err
	}
	rec := noticeRecordRecord{V: noticeRecordVersion, Kind: r.Key.Kind, Reason: r.Key.Reason, Outcome: r.Key.Outcome, Check: []byte(r.Key.Check), Effect: r.Key.Effect, Count: r.Count, Acked: r.Acked}
	if r.Count == 0 {
		if !allowEmpty && !r.Key.Fixed() {
			return bad("a keyed notice record has no event")
		}
		if r.Acked != 0 || !r.First.IsZero() || !r.Last.IsZero() || !r.Sent.IsZero() || len(r.Examples) != 0 {
			return bad("an empty notice record has event or delivery state")
		}
		return rec, nil
	}
	var okFirst, okLast bool
	rec.First, okFirst = unixNano(r.First)
	rec.Last, okLast = unixNano(r.Last)
	if !okFirst || !okLast || r.Last.Before(r.First) {
		return bad("notice event times are inconsistent")
	}
	if r.Acked > r.Count || (r.Acked == 0) != r.Sent.IsZero() {
		return bad("notice delivery state is inconsistent")
	}
	if r.Acked > 0 {
		var ok bool
		if rec.Sent, ok = unixNano(r.Sent); !ok || r.Sent.Before(r.First) {
			return bad("notice delivery time is inconsistent")
		}
	}
	if len(r.Examples) > MaxNoticeExamples {
		return bad("notice record keeps too many examples")
	}
	last := r.Acked
	for _, e := range r.Examples {
		if _, err := ParseCandidateID(string(e.Candidate)); err != nil || e.Transitions == 0 || e.Ordinal <= last || e.Ordinal > r.Count {
			return bad("notice examples are malformed, delivered or out of order")
		}
		last = e.Ordinal
		rec.Examples = append(rec.Examples, noticeExampleRecord(e))
	}
	return rec, nil
}

func (r NoticeRecord) MarshalBinary() ([]byte, error) {
	rec, err := r.record(false)
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalNoticeRecord decodes a stored record and checks its invariants.
func UnmarshalNoticeRecord(data []byte) (NoticeRecord, error) {
	var rec noticeRecordRecord
	if err := openRecord(data, &rec); err != nil {
		return NoticeRecord{}, err
	}
	r := NoticeRecord{
		Key:   NoticeKey{Kind: rec.Kind, Reason: rec.Reason, Outcome: rec.Outcome, Check: string(rec.Check), Effect: rec.Effect},
		Count: rec.Count, Acked: rec.Acked, First: fromNano(rec.First), Last: fromNano(rec.Last), Sent: fromNano(rec.Sent),
	}
	for _, e := range rec.Examples {
		r.Examples = append(r.Examples, NoticeExample(e))
	}
	if again, err := r.MarshalBinary(); rec.V != noticeRecordVersion || err != nil || string(again) != string(data) {
		return NoticeRecord{}, ErrCorruptRecord
	}
	return r, nil
}
