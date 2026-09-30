package admission

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGapNoticeClassifiesEvents(t *testing.T) {
	crit := Tier{Class: ClassC2, Severity: SeverityCritical}
	c3 := Tier{Class: ClassC3, Severity: SeverityHigh}
	c2 := Tier{Class: ClassC2, Severity: SeverityHigh}
	for _, tc := range []struct {
		name    string
		event   GapEvent
		reason  Reason
		outcome Disposition
		tier    Tier
		want    NoticeKind
	}{
		{"critical deferred on the ceiling", GapDeferred, ReasonCeiling, 0, crit, NoticeCapacity},
		{"critical deferred on history", GapDeferred, ReasonStorageShare, 0, crit, NoticeCapacity},
		{"critical deferred on recovery", GapDeferred, ReasonPendingRecovery, 0, crit, NoticeCapacity},
		{"critical deferred on a full set", GapDeferred, ReasonSetFull, 0, crit, NoticeCapacity},
		{"critical deferred without an engine", GapDeferred, ReasonEngineUnavailable, 0, crit, NoticeWithheld},
		{"c3 work deferred", GapDeferred, ReasonCeiling, 0, c3, 0},
		{"critical refused", GapEnded, ReasonAttribution, 0, crit, NoticeWithheld},
		{"critical with an existing effect", GapEnded, ReasonExistingEffect, 0, crit, 0},
		{"critical withheld", GapEnded, ReasonCollateral, 0, crit, NoticeWithheld},
		{"critical aged out", GapEnded, ReasonStale, 0, crit, NoticeWithheld},
		{"critical displaced", GapEnded, ReasonQueueOverflow, 0, crit, NoticeCapacity},
		{"c3 displaced", GapEnded, ReasonQueueOverflow, 0, c3, NoticeCapacity},
		{"general work displaced", GapEnded, ReasonQueueOverflow, 0, c2, 0},
		{"c3 below critical refused", GapEnded, ReasonPolicy, 0, c3, NoticeWithheldWarning},
		{"c2 refused", GapEnded, ReasonPolicy, 0, c2, 0},
		{"critical failed", GapOutcome, 0, DispositionFailed, crit, NoticeWithheld},
		{"critical unknown", GapOutcome, 0, DispositionUnknown, crit, NoticeWithheld},
		{"c3 unknown", GapOutcome, 0, DispositionUnknown, c3, NoticeWithheldWarning},
		{"critical applied", GapOutcome, 0, DispositionApplied, crit, 0},
		{"critical narrowed", GapOutcome, 0, DispositionNarrowed, crit, 0},
		{"unassessed dropped", GapEnded, ReasonStale, 0, Tier{}, 0},
	} {
		if got := GapNotice(tc.event, tc.reason, tc.outcome, tc.tier); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNoticeKindsNameTheirChecks(t *testing.T) {
	for k, want := range map[NoticeKind]struct {
		check    string
		severity Severity
		interval time.Duration
		critical bool
	}{
		NoticeWithheld:        {"auto_response_withheld", SeverityCritical, time.Hour, true},
		NoticeWithheldWarning: {"auto_response_withheld", SeverityWarning, time.Hour, false},
		NoticeCapacity:        {"response_capacity_exhausted", SeverityCritical, time.Hour, true},
		NoticeCriticalSummary: {"auto_response_withheld", SeverityCritical, time.Minute, false},
		NoticeAppliedSummary:  {"auto_block", SeverityWarning, time.Minute, false},
	} {
		if k.Check() != want.check || k.Severity() != want.severity || k.Interval() != want.interval || k.Critical() != want.critical {
			t.Errorf("%v: %s %v %v %v", k, k.Check(), k.Severity(), k.Interval(), k.Critical())
		}
	}
	if NoticeKind(0).Valid() || noticeKindEnd.Valid() {
		t.Fatal("an unknown notice kind is valid")
	}
}

func TestNoticeKeysValidateAndEncode(t *testing.T) {
	good := []NoticeKey{
		{Kind: NoticeWithheld, Reason: ReasonCollateral, Check: "ssh_brute", Effect: EffectAddress},
		{Kind: NoticeCapacity, Reason: ReasonQueueOverflow, Check: strings.Repeat("c", 64), Effect: EffectChallenge},
		{Kind: NoticeWithheld, Reason: ReasonEngineUnavailable},
		{Kind: NoticeWithheld, Outcome: DispositionUnknown, Check: "ssh_brute", Effect: EffectAddress},
		{Kind: NoticeWithheldWarning, Outcome: DispositionFailed, Check: "ssh_brute", Effect: EffectService},
		OverflowKey(NoticeCapacity), OverflowKey(NoticeWithheldWarning),
		{Kind: NoticeCriticalSummary}, {Kind: NoticeAppliedSummary},
	}
	for _, k := range good {
		b, err := k.Bytes()
		if err != nil || len(b) > NoticeKeyMaxLen {
			t.Fatalf("%+v: %q, %v", k, b, err)
		}
		back, err := ParseNoticeKey(b)
		if err != nil || back != k {
			t.Fatalf("parse %q = %+v, %v; want %+v", b, back, err, k)
		}
	}
	for name, k := range map[string]NoticeKey{
		"unknown kind":              {Kind: noticeKindEnd, Reason: ReasonCollateral},
		"capacity for a refusal":    {Kind: NoticeCapacity, Reason: ReasonPolicy},
		"withheld for capacity":     {Kind: NoticeWithheld, Reason: ReasonCeiling},
		"summary with a reason":     {Kind: NoticeCriticalSummary, Reason: ReasonPolicy},
		"summary with a check":      {Kind: NoticeAppliedSummary, Check: "x"},
		"overflow with a check":     {Kind: NoticeWithheld, Check: "ssh_brute"},
		"overflow with an effect":   {Kind: NoticeWithheld, Effect: EffectAddress},
		"long check":                {Kind: NoticeWithheld, Reason: ReasonPolicy, Check: strings.Repeat("c", 65)},
		"unknown effect":            {Kind: NoticeWithheld, Reason: ReasonPolicy, Effect: effectEnd},
		"existing effect is no gap": {Kind: NoticeWithheld, Reason: ReasonExistingEffect},
		"unknown reason":            {Kind: NoticeWithheld, Reason: reasonEnd},
		"outcome with a reason":     {Kind: NoticeWithheld, Reason: ReasonStale, Outcome: DispositionUnknown},
		"capacity for an outcome":   {Kind: NoticeCapacity, Outcome: DispositionFailed},
		"applied is no gap":         {Kind: NoticeWithheld, Outcome: DispositionApplied},
		"summary with an outcome":   {Kind: NoticeCriticalSummary, Outcome: DispositionUnknown},
	} {
		if _, err := k.Bytes(); err == nil {
			t.Errorf("%s: key accepted", name)
		}
	}
	for _, bad := range [][]byte{nil, []byte("n\x01\x0c\x00"), []byte("x\x01\x0c\x00\x01ssh"), []byte("n\x01\x0c\x00\x01ss h")} {
		if _, err := ParseNoticeKey(bad); err == nil {
			t.Errorf("malformed key %q parsed", bad)
		}
	}
	if len(FixedNoticeKeys()) != FixedNotices {
		t.Fatal("fixed notice keys do not match their count")
	}
}

func testCandidateID(t *testing.T, n byte) CandidateID {
	t.Helper()
	id, err := ParseCandidateID("cand_" + strings.Repeat(string("0123456789abcdef"[n%16]), 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestNoticeRecordCoalescesEvents(t *testing.T) {
	key := NoticeKey{Kind: NoticeWithheld, Reason: ReasonCollateral, Check: "ssh_brute", Effect: EffectAddress}
	r := NewNoticeRecord(key)
	var err error
	for i := 0; i < MaxNoticeExamples+5; i++ {
		if r, err = r.Add(t0.Add(time.Duration(i)*time.Second), testCandidateID(t, byte(i)), uint32(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	if r.Count != MaxNoticeExamples+5 || !r.First.Equal(t0) || !r.Last.Equal(t0.Add(time.Duration(MaxNoticeExamples+4)*time.Second)) {
		t.Fatalf("record = %+v", r)
	}
	if len(r.Examples) != MaxNoticeExamples || r.Examples[0] != (NoticeExample{Candidate: testCandidateID(t, 0), Transitions: 1, Ordinal: 1}) ||
		r.Examples[MaxNoticeExamples-1].Ordinal != MaxNoticeExamples {
		t.Fatalf("examples = %+v", r.Examples)
	}
	if r, err = r.Add(t0.Add(time.Hour), "", 0); err != nil || r.Count != MaxNoticeExamples+6 || len(r.Examples) != MaxNoticeExamples {
		t.Fatalf("an event without an example: %+v, %v", r, err)
	}
	if _, err = r.Add(t0.Add(time.Hour), testCandidateID(t, 1), 0); err == nil {
		t.Fatal("an example without a transition was accepted")
	}
	if _, err = r.Add(time.Time{}, "", 0); err == nil {
		t.Fatal("an event without a time was accepted")
	}
	full := NewNoticeRecord(key)
	full.Count, full.First, full.Last = math.MaxUint64, t0, t0
	if full, err = full.Add(t0.Add(time.Second), testCandidateID(t, 3), 1); err != nil || full.Count != math.MaxUint64 || len(full.Examples) != 0 {
		t.Fatalf("a saturated count took an example: %+v, %v", full, err)
	}
	if !full.Last.Equal(t0.Add(time.Second)) {
		t.Fatal("a saturated record stopped tracking its last event")
	}
}

func TestNoticeDeliveryBounds(t *testing.T) {
	key := NoticeKey{Kind: NoticeCapacity, Reason: ReasonCeiling, Check: "ssh_brute", Effect: EffectAddress}
	r := NewNoticeRecord(key)
	if r.Due(t0) {
		t.Fatal("an empty record is due")
	}
	r, _ = r.Add(t0, testCandidateID(t, 1), 2)
	if !r.Due(t0) {
		t.Fatal("the first event of a key is not due at once")
	}
	seen := r.Count
	r, _ = r.Add(t0.Add(time.Second), testCandidateID(t, 2), 2)
	r, err := r.Ack(seen, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if r.Acked != 1 || r.Unsent() != 1 || len(r.Examples) != 1 || r.Examples[0].Ordinal != 2 || !r.Sent.Equal(t0.Add(time.Second)) {
		t.Fatalf("an acknowledgement lost a later event: %+v", r)
	}
	if again, ackErr := r.Ack(seen, t0.Add(time.Minute)); ackErr != nil || !reflect.DeepEqual(again, r) {
		t.Fatalf("a repeated acknowledgement changed the record: %+v, %v", again, ackErr)
	}
	if r.Due(t0.Add(time.Second + time.Hour - 1)) {
		t.Fatal("a key was due twice within an hour")
	}
	if !r.Due(t0.Add(time.Second + time.Hour)) {
		t.Fatal("a key was not due an hour after its delivery")
	}
	if _, err = r.Ack(r.Count+1, t0.Add(time.Hour)); err == nil {
		t.Fatal("an acknowledgement beyond the count was accepted")
	}
	sum := NewNoticeRecord(NoticeKey{Kind: NoticeCriticalSummary})
	sum, _ = sum.Add(t0, testCandidateID(t, 1), 2)
	sum, _ = sum.Ack(1, t0)
	sum, _ = sum.Add(t0.Add(time.Second), testCandidateID(t, 2), 2)
	if sum.Due(t0.Add(time.Minute-1)) || !sum.Due(t0.Add(time.Minute)) {
		t.Fatal("a summary is not bounded to once a minute")
	}
}

func TestNoticeRecordQuiet(t *testing.T) {
	key := NoticeKey{Kind: NoticeWithheld, Reason: ReasonStale, Check: "ssh_brute", Effect: EffectAddress}
	r := NewNoticeRecord(key)
	r, _ = r.Add(t0, "", 0)
	if r.Quiet(t0.Add(48 * time.Hour)) {
		t.Fatal("an undelivered record is quiet")
	}
	r, _ = r.Ack(1, t0)
	if r.Quiet(t0.Add(time.Hour-1)) || !r.Quiet(t0.Add(time.Hour)) {
		t.Fatal("a delivered record is not quiet exactly an hour after its delivery")
	}
	fixed := NewNoticeRecord(OverflowKey(NoticeWithheld))
	fixed, _ = fixed.Add(t0, "", 0)
	fixed, _ = fixed.Ack(1, t0)
	if fixed.Quiet(t0.Add(48 * time.Hour)) {
		t.Fatal("a fixed record is quiet")
	}
}

func TestNoticeRecordRoundTripsAndRefusesTampering(t *testing.T) {
	key := NoticeKey{Kind: NoticeWithheld, Reason: ReasonCollateral, Check: "ssh_brute", Effect: EffectAddress}
	r := NewNoticeRecord(key)
	r, _ = r.Add(t0, testCandidateID(t, 1), 2)
	r, _ = r.Add(t0.Add(time.Second), testCandidateID(t, 2), 3)
	r, _ = r.Ack(1, t0.Add(time.Second))
	for _, rec := range []NoticeRecord{r, NewNoticeRecord(OverflowKey(NoticeCapacity))} {
		data, err := rec.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmarshalNoticeRecord(data)
		if err != nil || !reflect.DeepEqual(back, rec) {
			t.Fatalf("round trip = %+v, %v\nwant %+v", back, err, rec)
		}
	}
	data, _ := r.MarshalBinary()
	body := data[:len(data)-8]
	prefix := []byte(fmt.Sprintf(`{"v":%d,`, noticeRecordVersion))
	for name, tampered := range map[string][]byte{
		"flipped byte":  func() []byte { d := bytes.Clone(data); d[10] ^= 1; return d }(),
		"unknown field": resealForTest(bytes.Replace(body, prefix, []byte(fmt.Sprintf(`{"v":%d,"x":1,`, noticeRecordVersion)), 1)),
		"next version":  resealForTest(bytes.Replace(body, prefix, []byte(fmt.Sprintf(`{"v":%d,`, noticeRecordVersion+1)), 1)),
	} {
		if _, err := UnmarshalNoticeRecord(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
	for name, mutate := range map[string]func(*NoticeRecord){
		"acked beyond count":       func(r *NoticeRecord) { r.Acked = r.Count + 1 },
		"acked without a delivery": func(r *NoticeRecord) { r.Sent = time.Time{} },
		"delivered with nothing":   func(r *NoticeRecord) { r.Acked = 0 },
		"last before first":        func(r *NoticeRecord) { r.First = r.Last.Add(time.Second) },
		"no first event":           func(r *NoticeRecord) { r.First = time.Time{} },
		"acked example":            func(r *NoticeRecord) { r.Examples[0].Ordinal = r.Acked },
		"example past the count":   func(r *NoticeRecord) { r.Examples[0].Ordinal = r.Count + 1 },
		"example without a step":   func(r *NoticeRecord) { r.Examples[0].Transitions = 0 },
		"example without an ID":    func(r *NoticeRecord) { r.Examples[0].Candidate = "cand_x" },
		"examples out of order": func(r *NoticeRecord) {
			r.Count++
			r.Examples = append(r.Examples, r.Examples[0])
		},
		"too many examples": func(r *NoticeRecord) {
			r.Count = MaxNoticeExamples + 2
			r.Examples = nil
			for i := 0; i <= MaxNoticeExamples; i++ {
				r.Examples = append(r.Examples, NoticeExample{Candidate: testCandidateID(t, 1), Transitions: 1, Ordinal: uint64(i + 2)})
			}
		},
		"keyed record without events": func(r *NoticeRecord) { *r = NewNoticeRecord(r.Key) },
		"invalid key":                 func(r *NoticeRecord) { r.Key.Reason = ReasonCeiling },
	} {
		m := r
		m.Examples = append([]NoticeExample(nil), r.Examples...)
		mutate(&m)
		if _, err := m.MarshalBinary(); err == nil {
			t.Errorf("%s: record accepted", name)
		}
	}
	empty := NewNoticeRecord(OverflowKey(NoticeWithheld))
	empty.First = t0
	if _, err := empty.MarshalBinary(); err == nil {
		t.Fatal("an empty record with an event time was accepted")
	}
	// Undelivered, so only the event times can refuse it.
	pending := NewNoticeRecord(key)
	pending, _ = pending.Add(t0, "", 0)
	pending.First = pending.Last.Add(time.Second)
	if _, err := pending.MarshalBinary(); err == nil {
		t.Fatal("an undelivered record whose last event precedes its first was accepted")
	}
}

// The outbox charges a fixed slot per notice record, so the widest record
// the invariants allow must fit it.
func TestNoticeRecordFitsItsSlot(t *testing.T) {
	far := time.Unix(0, math.MaxInt64).UTC()
	r := NoticeRecord{
		Key:   NoticeKey{Kind: NoticeWithheldWarning, Reason: reasonEnd - 1, Check: strings.Repeat("c", 64), Effect: effectEnd - 1},
		Count: math.MaxUint64, Acked: math.MaxUint64 - MaxNoticeExamples - 1, First: far, Last: far, Sent: far,
	}
	for i := uint64(0); i < MaxNoticeExamples; i++ {
		r.Examples = append(r.Examples, NoticeExample{Candidate: testCandidateID(t, 15), Transitions: math.MaxUint32, Ordinal: math.MaxUint64 - MaxNoticeExamples + i})
	}
	data, err := r.MarshalBinary()
	if err != nil || len(data) > MaxNoticeRecordBytes {
		t.Fatalf("largest record: %d bytes (bound %d), %v", len(data), MaxNoticeRecordBytes, err)
	}
	if NoticeSlotBytes != NoticeKeyMaxLen+NoticeQuietKeyMaxLen+MaxNoticeRecordBytes || NoticeBytes/NoticeSlotBytes < 1000 {
		t.Fatal("notice slots do not add up or the share holds too few keys")
	}
}

// A keyed record is quiet from an interval after the delivery that covered
// all its events; the index key orders records by that time.
func TestNoticeRecordQuietIndex(t *testing.T) {
	key := NoticeKey{Kind: NoticeWithheld, Reason: ReasonStale, Check: "ssh_brute", Effect: EffectAddress}
	r, _ := NewNoticeRecord(key).Add(t0, "", 0)
	if !r.QuietAt().IsZero() {
		t.Fatal("an undelivered record has a quiet time")
	}
	r, _ = r.Ack(1, t0.Add(time.Minute))
	at := r.QuietAt()
	if !at.Equal(t0.Add(time.Minute + time.Hour)) {
		t.Fatalf("quiet at %v", at)
	}
	k, err := QuietKey(at, key)
	if err != nil || len(k) > NoticeQuietKeyMaxLen {
		t.Fatalf("key %q, %v", k, err)
	}
	back, gotKey, err := ParseQuietKey(k)
	if err != nil || !back.Equal(at) || gotKey != key {
		t.Fatalf("parse = %v %+v %v", back, gotKey, err)
	}
	earlier, _ := QuietKey(at.Add(-time.Second), key)
	if bytes.Compare(earlier, k) >= 0 {
		t.Fatal("quiet keys do not order by time")
	}
	if r, _ = r.Add(t0.Add(2*time.Minute), "", 0); !r.QuietAt().IsZero() {
		t.Fatal("a record with a new event is still quiet")
	}
	fixed, _ := NewNoticeRecord(OverflowKey(NoticeWithheld)).Add(t0, "", 0)
	fixed, _ = fixed.Ack(1, t0)
	if !fixed.QuietAt().IsZero() {
		t.Fatal("a fixed record has a quiet time")
	}
	if _, err = QuietKey(at, OverflowKey(NoticeWithheld)); err == nil {
		t.Fatal("a fixed record got a quiet key")
	}
	for _, bad := range [][]byte{nil, k[:20], append([]byte{'x'}, k[1:]...), append(append([]byte{'q'}, []byte("0000000000000000000")...), k[20:]...)} {
		if _, _, err := ParseQuietKey(bad); err == nil {
			t.Errorf("malformed quiet key %q parsed", bad)
		}
	}
}

func TestNoticeSlotIncludesEscapedChecksAndUnknownOutcomes(t *testing.T) {
	far := time.Unix(0, math.MinInt64).UTC()
	for _, check := range []string{strings.Repeat("&", 64), strings.Repeat(`"`, 64), strings.Repeat(`\`, 64)} {
		for _, key := range []NoticeKey{
			{Kind: NoticeWithheldWarning, Reason: ReasonIngressInterruption, Check: check, Effect: EffectChallenge},
			{Kind: NoticeWithheldWarning, Outcome: DispositionUnknown, Check: check, Effect: EffectChallenge},
		} {
			r := NoticeRecord{Key: key, Count: math.MaxUint64, Acked: math.MaxUint64 - 21, First: far, Last: far, Sent: far}
			for i := uint64(0); i < 20; i++ {
				r.Examples = append(r.Examples, NoticeExample{testCandidateID(t, 15), math.MaxUint32, math.MaxUint64 - 20 + i})
			}
			data, err := r.MarshalBinary()
			if err != nil || len(data) > MaxNoticeRecordBytes {
				t.Errorf("check %q, outcome %v: %d bytes, bound %d, error %v", check[:1], key.Outcome, len(data), MaxNoticeRecordBytes, err)
				continue
			}
			back, err := UnmarshalNoticeRecord(data)
			if err != nil || !reflect.DeepEqual(back, r) {
				t.Errorf("escaped check did not round trip: %+v, %v", back, err)
			}
		}
	}
}

func TestNoticeMutationsRefuseDamagedReceivers(t *testing.T) {
	good, err := NewNoticeRecord(NoticeKey{Kind: NoticeWithheld, Reason: ReasonPolicy}).Add(t0, testCandidateID(t, 1), 1)
	if err != nil {
		t.Fatal(err)
	}
	for name, damage := range map[string]func(*NoticeRecord){
		"key": func(r *NoticeRecord) { r.Key.Kind = noticeKindEnd },
		"count": func(r *NoticeRecord) {
			r.Acked, r.Sent, r.Examples = 2, t0, nil
		},
		"first time": func(r *NoticeRecord) { r.First = time.Time{} },
		"example":    func(r *NoticeRecord) { r.Examples[0].Ordinal = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			r := good
			r.Examples = append([]NoticeExample(nil), good.Examples...)
			damage(&r)
			before := r
			before.Examples = append([]NoticeExample(nil), r.Examples...)
			if got, err := r.Add(t0.Add(time.Second), "", 0); err == nil || !reflect.DeepEqual(got, before) || !reflect.DeepEqual(r, before) {
				t.Errorf("Add did not refuse unchanged: %+v, %v", got, err)
			}
			if got, err := r.Ack(1, t0.Add(time.Second)); err == nil || !reflect.DeepEqual(got, before) || !reflect.DeepEqual(r, before) {
				t.Errorf("Ack did not refuse unchanged: %+v, %v", got, err)
			}
		})
	}
}

func TestNoticeMutationsRefuseBackwardTimes(t *testing.T) {
	r, err := NewNoticeRecord(NoticeKey{Kind: NoticeWithheld, Reason: ReasonPolicy}).Add(t0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, addErr := r.Add(t0.Add(-time.Second), "", 0); addErr == nil || !reflect.DeepEqual(got, r) {
		t.Errorf("backward event was not refused unchanged: %+v, %v", got, addErr)
	}
	if got, ackErr := r.Ack(1, t0.Add(-time.Second)); ackErr == nil || !reflect.DeepEqual(got, r) {
		t.Errorf("delivery before the event was not refused unchanged: %+v, %v", got, ackErr)
	}
	r, err = r.Add(t0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err = r.Ack(1, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got, addErr := r.Add(t0.Add(time.Second), "", 0); addErr == nil || !reflect.DeepEqual(got, r) {
		t.Errorf("an event before the previous delivery was not refused unchanged: %+v, %v", got, addErr)
	}
	if got, ackErr := r.Ack(2, t0.Add(time.Second)); ackErr == nil || !reflect.DeepEqual(got, r) {
		t.Errorf("an acknowledgement before the previous delivery was not refused unchanged: %+v, %v", got, ackErr)
	}
	r, err = r.Add(t0.Add(time.Minute), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Ack(3, t0.Add(time.Second)); err == nil || !reflect.DeepEqual(got, r) {
		t.Errorf("a later acknowledgement moved delivery backward: %+v, %v", got, err)
	}
}

func TestNoticeCodecRejectsDeliveryBeforeFirstEvent(t *testing.T) {
	r, err := NewNoticeRecord(NoticeKey{Kind: NoticeWithheld, Reason: ReasonPolicy}).Add(t0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err = r.Ack(1, t0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	early := t0.Add(-time.Second)
	body := bytes.Replace(data[:len(data)-8], []byte(fmt.Sprintf(`"sent":%d`, t0.UnixNano())), []byte(fmt.Sprintf(`"sent":%d`, early.UnixNano())), 1)
	if _, err := UnmarshalNoticeRecord(resealForTest(body)); err != ErrCorruptRecord {
		t.Errorf("decoder accepted delivery before the first event: %v", err)
	}
	r.Sent = early
	if _, err := r.MarshalBinary(); err == nil {
		t.Error("encoder accepted delivery before the first event")
	}
}

// Version 1 stored checks as text. A base64-shaped old check must never
// silently acquire a different identity when the encoding changes.
func legacyCheckRecord(t *testing.T, data []byte) []byte {
	t.Helper()
	body := data[:len(data)-8]
	versionEnd := bytes.IndexByte(body, ',')
	if versionEnd < 0 {
		t.Fatal("record has no version separator")
	}
	body = append([]byte(`{"v":1`), body[versionEnd:]...)
	checkAt := bytes.Index(body, []byte(`"check":`))
	if checkAt < 0 {
		t.Fatal("record has no check")
	}
	checkAt += len(`"check":`)
	checkEnd := bytes.IndexByte(body[checkAt:], ',')
	if checkEnd < 0 {
		t.Fatal("record has no field after check")
	}
	old := append([]byte(nil), body[:checkAt]...)
	old = append(old, `"QUJD"`...)
	return resealForTest(append(old, body[checkAt+checkEnd:]...))
}

func TestNoticeRejectsUnversionedCheckEncoding(t *testing.T) {
	r, err := NewNoticeRecord(NoticeKey{Kind: NoticeWithheld, Reason: ReasonPolicy, Check: "QUJD", Effect: EffectAddress}).Add(t0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalNoticeRecord(legacyCheckRecord(t, data)); err != ErrCorruptRecord {
		t.Errorf("accepted a legacy check that aliases a base64 check: %v", err)
	}
}

// Events counted in bulk, as a checkpoint reports them, add to the count
// without examples and saturate.
func TestNoticeRecordAddsCounts(t *testing.T) {
	key := NoticeKey{Kind: NoticeCapacity, Reason: ReasonQueueOverflow}
	r, err := NewNoticeRecord(key).AddCount(t0, 3)
	if err != nil || r.Count != 3 || !r.First.Equal(t0) || !r.Last.Equal(t0) || len(r.Examples) != 0 {
		t.Fatalf("add three = %+v, %v", r, err)
	}
	if again, addErr := r.AddCount(t0.Add(time.Second), 0); addErr != nil || !reflect.DeepEqual(again, r) {
		t.Fatalf("add none changed the record: %+v, %v", again, addErr)
	}
	r.Count = math.MaxUint64 - 1
	if r, err = r.AddCount(t0.Add(time.Second), 5); err != nil || r.Count != math.MaxUint64 || !r.Last.Equal(t0.Add(time.Second)) {
		t.Fatalf("saturation = %+v, %v", r, err)
	}
	if _, err = r.AddCount(time.Time{}, 1); err == nil {
		t.Fatal("a count without a time was accepted")
	}
}
