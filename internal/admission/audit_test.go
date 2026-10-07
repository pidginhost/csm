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

// reservedPair is a queued candidate after its first reservation, with that
// attempt.
func reservedPair(t *testing.T) (Candidate, AttemptRecord) {
	t.Helper()
	c := queuedCandidate(t)
	id, err := c.ID()
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewAttempt(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	c.State, c.Attempts, c.ExpiresAt, c.Transitions = StateReserved, 1, t0.Add(time.Hour), 2
	a := AttemptRecord{Attempt: first, State: StateReserved, ExpiresAt: c.ExpiresAt, Reserved: t0.Add(time.Minute), Lane: LaneDirect}
	return c, a
}

func TestNewAuditRowRecordsTheTransition(t *testing.T) {
	c, a := reservedPair(t)
	tier := Tier{Class: ClassC3, Severity: SeverityCritical}
	row, err := NewAuditRow(c, a, tier, a.Reserved)
	if err != nil {
		t.Fatal(err)
	}
	want := AuditRow{
		Attempt: a.Attempt, Transition: 2, State: StateReserved, Lane: LaneDirect, At: a.Reserved,
		ExpiresAt: c.ExpiresAt, Kind: KindBlockIP, Target: c.Key.Target, Check: "ssh_brute",
		FindingID: "0123456789abcdef", Roots: c.Roots, Tier: tier,
	}
	if !reflect.DeepEqual(row, want) {
		t.Fatalf("row = %+v\nwant %+v", row, want)
	}
	a.State, a.Disposition, a.Finished = StateVerified, DispositionApplied, t0.Add(2*time.Minute)
	c.State, c.Disposition, c.Transitions = StateVerified, DispositionApplied, 4
	row, err = NewAuditRow(c, a, tier, a.Finished)
	if err != nil || row.State != StateVerified || row.Disposition != DispositionApplied || row.Transition != 4 {
		t.Fatalf("finish row = %+v, %v", row, err)
	}
	// The other candidate matches the attempt in everything but its ID, so
	// only the candidate link can refuse the row.
	other := c
	other.Key.Generation = 2
	if _, err = NewAuditRow(other, a, tier, a.Finished); err == nil {
		t.Fatal("a row joined an attempt to another candidate")
	}
}

func TestAuditRowRoundTripsAndRefusesTampering(t *testing.T) {
	c, a := reservedPair(t)
	row, err := NewAuditRow(c, a, Tier{Class: ClassC2, Severity: SeverityHigh}, a.Reserved)
	if err != nil {
		t.Fatal(err)
	}
	data, err := row.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalAuditRow(data)
	if err != nil || !reflect.DeepEqual(back, row) {
		t.Fatalf("round trip = %+v, %v\nwant %+v", back, err, row)
	}
	body := data[:len(data)-8]
	prefix := []byte(fmt.Sprintf(`{"v":%d,`, auditRowVersion))
	for name, tampered := range map[string][]byte{
		"flipped byte":  func() []byte { d := bytes.Clone(data); d[10] ^= 1; return d }(),
		"unknown field": resealForTest(bytes.Replace(body, prefix, []byte(fmt.Sprintf(`{"v":%d,"x":1,`, auditRowVersion)), 1)),
		"next version":  resealForTest(bytes.Replace(body, prefix, []byte(fmt.Sprintf(`{"v":%d,`, auditRowVersion+1)), 1)),
		"other seq":     resealForTest(bytes.Replace(body, []byte(`"seq":1,`), []byte(`"seq":2,`), 1)),
	} {
		if _, err := UnmarshalAuditRow(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

// A row's acknowledgement names the row and the time it was written.
func TestAuditRowAckNamesItsTime(t *testing.T) {
	c, a := reservedPair(t)
	row, err := NewAuditRow(c, a, Tier{}, a.Reserved)
	if err != nil {
		t.Fatal(err)
	}
	if ack := row.Ack(); ack.ID != row.ID() || !ack.At.Equal(a.Reserved) {
		t.Fatalf("ack = %+v, want %+v at %v", ack, row.ID(), a.Reserved)
	}
}

func TestAuditRowRefusesInconsistentFields(t *testing.T) {
	c, a := reservedPair(t)
	good, err := NewAuditRow(c, a, Tier{}, a.Reserved)
	if err != nil {
		t.Fatalf("an unassessed row was refused: %v", err)
	}
	for name, mutate := range map[string]func(*AuditRow){
		"no transition":       func(r *AuditRow) { r.Transition = 0 },
		"queued state":        func(r *AuditRow) { r.State = StateQueued },
		"open with outcome":   func(r *AuditRow) { r.Disposition = DispositionApplied },
		"outcome without one": func(r *AuditRow) { r.State = StateVerified },
		"no time":             func(r *AuditRow) { r.At = time.Time{} },
		"no expiry":           func(r *AuditRow) { r.ExpiresAt = time.Time{} },
		"unknown lane":        func(r *AuditRow) { r.Lane = laneEnd },
		"kind for a service":  func(r *AuditRow) { r.Kind = KindBlockService },
		"long check":          func(r *AuditRow) { r.Check = strings.Repeat("c", 65) },
		"short finding":       func(r *AuditRow) { r.FindingID = "0123" },
		"no roots":            func(r *AuditRow) { r.Roots = nil },
		"unsorted roots":      func(r *AuditRow) { r.Roots = []EvidenceID{testEvidenceID(2), testEvidenceID(1)} },
		"half a tier":         func(r *AuditRow) { r.Tier = Tier{Class: ClassC1} },
		"attempt past limit": func(r *AuditRow) {
			r.Attempt, _ = NewAttempt(r.Attempt.Candidate, MaxAttempts+1)
			r.Transition = math.MaxUint32
		},
		"relinked attempt": func(r *AuditRow) { r.Attempt.ID = ActionID("act_" + strings.Repeat("0", 32)) },
	} {
		r := good
		r.Roots = append([]EvidenceID(nil), good.Roots...)
		mutate(&r)
		if _, err := r.MarshalBinary(); err == nil {
			t.Errorf("%s: row accepted", name)
		}
	}
}

// The outbox reserves a fixed slot per row, so the widest row the
// invariants allow must fit it.
func TestAuditRowFitsItsSlot(t *testing.T) {
	c := largestCandidate(t)
	id, _ := c.ID()
	third, _ := NewAttempt(id, MaxAttempts)
	far := time.Unix(0, math.MaxInt64).UTC()
	row := AuditRow{
		Attempt: third, Transition: math.MaxUint32, State: StateUnknown, Disposition: DispositionUnknown,
		Lane: LaneCorroborated, At: far, ExpiresAt: far, Kind: c.Key.Kind, Target: c.Key.Target,
		Check: c.Check, FindingID: c.FindingID, Roots: c.Roots, Tier: Tier{Class: ClassC3, Severity: SeverityCritical},
	}
	data, err := row.MarshalBinary()
	if err != nil || len(data) > MaxAuditRowBytes {
		t.Fatalf("largest row: %d bytes (bound %d), %v", len(data), MaxAuditRowBytes, err)
	}
	if AuditSlotBytes != AuditKeyLen+MaxAuditRowBytes || AttemptAuditBytes != AuditStepsPerAttempt*AuditSlotBytes {
		t.Fatal("slot sizes do not add up")
	}
}

func TestAuditKeysOrderAnAttemptsTransitions(t *testing.T) {
	c, a := reservedPair(t)
	row, _ := NewAuditRow(c, a, Tier{}, a.Reserved)
	k := row.Key()
	if id := row.ID(); id != (AuditID{Action: a.Attempt.ID, Transition: 2}) || !bytes.Equal(id.Key(), k) {
		t.Fatalf("id %+v", id)
	}
	if len(k) != AuditKeyLen || !bytes.HasPrefix(k, AuditPrefix(a.Attempt.ID)) {
		t.Fatalf("key %q", k)
	}
	action, transition, err := ParseAuditKey(k)
	if err != nil || action != a.Attempt.ID || transition != 2 {
		t.Fatalf("parse = %s, %d, %v", action, transition, err)
	}
	later := row
	later.Transition = 256
	if bytes.Compare(k, later.Key()) >= 0 {
		t.Fatal("keys do not order by transition")
	}
	for _, bad := range [][]byte{nil, k[:len(k)-1], append([]byte{'b'}, k[1:]...), append(bytes.Clone(k[:len(k)-4]), 0, 0, 0, 0)} {
		if _, _, err := ParseAuditKey(bad); err == nil {
			t.Errorf("malformed key %q parsed", bad)
		}
	}
}

func TestAuditRowSlotIncludesEscapedChecksAndSignedTimes(t *testing.T) {
	c := largestCandidate(t)
	id, err := c.ID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAttempt(id, MaxAttempts)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []string{strings.Repeat("&", 64), strings.Repeat(`"`, 64), strings.Repeat(`\`, 64)} {
		row := AuditRow{
			Attempt: a, Transition: math.MaxUint32, State: StateUnknown, Disposition: DispositionUnknown,
			Lane: LaneCorroborated, At: time.Unix(0, math.MinInt64).UTC(), ExpiresAt: time.Unix(0, math.MinInt64).UTC(),
			Kind: c.Key.Kind, Target: c.Key.Target, Check: check, FindingID: c.FindingID,
			Roots: c.Roots, Tier: Tier{ClassC3, SeverityCritical},
		}
		data, err := row.MarshalBinary()
		if err != nil || len(data) > MaxAuditRowBytes {
			t.Errorf("escaped check %q: %d bytes, bound %d, error %v", check[:1], len(data), MaxAuditRowBytes, err)
			continue
		}
		back, err := UnmarshalAuditRow(data)
		if err != nil || !reflect.DeepEqual(back, row) {
			t.Errorf("escaped check did not round trip: %+v, %v", back, err)
		}
	}
}

func TestAuditRowRejectsImpossibleAttemptTransitions(t *testing.T) {
	c, a := reservedPair(t)
	row, err := NewAuditRow(c, a, Tier{}, a.Reserved)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		state State
		first uint32
	}{
		{StateReserved, 6}, {StateExecuting, 7}, {StateVerified, 8}, {StateFailed, 7}, {StateUnknown, 8}, {StateObserved, 7},
	} {
		r := row
		r.Attempt, err = NewAttempt(a.Attempt.Candidate, MaxAttempts)
		if err != nil {
			t.Fatal(err)
		}
		r.State, r.Disposition, r.Transition = tc.state, 0, tc.first-1
		switch tc.state {
		case StateVerified:
			r.Disposition = DispositionApplied
		case StateFailed:
			r.Disposition = DispositionFailed
		case StateUnknown:
			r.Disposition = DispositionUnknown
		case StateObserved:
			r.Disposition = DispositionObserve
		}
		if _, err := r.MarshalBinary(); err == nil {
			t.Errorf("state %v accepted transition %d before its first possible transition %d", tc.state, r.Transition, tc.first)
		}
		r.Transition = tc.first
		if _, err := r.MarshalBinary(); err != nil {
			t.Errorf("state %v refused its first possible transition %d: %v", tc.state, tc.first, err)
		}
	}
	row.State, row.Disposition, row.Transition = StateVerified, DispositionNarrowed, 4
	if _, err := row.MarshalBinary(); err == nil {
		t.Error("an address block claimed a narrowed outcome")
	}
}

func TestNewAuditRowRejectsAnEarlierAttempt(t *testing.T) {
	c, a := reservedPair(t)
	c.Attempts, c.Transitions = 2, 5
	if _, err := NewAuditRow(c, a, Tier{}, a.Reserved); err == nil {
		t.Fatal("the current transition was attached to an earlier attempt")
	}
}

func TestNewAuditRowRejectsConflictingExpiry(t *testing.T) {
	c, a := reservedPair(t)
	a.ExpiresAt = a.ExpiresAt.Add(time.Second)
	if _, err := NewAuditRow(c, a, Tier{}, a.Reserved); err == nil {
		t.Fatal("the audit row accepted an expiry different from its candidate")
	}
}

func TestAuditRowRejectsUnversionedCheckEncoding(t *testing.T) {
	c, a := reservedPair(t)
	c.Check = "QUJD"
	r, err := NewAuditRow(c, a, Tier{}, a.Reserved)
	if err != nil {
		t.Fatal(err)
	}
	data, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalAuditRow(legacyCheckRecord(t, data)); err != ErrCorruptRecord {
		t.Errorf("accepted a legacy check that aliases a base64 check: %v", err)
	}
}
