package admission

import (
	"bytes"
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
	other := queuedCandidate(t)
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
	for name, tampered := range map[string][]byte{
		"flipped byte":  func() []byte { d := bytes.Clone(data); d[10] ^= 1; return d }(),
		"unknown field": resealForTest(bytes.Replace(body, []byte(`{"v":1,`), []byte(`{"v":1,"x":1,`), 1)),
		"version 2":     resealForTest(bytes.Replace(body, []byte(`{"v":1,`), []byte(`{"v":2,`), 1)),
		"other seq":     resealForTest(bytes.Replace(body, []byte(`"seq":1,`), []byte(`"seq":2,`), 1)),
	} {
		if _, err := UnmarshalAuditRow(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
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
		"attempt past limit":  func(r *AuditRow) { r.Attempt, _ = NewAttempt(r.Attempt.Candidate, MaxAttempts+1) },
		"relinked attempt":    func(r *AuditRow) { r.Attempt.ID = ActionID("act_" + strings.Repeat("0", 32)) },
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
