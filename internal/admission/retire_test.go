package admission

import (
	"errors"
	"math"
	"testing"
	"time"
)

// unknownPair is a candidate whose first attempt ran and ended unknown.
func unknownPair(t *testing.T) (Candidate, AttemptRecord) {
	t.Helper()
	c, a := reservedPair(t)
	a.State, a.Disposition, a.Finished = StateUnknown, DispositionUnknown, t0.Add(2*time.Minute)
	c.State, c.Disposition, c.Transitions = StateUnknown, DispositionUnknown, 4
	return c, a
}

// Only an unknown attempt can be retired; retiring it keeps its outcome.
func TestAttemptRecordRetiresOnlyAnUnknownOutcome(t *testing.T) {
	_, a := unknownPair(t)
	a.Retired = true
	data, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := UnmarshalAttempt(data); err != nil || got != a {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	for name, mutate := range map[string]func(*AttemptRecord){
		"verified": func(r *AttemptRecord) { r.State, r.Disposition = StateVerified, DispositionApplied },
		"failed":   func(r *AttemptRecord) { r.State, r.Disposition = StateFailed, DispositionFailed },
		"observed": func(r *AttemptRecord) { r.State, r.Disposition = StateObserved, DispositionObserve },
		"running":  func(r *AttemptRecord) { r.State, r.Disposition, r.Finished = StateExecuting, 0, time.Time{} },
	} {
		r := a
		mutate(&r)
		wantReason(t, name, r.Validate(), ReasonInvalid)
	}
}

// The retirement row is a linked event on an unknown attempt: its state
// stays unknown, its disposition names the event, and it follows the
// outcome by at least one transition. No candidate, attempt or outcome
// count carries that disposition.
func TestAuditRowRecordsExpiredUnproven(t *testing.T) {
	if DispositionExpiredUnproven.String() != "expired_unproven" {
		t.Fatalf("name = %q", DispositionExpiredUnproven)
	}
	c, a := unknownPair(t)
	a.Retired = true
	c.Transitions = 5
	marker := a
	marker.Disposition = DispositionExpiredUnproven
	row, err := NewAuditRow(c, marker, Tier{}, c.ExpiresAt)
	if err != nil || row.State != StateUnknown || row.Disposition != DispositionExpiredUnproven || row.Transition != 5 {
		t.Fatalf("row = %+v, %v", row, err)
	}
	data, err := row.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got, decodeErr := UnmarshalAuditRow(data); decodeErr != nil || got.Disposition != DispositionExpiredUnproven || got.Transition != 5 {
		t.Fatalf("round trip = %+v, %v", got, decodeErr)
	}
	early := c
	early.Transitions = 4
	if _, err = NewAuditRow(early, marker, Tier{}, c.ExpiresAt); err == nil {
		t.Fatal("a retirement row shared the outcome's transition")
	}
	verified := marker
	verified.State = StateVerified
	if _, err = NewAuditRow(c, verified, Tier{}, c.ExpiresAt); err == nil {
		t.Fatal("a verified attempt carried a retirement row")
	}
	cand := c
	cand.Disposition = DispositionExpiredUnproven
	wantReason(t, "candidate", cand.Validate(), ReasonInvalid)
	wantReason(t, "attempt", marker.Validate(), ReasonInvalid)
	if AttemptOutcome(DispositionExpiredUnproven, Tier{}).Valid() {
		t.Fatal("retirement counted as an attempt outcome")
	}
}

// Retiring an unknown outcome returns its history to its allowances and
// releases its intent from the recovery reserve: the inverse of pinning.
func TestStorageUnpinsARetiredOutcome(t *testing.T) {
	s := NewStorageState()
	s.General.Used, s.Reserved.Used = 5000, 3000
	pinned, err := s.PinHistory(2000, 1000)
	if err == nil {
		pinned, err = pinned.HoldIntent()
	}
	if err != nil {
		t.Fatal(err)
	}
	back, err := pinned.UnpinHistory(2000, 1000)
	if err != nil || back != s {
		t.Fatalf("unpin = %+v, %v; want %+v", back, err, s)
	}
	short := pinned
	short.Recovery--
	if got, err := short.UnpinHistory(2000, 1000); !errors.Is(err, ErrCorruptRecord) || got != short {
		t.Fatalf("unpin beyond the reserve = %+v, %v", got, err)
	}
	full := pinned
	full.General.Used = math.MaxUint64 - 1999
	if got, err := full.UnpinHistory(2000, 1000); !errors.Is(err, ErrCorruptRecord) || got != full {
		t.Fatalf("unpin overflowing an allowance = %+v, %v", got, err)
	}
	full = pinned
	full.Reserved.Used = math.MaxUint64 - 999
	if got, err := full.UnpinHistory(2000, 1000); !errors.Is(err, ErrCorruptRecord) || got != full {
		t.Fatalf("unpin overflowing the reserved allowance = %+v, %v", got, err)
	}
}
