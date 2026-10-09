package admission

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func testActionID(t *testing.T, n byte) ActionID {
	t.Helper()
	a, err := NewAttempt(testCandidateID(t, n), 1)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func testIntent(t *testing.T) Intent {
	t.Helper()
	target, err := ParseTargetKey("ip:192.0.2.1", v6)
	if err != nil {
		t.Fatal(err)
	}
	action := testActionID(t, 1)
	batch, err := NewBatchID([]ActionID{action})
	if err != nil {
		t.Fatal(err)
	}
	return Intent{Action: action, Batch: batch, Kind: KindBlockIP, Target: target, ExpiresAt: time.Unix(1_800_000_000, 0).UTC()}
}

// A batch is named by its members, never by their order, so a repeated
// execution of the same members names the same batch.
func TestBatchIDIsDerivedFromItsMembers(t *testing.T) {
	a, b, c := testActionID(t, 1), testActionID(t, 2), testActionID(t, 3)
	ab, err := NewBatchID([]ActionID{a, b})
	if err != nil {
		t.Fatal(err)
	}
	ba, err := NewBatchID([]ActionID{b, a})
	if err != nil || ba != ab {
		t.Fatalf("member order changed the batch: %s %s %v", ab, ba, err)
	}
	if abc, _ := NewBatchID([]ActionID{a, b, c}); abc == ab {
		t.Fatal("another member set named the same batch")
	}
	if !strings.HasPrefix(string(ab), "bat_") || len(ab) != len("bat_")+32 {
		t.Fatalf("batch ID %q is not bat_ and 32 hex digits", ab)
	}
	if got, parseErr := ParseBatchID(string(ab)); parseErr != nil || got != ab {
		t.Fatalf("ParseBatchID(%q) = %q %v", ab, got, parseErr)
	}
	distinct := make([]ActionID, 0, MaxBatchMembers+1)
	for i := 0; i <= MaxBatchMembers; i++ {
		id, idErr := NewAttempt(testCandidateID(t, byte(i%16)), uint32(1+i/16))
		if idErr != nil {
			t.Fatal(idErr)
		}
		distinct = append(distinct, id.ID)
	}
	for name, members := range map[string][]ActionID{
		"empty":     nil,
		"repeated":  {a, a},
		"malformed": {a, "act_x"},
		"too many":  distinct,
	} {
		_, batchErr := NewBatchID(members)
		wantReason(t, name, batchErr, ReasonInvalid)
	}
	if _, err = NewBatchID(distinct[:MaxBatchMembers]); err != nil {
		t.Fatalf("a full batch was refused: %v", err)
	}
	for _, s := range []string{"", "bat_", "bat_" + strings.Repeat("A", 32), "act_" + strings.Repeat("a", 32), "bat_" + strings.Repeat("a", 31)} {
		_, err := ParseBatchID(s)
		wantReason(t, "ParseBatchID("+s+")", err, ReasonInvalid)
	}
}

func TestIntentRoundTrips(t *testing.T) {
	in := testIntent(t)
	data, err := in.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalIntent(data)
	if err != nil || out != in {
		t.Fatalf("round trip = %+v %v, want %+v", out, err, in)
	}
	data[0] ^= 1
	if _, err = UnmarshalIntent(data); err != ErrCorruptRecord {
		t.Fatalf("a damaged intent decoded: %v", err)
	}
	rec, err := in.record()
	if err != nil {
		t.Fatal(err)
	}
	future, mismatched := rec, rec
	future.V = intentVersion + 1
	mismatched.Kind = KindBlockSubnet
	for name, r := range map[string]intentRecord{"future version": future, "kind and target disagree": mismatched} {
		sealed, sealErr := sealRecord(r)
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		if _, err = UnmarshalIntent(sealed); err != ErrCorruptRecord {
			t.Errorf("%s: decoded with %v", name, err)
		}
	}
}

func TestIntentRefusesMalformedFields(t *testing.T) {
	subnet, err := ParseTargetKey("net:198.51.100.0/24", v6)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Intent){
		"action":        func(in *Intent) { in.Action = "act_x" },
		"batch":         func(in *Intent) { in.Batch = "bat_x" },
		"kind":          func(in *Intent) { in.Kind = kindEnd },
		"kind target":   func(in *Intent) { in.Target = subnet },
		"no target":     func(in *Intent) { in.Target = Target{} },
		"no expiry":     func(in *Intent) { in.ExpiresAt = time.Time{} },
		"before epoch":  func(in *Intent) { in.ExpiresAt = time.Unix(-1, 0).UTC() },
		"unrepresented": func(in *Intent) { in.ExpiresAt = time.Unix(0, math.MaxInt64).Add(time.Second) },
	} {
		in := testIntent(t)
		mutate(&in)
		_, err := in.MarshalBinary()
		wantReason(t, name, err, ReasonInvalid)
	}
}

func TestStoredIntentFitsItsBound(t *testing.T) {
	in := testIntent(t)
	target, err := ParseTargetKey("svc:2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/udp/65535", v6)
	if err != nil {
		t.Fatal(err)
	}
	in.Kind, in.Target, in.ExpiresAt = KindBlockService, target, time.Unix(0, math.MaxInt64).UTC()
	data, err := in.MarshalBinary()
	if err != nil || len(data) > MaxIntentBytes {
		t.Fatalf("widest intent: %d bytes (bound %d), %v", len(data), MaxIntentBytes, err)
	}
}

// A reservation needs room for the intent its attempt may keep and the row
// that retires an unknown outcome, and an unknown outcome holds the intent's
// room in the recovery reserve.
func TestRecoveryHoldsRoomForTheIntent(t *testing.T) {
	if UnknownHoldBytes != AuditSlotBytes+MaxIntentBytes || AttemptRecoveryBytes != AttemptAuditBytes+UnknownHoldBytes ||
		MaxRecoveryNeed != MaxHistoryBytes+AttemptRecoveryBytes {
		t.Fatalf("recovery needs = %d, %d", AttemptRecoveryBytes, MaxRecoveryNeed)
	}
	s := NewStorageState()
	s.Recovery = 3000
	held, err := s.HoldIntent()
	if err != nil || held.Recovery != 3000+MaxIntentBytes {
		t.Fatalf("hold = %+v, %v", held, err)
	}
	full := s
	full.Recovery = math.MaxUint64 - MaxIntentBytes + 1
	if got, err := full.HoldIntent(); !errors.Is(err, ErrCorruptRecord) || got != full {
		t.Fatalf("overflowing hold = %+v, %v", got, err)
	}
	full.Recovery--
	if got, err := full.HoldIntent(); err != nil || got.Recovery != math.MaxUint64 {
		t.Fatalf("representable hold = %+v, %v", got, err)
	}
}
