package admission

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testEvidenceID(n byte) EvidenceID {
	return EvidenceID("ev_" + strings.Repeat(string("0123456789abcdef"[n%16]), 32))
}

// queuedCandidate is a valid queued candidate for alice's address scope.
func queuedCandidate(t *testing.T) Candidate {
	t.Helper()
	owner := testInventory(t).Resolve(Claim{Kind: ClaimAccount, Value: "alice"})
	return Candidate{
		Key: CandidateKey{
			Kind: KindBlockIP, Target: mustAddr(t, "192.0.2.10"),
			Episode: testEpisode(t, "00000000000000000000000000000001"), Generation: 1,
		},
		Scope:       Scope{Owner: owner, Effect: EffectAddress},
		Entry:       EntryScan,
		Check:       "ssh_brute",
		FindingID:   "0123456789abcdef",
		Roots:       []EvidenceID{testEvidenceID(1), testEvidenceID(2)},
		FirstQueued: t0,
		AgeOut:      t0.Add(90 * time.Minute),
		State:       StateQueued,
		Transitions: 1,
	}
}

func TestCandidateRoundTripsAndRefusesTampering(t *testing.T) {
	c := queuedCandidate(t)
	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalCandidate(data)
	if err != nil || !reflect.DeepEqual(back, c) {
		t.Fatalf("round trip = %+v, %v\nwant %+v", back, err, c)
	}
	if id, _ := back.ID(); id == "" {
		t.Fatal("decoded candidate has no ID")
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":  func() []byte { d := bytes.Clone(data); d[10] ^= 1; return d }(),
		"unknown field": resealForTest(bytes.Replace(body, []byte(`{"v":1,`), []byte(`{"v":1,"x":1,`), 1)),
		"non-canonical": resealForTest(bytes.Replace(body, []byte(`{"v":1,`), []byte(`{ "v":1,`), 1)),
		"version 2":     resealForTest(bytes.Replace(body, []byte(`{"v":1,`), []byte(`{"v":2,`), 1)),
		"mapped target": resealForTest(bytes.Replace(body, []byte(`"ip:192.0.2.10"`), []byte(`"ip:::ffff:192.0.2.10"`), 1)),
		"host with generation": resealForTest(bytes.Replace(body,
			[]byte(`"owner_account":"alice","owner_generation":1`), []byte(`"owner_generation":1`), 1)),
		"leading padding": append(bytes.Repeat([]byte(" "), 16), data...),
	} {
		if _, err := UnmarshalCandidate(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

// Every invariant is checked on encode, so the ledger cannot write a record
// its own decoder would refuse.
func TestCandidateInvariants(t *testing.T) {
	later := t0.Add(time.Hour)
	for _, c := range []struct {
		name   string
		mutate func(*Candidate)
		ok     bool
	}{
		{"queued", func(*Candidate) {}, true},
		{"deferred", func(c *Candidate) { c.Reason = ReasonCeiling }, true},
		{"refused", func(c *Candidate) {
			c.State, c.Disposition, c.Reason = StateRefused, DispositionRefused, ReasonProtected
		}, true},
		{"reserved", func(c *Candidate) { c.State, c.Attempts, c.ExpiresAt = StateReserved, 1, later }, true},
		{"retry wait", func(c *Candidate) { c.Attempts, c.ExpiresAt, c.NotBefore = 1, later, t0.Add(time.Second) }, true},
		{"failed out", func(c *Candidate) {
			c.State, c.Disposition, c.Attempts, c.ExpiresAt = StateFailed, DispositionFailed, MaxAttempts, later
		}, true},
		{"narrowed challenge", func(c *Candidate) {
			c.Key.Kind, c.Scope.Effect = KindChallenge, EffectChallenge
			c.State, c.Disposition, c.Attempts, c.ExpiresAt = StateVerified, DispositionNarrowed, 1, later
		}, true},
		{"narrowed full block", func(c *Candidate) {
			c.State, c.Disposition, c.Attempts, c.ExpiresAt = StateVerified, DispositionNarrowed, 1, later
		}, false},
		{"scope family", func(c *Candidate) { c.Scope.Effect = EffectPrefix }, false},
		{"no roots", func(c *Candidate) { c.Roots = nil }, false},
		{"unsorted roots", func(c *Candidate) { c.Roots = []EvidenceID{testEvidenceID(2), testEvidenceID(1)} }, false},
		{"repeated root", func(c *Candidate) { c.Roots = []EvidenceID{testEvidenceID(1), testEvidenceID(1)} }, false},
		{"too many roots", func(c *Candidate) {
			c.Roots = nil
			for i := 0; i <= MaxRoots; i++ {
				c.Roots = append(c.Roots, EvidenceID("ev_"+strings.Repeat("0", 30)+string("0123456789abcdef"[i/16])+string("0123456789abcdef"[i%16])))
			}
		}, false},
		{"malformed root", func(c *Candidate) { c.Roots = []EvidenceID{"ev_x"} }, false},
		{"bad finding link", func(c *Candidate) { c.FindingID = "0123456789ABCDEF" }, false},
		{"bad check", func(c *Candidate) { c.Check = "SSH brute" }, false},
		{"age-out past limit", func(c *Candidate) { c.AgeOut = t0.Add(QueueAgeLimit + time.Second) }, false},
		{"age-out before queued", func(c *Candidate) { c.AgeOut = t0 }, false},
		{"queued with refusal reason", func(c *Candidate) { c.Reason = ReasonProtected }, false},
		{"reserved without attempt", func(c *Candidate) { c.State = StateReserved }, false},
		{"failed early", func(c *Candidate) {
			c.State, c.Disposition, c.Attempts, c.ExpiresAt = StateFailed, DispositionFailed, 2, later
		}, false},
		{"too many attempts", func(c *Candidate) { c.Attempts, c.ExpiresAt = MaxAttempts+1, later }, false},
		{"expiry before reservation", func(c *Candidate) { c.ExpiresAt = later }, false},
		{"reservation without expiry", func(c *Candidate) { c.State, c.Attempts = StateReserved, 1 }, false},
		{"retry wait while reserved", func(c *Candidate) {
			c.State, c.Attempts, c.ExpiresAt, c.NotBefore = StateReserved, 1, later, later
		}, false},
		{"retry wait without attempt", func(c *Candidate) { c.NotBefore = later }, false},
		{"no transition", func(c *Candidate) { c.Transitions = 0 }, false},
	} {
		cand := queuedCandidate(t)
		c.mutate(&cand)
		err := cand.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: Validate() = %v, want ok %v", c.name, err, c.ok)
		}
		if !c.ok {
			wantReason(t, c.name, err, ReasonInvalid)
		} else {
			data, encodeErr := cand.MarshalBinary()
			back, decodeErr := UnmarshalCandidate(data)
			if encodeErr != nil || decodeErr != nil || !reflect.DeepEqual(back, cand) {
				t.Errorf("%s: encode/decode mismatch: %v %v", c.name, encodeErr, decodeErr)
			}
		}
	}
}

// The largest candidate the invariants allow fits MaxCandidateBytes with room
// to spare, so storage accounting can reserve that bound per candidate.
func TestCandidateLargestFitsItsBound(t *testing.T) {
	c := queuedCandidate(t)
	c.Key.Kind, c.Scope.Effect = KindBlockService, EffectService
	c.Key.Target = mustService(t, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "tcp", 65535)
	c.Check = strings.Repeat("c", 64)
	c.Roots = nil
	for i := 0; i < MaxRoots; i++ {
		c.Roots = append(c.Roots, EvidenceID("ev_"+strings.Repeat("f", 30)+string("0123456789abcdef"[i/16])+string("0123456789abcdef"[i%16])))
	}
	c.State, c.Disposition, c.Attempts = StateFailed, DispositionFailed, MaxAttempts
	c.ExpiresAt, c.Transitions = t0.Add(24*time.Hour), ^uint32(0)
	data, err := c.MarshalBinary()
	if err != nil || len(data) > MaxCandidateBytes/2 {
		t.Fatalf("largest candidate: %d bytes, %v", len(data), err)
	}
}

func TestAttemptRecordInvariants(t *testing.T) {
	cand, _ := queuedCandidate(t).ID()
	first, _ := NewAttempt(cand, 1)
	second, _ := NewAttempt(cand, 2)
	finished := t0.Add(time.Minute)
	for _, c := range []struct {
		name string
		rec  AttemptRecord
		ok   bool
	}{
		{"reserved", AttemptRecord{Attempt: first, State: StateReserved, ExpiresAt: t0.Add(time.Hour), Reserved: t0}, true},
		{"executing", AttemptRecord{Attempt: second, State: StateExecuting, ExpiresAt: t0.Add(time.Hour), Reserved: t0}, true},
		{"verified", AttemptRecord{Attempt: first, State: StateVerified, Disposition: DispositionApplied, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Finished: finished}, true},
		{"failed", AttemptRecord{Attempt: first, State: StateFailed, Disposition: DispositionFailed, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Finished: t0}, true},
		{"unknown", AttemptRecord{Attempt: first, State: StateUnknown, Disposition: DispositionUnknown, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Finished: finished}, true},
		{"queued is not a phase", AttemptRecord{Attempt: first, State: StateQueued, ExpiresAt: t0.Add(time.Hour), Reserved: t0}, false},
		{"outcome without finish", AttemptRecord{Attempt: first, State: StateVerified, Disposition: DispositionApplied, ExpiresAt: t0.Add(time.Hour), Reserved: t0}, false},
		{"open with finish", AttemptRecord{Attempt: first, State: StateExecuting, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Finished: finished}, false},
		{"finished before reserved", AttemptRecord{Attempt: first, State: StateFailed, Disposition: DispositionFailed, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Finished: t0.Add(-time.Second)}, false},
		{"expiry at reservation", AttemptRecord{Attempt: first, State: StateReserved, ExpiresAt: t0, Reserved: t0}, false},
		{"wrong disposition", AttemptRecord{Attempt: first, State: StateUnknown, Disposition: DispositionFailed, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Finished: finished}, false},
		{"relinked", AttemptRecord{Attempt: Attempt{ID: first.ID, Candidate: cand, Seq: 2, Prev: first.ID}, State: StateReserved, ExpiresAt: t0.Add(time.Hour), Reserved: t0}, false},
	} {
		err := c.rec.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: Validate() = %v, want ok %v", c.name, err, c.ok)
			continue
		}
		if !c.ok {
			continue
		}
		data, err := c.rec.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if back, err := UnmarshalAttempt(data); err != nil || back != c.rec {
			t.Errorf("%s: round trip = %+v, %v", c.name, back, err)
		}
		if _, err := UnmarshalAttempt(resealForTest(bytes.Replace(data[:len(data)-8], []byte(`"v":1`), []byte(`"v":9`), 1))); err != ErrCorruptRecord {
			t.Errorf("%s: unknown version decoded: %v", c.name, err)
		}
	}
}

func TestRetryBackoff(t *testing.T) {
	for seq, want := range map[uint32]time.Duration{0: 0, 1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 6: 32 * time.Second, 7: time.Minute, 200: time.Minute} {
		if got := RetryBackoff(seq); got != want {
			t.Errorf("RetryBackoff(%d) = %v, want %v", seq, got, want)
		}
	}
}

func TestParseEvidenceID(t *testing.T) {
	if _, err := ParseEvidenceID(string(testEvidenceID(3))); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "ev_", "ev_" + strings.Repeat("A", 32), "ev_" + strings.Repeat("0", 31), "cand_" + strings.Repeat("0", 32)} {
		if _, err := ParseEvidenceID(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestCandidateAndAttemptRejectUnrecoverableRecords(t *testing.T) {
	for name, mutate := range map[string]func(*Candidate){
		"epoch queue":         func(c *Candidate) { c.FirstQueued = time.Unix(0, 0); c.AgeOut = c.FirstQueued.Add(time.Hour) },
		"retry without delay": func(c *Candidate) { c.Attempts = 1; c.ExpiresAt = t0.Add(time.Hour) },
		"retry after exhaustion": func(c *Candidate) {
			c.Attempts = MaxAttempts
			c.ExpiresAt = t0.Add(time.Hour)
			c.NotBefore = t0.Add(time.Second)
		},
		"retry before queue": func(c *Candidate) {
			c.Attempts = 1
			c.ExpiresAt = t0.Add(time.Hour)
			c.NotBefore = t0.Add(-time.Second)
		},
	} {
		c := queuedCandidate(t)
		mutate(&c)
		if _, err := c.MarshalBinary(); refusalReason(err) != ReasonInvalid {
			t.Errorf("%s encoded: %v", name, err)
		}
	}
	id, _ := queuedCandidate(t).ID()
	a, _ := NewAttempt(id, MaxAttempts+1)
	rec := AttemptRecord{Attempt: a, State: StateReserved, Reserved: t0, ExpiresAt: t0.Add(time.Hour)}
	if _, err := rec.MarshalBinary(); refusalReason(err) != ReasonInvalid {
		t.Fatalf("excess attempt encoded: %v", err)
	}
	a, _ = NewAttempt(id, 1)
	rec.Attempt, rec.Reserved = a, time.Unix(0, 0)
	if _, err := rec.MarshalBinary(); refusalReason(err) != ReasonInvalid {
		t.Fatalf("epoch reservation encoded: %v", err)
	}
}
