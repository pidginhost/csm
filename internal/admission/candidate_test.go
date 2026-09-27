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
// its own decoder would refuse. Each refused case carries the transitions and
// retry timing its state needs, so it fails only on the invariant it names.
func TestCandidateInvariants(t *testing.T) {
	later := t0.Add(time.Hour)
	for _, c := range []struct {
		name   string
		mutate func(*Candidate)
		ok     bool
	}{
		{"queued", func(*Candidate) {}, true},
		{"deferred", func(c *Candidate) { c.Reason, c.Transitions = ReasonCeiling, 2 }, true},
		{"refused", func(c *Candidate) {
			c.State, c.Disposition, c.Reason = StateRefused, DispositionRefused, ReasonProtected
			c.Transitions = 2
		}, true},
		{"reserved", func(c *Candidate) { c.State, c.Attempts, c.ExpiresAt, c.Transitions = StateReserved, 1, later, 2 }, true},
		{"retry wait", func(c *Candidate) {
			c.Attempts, c.ExpiresAt, c.NotBefore, c.Transitions = 1, later, t0.Add(time.Second), 3
		}, true},
		{"failed out", func(c *Candidate) {
			c.State, c.Disposition, c.Attempts, c.ExpiresAt = StateFailed, DispositionFailed, MaxAttempts, later
			c.Transitions = 7
		}, true},
		{"narrowed challenge", func(c *Candidate) {
			c.Key.Kind, c.Scope.Effect = KindChallenge, EffectChallenge
			c.State, c.Disposition, c.Attempts, c.ExpiresAt = StateVerified, DispositionNarrowed, 1, later
			c.Transitions = 4
		}, true},
		{"narrowed full block", func(c *Candidate) {
			c.State, c.Disposition, c.Attempts, c.ExpiresAt = StateVerified, DispositionNarrowed, 1, later
			c.Transitions = 4
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
		{"queued with refusal reason", func(c *Candidate) { c.Reason, c.Transitions = ReasonProtected, 2 }, false},
		{"reserved without attempt", func(c *Candidate) { c.State = StateReserved }, false},
		{"verified without attempt", func(c *Candidate) {
			c.State, c.Disposition, c.Transitions = StateVerified, DispositionApplied, 2
		}, false},
		{"failed early", func(c *Candidate) {
			c.State, c.Disposition, c.Attempts, c.ExpiresAt = StateFailed, DispositionFailed, 2, later
			c.Transitions = 5
		}, false},
		{"too many attempts", func(c *Candidate) {
			c.Attempts, c.ExpiresAt, c.NotBefore, c.Transitions = MaxAttempts+1, later, t0.Add(time.Minute), 9
		}, false},
		{"expiry before reservation", func(c *Candidate) { c.ExpiresAt = later }, false},
		{"reservation without expiry", func(c *Candidate) { c.State, c.Attempts, c.Transitions = StateReserved, 1, 2 }, false},
		{"retry wait while reserved", func(c *Candidate) {
			c.State, c.Attempts, c.ExpiresAt, c.NotBefore, c.Transitions = StateReserved, 1, later, later, 2
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
		{"charged lane", AttemptRecord{Attempt: first, State: StateReserved, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Lane: LaneCorroborated}, true},
		{"unknown lane", AttemptRecord{Attempt: first, State: StateReserved, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Lane: laneEnd}, false},
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

// An attempt stored before the ledger kept a ceiling has no lane field. It
// still decodes, as lane zero, and re-encodes to the same bytes.
func TestAttemptWithoutLaneKeepsItsBytes(t *testing.T) {
	cand, _ := queuedCandidate(t).ID()
	first, _ := NewAttempt(cand, 1)
	legacy, err := sealRecord(struct {
		V         uint8       `json:"v"`
		ID        ActionID    `json:"id"`
		Candidate CandidateID `json:"candidate"`
		Seq       uint32      `json:"seq"`
		State     State       `json:"state"`
		ExpiresAt int64       `json:"expires_at"`
		Reserved  int64       `json:"reserved"`
	}{attemptVersion, first.ID, cand, 1, StateReserved, t0.Add(time.Hour).UnixNano(), t0.UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	a, err := UnmarshalAttempt(legacy)
	if err != nil || a.Lane != 0 || a.Attempt != first {
		t.Fatalf("legacy attempt: %+v %v", a, err)
	}
	if again, err := a.MarshalBinary(); err != nil || !bytes.Equal(again, legacy) {
		t.Fatalf("legacy attempt re-encoded differently: %v", err)
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
		"retry without delay": func(c *Candidate) { c.Attempts, c.ExpiresAt, c.Transitions = 1, t0.Add(time.Hour), 3 },
		"retry after exhaustion": func(c *Candidate) {
			c.Attempts = MaxAttempts
			c.ExpiresAt = t0.Add(time.Hour)
			c.NotBefore = t0.Add(time.Minute)
			c.Transitions = 7
		},
		"retry before queue": func(c *Candidate) {
			c.Attempts = 1
			c.ExpiresAt = t0.Add(time.Hour)
			c.NotBefore = t0.Add(-time.Second)
			c.Transitions = 3
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

func TestCandidateTransitionCountProvesMinimumHistory(t *testing.T) {
	for _, tc := range []struct {
		name        string
		state       State
		disposition Disposition
		reason      Reason
		attempts    uint32
		minimum     uint32
	}{
		{"deferred", StateQueued, 0, ReasonCeiling, 0, 2},
		{"reserved", StateReserved, 0, 0, 1, 2},
		{"executing", StateExecuting, 0, 0, 1, 3},
		{"verified", StateVerified, DispositionApplied, 0, 1, 4},
		{"unknown", StateUnknown, DispositionUnknown, 0, 1, 4},
		{"exhausted", StateFailed, DispositionFailed, 0, MaxAttempts, 7},
		{"retry", StateQueued, 0, 0, 1, 3},
		{"second retry", StateQueued, 0, 0, 2, 5},
		{"deferred retry", StateQueued, 0, ReasonCeiling, 1, 4},
		{"refused", StateRefused, DispositionRefused, ReasonProtected, 0, 2},
		{"withheld", StateWithheld, DispositionWithheld, ReasonCollateral, 0, 2},
		{"dropped", StateDropped, DispositionDropped, ReasonStale, 0, 2},
		{"refused retry", StateRefused, DispositionRefused, ReasonProtected, 1, 4},
		{"later reservation", StateReserved, 0, 0, 2, 4},
		{"later execution", StateExecuting, 0, 0, 2, 5},
		{"later verification", StateVerified, DispositionApplied, 0, 2, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := queuedCandidate(t)
			c.State, c.Disposition, c.Reason = tc.state, tc.disposition, tc.reason
			c.Attempts, c.Transitions = tc.attempts, tc.minimum
			if c.Attempts > 0 {
				c.ExpiresAt = t0.Add(time.Hour)
				if c.State == StateQueued {
					c.NotBefore = t0.Add(10 * time.Second)
				}
			}
			rec, err := c.record()
			if err != nil {
				t.Fatal(err)
			}
			data, err := c.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCandidate(data); err != nil {
				t.Fatalf("minimum history refused: %v", err)
			}
			c.Transitions--
			rec.Transitions--
			assertCandidateRefused(t, c, rec)
		})
	}
}

func TestCandidateCannotTerminateQueueAfterExhaustion(t *testing.T) {
	for _, reason := range []Reason{ReasonProtected, ReasonCollateral, ReasonStale} {
		t.Run(reason.String(), func(t *testing.T) {
			c := queuedCandidate(t)
			c.Disposition, c.Reason = reason.Disposition(), reason
			switch reason {
			case ReasonProtected:
				c.State = StateRefused
			case ReasonCollateral:
				c.State = StateWithheld
			case ReasonStale:
				c.State = StateDropped
			}
			c.Attempts, c.ExpiresAt, c.Transitions = MaxAttempts-1, t0.Add(time.Hour), 10
			rec, err := c.record()
			if err != nil {
				t.Fatalf("termination before exhaustion: %v", err)
			}
			c.Attempts, rec.Attempts = MaxAttempts, MaxAttempts
			assertCandidateRefused(t, c, rec)
		})
	}
}

func TestCandidateRetryTimesRequireElapsedBackoff(t *testing.T) {
	for _, first := range []time.Time{t0, time.Unix(0, -1<<63).UTC(), time.Unix(0, 1<<63-1).UTC().Add(-time.Minute)} {
		for _, field := range []string{"retry", "expiry", "age-out"} {
			t.Run(first.String()+"/"+field, func(t *testing.T) {
				c := queuedCandidate(t)
				c.FirstQueued, c.AgeOut = first, first.Add(time.Minute)
				c.Attempts, c.Transitions = 2, 5
				c.ExpiresAt = first.Add(time.Minute)
				c.NotBefore = first.Add(3 * time.Second)
				if field != "retry" {
					c.State, c.NotBefore = StateReserved, time.Time{}
				}
				rec, err := c.record()
				if err != nil {
					t.Fatal(err)
				}
				switch field {
				case "retry":
					c.NotBefore = c.NotBefore.Add(-time.Nanosecond)
					rec.NotBefore = c.NotBefore.UnixNano()
				case "expiry":
					c.ExpiresAt = first.Add(time.Second)
					rec.ExpiresAt = c.ExpiresAt.UnixNano()
				case "age-out":
					c.AgeOut = first.Add(time.Second)
					rec.AgeOut = c.AgeOut.UnixNano()
				}
				assertCandidateRefused(t, c, rec)
			})
		}
	}
}

func assertCandidateRefused(t *testing.T, c Candidate, rec candidateRecord) {
	t.Helper()
	if err := c.Validate(); refusalReason(err) != ReasonInvalid {
		t.Errorf("invalid candidate validated: %v", err)
	}
	if _, err := c.MarshalBinary(); refusalReason(err) != ReasonInvalid {
		t.Errorf("invalid candidate encoded: %v", err)
	}
	data, err := sealRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalCandidate(data); err != ErrCorruptRecord {
		t.Errorf("invalid stored candidate decoded: %v", err)
	}
}

func TestCandidatePreservesRegisteredEvidenceCheck(t *testing.T) {
	const check = "ssh-brute.v2"
	reg, err := NewRegistry(func(name string) (string, Policy, bool) {
		return name, Policy{Family: FamilySSH, Basis: BasisLocal}, name == check
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(ProducerSpec{ID: "sshd_log", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{check}})
	if err != nil {
		t.Fatal(err)
	}
	reg.Seal()
	in := sshInput(t)
	in.Check = check
	e, err := p.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	if validateErr := reg.Validate(e); validateErr != nil {
		t.Fatal(validateErr)
	}
	c := queuedCandidate(t)
	c.Check, c.Entry, c.FindingID, c.Roots = e.Check(), e.Entry(), e.FindingID(), []EvidenceID{e.ID()}
	c.Key.Target, c.Scope.Owner = e.Target(), e.Owner()
	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatalf("registered evidence cannot become a candidate: %v", err)
	}
	back, err := UnmarshalCandidate(data)
	if err != nil || back.Check != check {
		t.Fatalf("registered check changed on reload: %q, %v", back.Check, err)
	}
}
