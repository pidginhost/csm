package admission

import (
	"bytes"
	"math"
	"sort"
	"strings"
	"time"
)

// QueueAgeLimit is the longest a candidate waits. It ages out at
// min(FirstQueued+QueueAgeLimit, evidence expiry); a duplicate report never
// extends that.
const QueueAgeLimit = 2 * time.Hour

// MaxCandidateBytes bounds one encoded candidate record (spec 5.4). Storage
// accounting reserves it per candidate; the invariants keep every valid
// record well inside it.
const MaxCandidateBytes = 4096

// MaxAttempts is how many proven-failure attempts one candidate generation
// may make. An unknown outcome is never retried.
const MaxAttempts = 3

// maxRetryBackoff caps the wait before a failed attempt is retried.
const maxRetryBackoff = time.Minute

const candidateVersion = 1
const attemptVersion = 1

// RetryBackoff is the wait after the proven failure of attempt seq: one
// second, doubling, capped at a minute.
func RetryBackoff(seq uint32) time.Duration {
	if seq == 0 {
		return 0
	}
	if seq > 7 {
		return maxRetryBackoff
	}
	return min(time.Second<<(seq-1), maxRetryBackoff)
}

// ParseEvidenceID accepts only the derived form.
func ParseEvidenceID(s string) (EvidenceID, error) {
	rest, ok := strings.CutPrefix(s, "ev_")
	if !ok || !lowerHex(rest, 32) {
		return "", refuse(ReasonInvalid, "malformed evidence ID")
	}
	return EvidenceID(s), nil
}

// Candidate is the ledger's record of one queued response. The engine owns
// it; every field is checked on encode and decode. These local invariants
// bound possible histories; the ledger also checks the actual attempt rows.
type Candidate struct {
	Key   CandidateKey
	Scope Scope
	// Entry, Check and FindingID come from the primary root evidence.
	Entry     Entry
	Check     string
	FindingID string
	// Roots are the validated root evidence IDs, sorted and unique.
	Roots       []EvidenceID
	FirstQueued time.Time
	AgeOut      time.Time
	State       State
	// Reason is a deferral reason while queued, or the reason a queued
	// candidate was refused, withheld or dropped.
	Reason      Reason
	Disposition Disposition
	// Attempts is the sequence of the latest attempt; zero before the
	// first reservation.
	Attempts uint32
	// ExpiresAt is the absolute effect expiry fixed by the first
	// reservation. Retries keep it.
	ExpiresAt time.Time
	// NotBefore is when a candidate returned by a proven failure may be
	// reserved again.
	NotBefore time.Time
	// Transitions counts recorded changes; (ID, Transitions) keys an
	// idempotent audit event.
	Transitions uint32
}

// ID derives the candidate ID from its key.
func (c Candidate) ID() (CandidateID, error) { return c.Key.ID() }

type candidateRecord struct {
	V               uint8        `json:"v"`
	Kind            Kind         `json:"kind"`
	Target          string       `json:"target"`
	Episode         string       `json:"episode"`
	Generation      uint32       `json:"generation"`
	OwnerAccount    string       `json:"owner_account,omitempty"`
	OwnerGeneration uint64       `json:"owner_generation,omitempty"`
	Effect          Effect       `json:"effect"`
	Entry           Entry        `json:"entry"`
	Check           string       `json:"check"`
	FindingID       string       `json:"finding_id"`
	Roots           []EvidenceID `json:"roots"`
	FirstQueued     int64        `json:"first_queued"`
	AgeOut          int64        `json:"age_out"`
	State           State        `json:"state"`
	Reason          Reason       `json:"reason,omitempty"`
	Disposition     Disposition  `json:"disposition,omitempty"`
	Attempts        uint32       `json:"attempts,omitempty"`
	ExpiresAt       int64        `json:"expires_at,omitempty"`
	NotBefore       int64        `json:"not_before,omitempty"`
	Transitions     uint32       `json:"transitions"`
}

// Validate checks the record's invariants.
func (c Candidate) Validate() error {
	_, err := c.record()
	return err
}

func (c Candidate) record() (candidateRecord, error) {
	bad := func(detail string) (candidateRecord, error) {
		return candidateRecord{}, refuse(ReasonInvalid, detail)
	}
	if _, err := c.Key.ID(); err != nil {
		return candidateRecord{}, err
	}
	if c.Scope.Effect != c.Key.Kind.Effect() {
		return bad("candidate scope is not its kind's action family")
	}
	if o := c.Scope.Owner; (o.IsHost() && o.generation != 0) || (!o.IsHost() && (!ValidAccountName(o.account) || o.generation == 0)) {
		return bad("candidate owner is malformed")
	}
	if !c.Entry.Valid() || !boundedToken(c.Check, 64) || !lowerHex(c.FindingID, 16) {
		return bad("candidate entry, check or finding link is malformed")
	}
	if len(c.Roots) == 0 || len(c.Roots) > MaxRoots || !sort.SliceIsSorted(c.Roots, func(i, j int) bool { return c.Roots[i] < c.Roots[j] }) {
		return bad("candidate roots are empty, too many or unsorted")
	}
	for i, id := range c.Roots {
		if _, err := ParseEvidenceID(string(id)); err != nil || (i > 0 && c.Roots[i-1] == id) {
			return bad("candidate roots are malformed or repeated")
		}
	}
	first, okFirst := unixNano(c.FirstQueued)
	ageOut, okAge := unixNano(c.AgeOut)
	if !okFirst || !okAge || !c.AgeOut.After(c.FirstQueued) || c.AgeOut.After(c.FirstQueued.Add(QueueAgeLimit)) {
		return bad("candidate queue times are inconsistent")
	}
	if !c.State.Valid() || !terminalDisposition(c.State, c.Disposition) || !stateReason(c.State, c.Reason) {
		return bad("candidate state, disposition and reason disagree")
	}
	if c.Disposition == DispositionNarrowed && c.Key.Kind != KindChallenge && c.Key.Kind != KindBlockService {
		return bad("only a challenge or service block narrows")
	}
	switch {
	case c.Attempts > MaxAttempts:
		return bad("candidate exceeds its attempts")
	case c.Attempts == 0 && c.State != StateQueued && !c.State.Terminal():
		return bad("candidate is past the queue without an attempt")
	case c.Attempts == 0 && (c.State == StateVerified || c.State == StateFailed || c.State == StateUnknown || c.State == StateObserved):
		return bad("candidate has an outcome without an attempt")
	case c.State == StateFailed && c.Attempts != MaxAttempts:
		return bad("candidate failed before exhausting its attempts")
	case c.State == StateQueued && c.Attempts > 0 && (c.Attempts == MaxAttempts || c.NotBefore.IsZero()):
		return bad("queued retry has no delay or has exhausted its attempts")
	case c.Attempts == MaxAttempts && (c.State == StateRefused || c.State == StateWithheld || c.State == StateDropped):
		return bad("exhausted candidate cannot end through the queue")
	}
	// Even immediate failures must wait out each preceding retry backoff.
	// Use time arithmetic so a deadline near the nanosecond limit cannot wrap.
	earliestReservation := c.FirstQueued
	for seq := uint32(1); seq < c.Attempts; seq++ {
		earliestReservation = earliestReservation.Add(RetryBackoff(seq))
	}
	var expires, notBefore int64
	if c.Attempts == 0 {
		if !c.ExpiresAt.IsZero() {
			return bad("candidate has an expiry before its first reservation")
		}
	} else {
		var ok bool
		if expires, ok = unixNano(c.ExpiresAt); !ok || !c.ExpiresAt.After(earliestReservation) || !c.AgeOut.After(earliestReservation) {
			return bad("candidate deadlines cannot accommodate its attempts")
		}
	}
	if !c.NotBefore.IsZero() {
		var ok bool
		if notBefore, ok = unixNano(c.NotBefore); !ok || c.State != StateQueued || c.Attempts == 0 || c.NotBefore.Before(earliestReservation.Add(RetryBackoff(c.Attempts))) {
			return bad("only a candidate returned by a failure waits for a retry time")
		}
	}
	// Creation counts once; every preceding attempt needs a reservation and
	// a failed outcome. Execute is optional only for a proven failure.
	minimumTransitions := 1 + 2*c.Attempts
	switch c.State {
	case StateReserved:
		minimumTransitions--
	case StateVerified, StateUnknown, StateRefused, StateWithheld, StateDropped:
		minimumTransitions++
	case StateQueued:
		if c.Reason != 0 {
			minimumTransitions++
		}
	}
	if c.Transitions < minimumTransitions {
		return bad("candidate has too few transitions for its state and attempts")
	}
	return candidateRecord{
		V: candidateVersion, Kind: c.Key.Kind, Target: c.Key.Target.Key(), Episode: c.Key.Episode.String(),
		Generation: c.Key.Generation, OwnerAccount: c.Scope.Owner.account, OwnerGeneration: c.Scope.Owner.generation,
		Effect: c.Scope.Effect, Entry: c.Entry, Check: c.Check, FindingID: c.FindingID, Roots: c.Roots,
		FirstQueued: first, AgeOut: ageOut, State: c.State, Reason: c.Reason, Disposition: c.Disposition,
		Attempts: c.Attempts, ExpiresAt: expires, NotBefore: notBefore, Transitions: c.Transitions,
	}, nil
}

// MarshalBinary validates and encodes c. The invariants keep every valid
// candidate well inside MaxCandidateBytes; the decoder repeats the same
// invariants on what it reads back.
func (c Candidate) MarshalBinary() ([]byte, error) {
	rec, err := c.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// MaxBytes is the largest encoding c can reach while its identity, scope,
// roots and queue times stay as they are: its state, reason, outcome,
// attempts, deadlines and transition count at their widest. Storage
// accounting reserves it for a candidate whose roots are fixed.
func (c Candidate) MaxBytes() (int, error) {
	rec, err := c.record()
	if err != nil {
		return 0, err
	}
	rec.State, rec.Reason, rec.Disposition = stateEnd-1, reasonEnd-1, dispositionEnd-1
	rec.Attempts, rec.ExpiresAt, rec.NotBefore, rec.Transitions = MaxAttempts, math.MaxInt64, math.MaxInt64, math.MaxUint32
	data, err := sealRecord(rec)
	return len(data), err
}

// UnmarshalCandidate decodes a stored candidate and checks its invariants.
func UnmarshalCandidate(data []byte) (Candidate, error) {
	var rec candidateRecord
	if err := openRecord(data, &rec); err != nil {
		return Candidate{}, err
	}
	if rec.V != candidateVersion || rec.Roots == nil {
		return Candidate{}, ErrCorruptRecord
	}
	target, err := ParseTargetKey(rec.Target, Caps{IPv6: true})
	if err != nil {
		return Candidate{}, ErrCorruptRecord
	}
	episode, err := ParseEpisodeID(rec.Episode)
	if err != nil {
		return Candidate{}, ErrCorruptRecord
	}
	c := Candidate{
		Key:   CandidateKey{Kind: rec.Kind, Target: target, Episode: episode, Generation: rec.Generation},
		Scope: Scope{Owner: Owner{account: rec.OwnerAccount, generation: rec.OwnerGeneration}, Effect: rec.Effect},
		Entry: rec.Entry, Check: rec.Check, FindingID: rec.FindingID, Roots: rec.Roots,
		FirstQueued: fromNano(rec.FirstQueued), AgeOut: fromNano(rec.AgeOut), State: rec.State, Reason: rec.Reason,
		Disposition: rec.Disposition, Attempts: rec.Attempts, ExpiresAt: fromNano(rec.ExpiresAt),
		NotBefore: fromNano(rec.NotBefore), Transitions: rec.Transitions,
	}
	// Re-encoding must reproduce the stored bytes: every field survived
	// decoding and passes the invariants.
	if again, err := c.MarshalBinary(); err != nil || !bytes.Equal(again, data) {
		return Candidate{}, ErrCorruptRecord
	}
	return c, nil
}

// AttemptRecord is the ledger's record of one admitted attempt.
type AttemptRecord struct {
	Attempt Attempt
	// State is reserved, executing, verified, failed or unknown.
	State       State
	Disposition Disposition
	ExpiresAt   time.Time
	Reserved    time.Time
	// Finished is zero until the attempt has an outcome.
	Finished time.Time
	// Lane is the lane the reservation was admitted on and charged to. It
	// is zero only on attempts reserved before the ledger kept a ceiling.
	Lane Lane
}

type attemptRecord struct {
	V           uint8       `json:"v"`
	ID          ActionID    `json:"id"`
	Candidate   CandidateID `json:"candidate"`
	Seq         uint32      `json:"seq"`
	Prev        ActionID    `json:"prev,omitempty"`
	State       State       `json:"state"`
	Disposition Disposition `json:"disposition,omitempty"`
	ExpiresAt   int64       `json:"expires_at"`
	Reserved    int64       `json:"reserved"`
	Finished    int64       `json:"finished,omitempty"`
	Lane        Lane        `json:"lane,omitempty"`
}

func (a AttemptRecord) record() (attemptRecord, error) {
	bad := func(detail string) (attemptRecord, error) { return attemptRecord{}, refuse(ReasonInvalid, detail) }
	if err := a.Attempt.Validate(); err != nil {
		return attemptRecord{}, err
	}
	if a.Attempt.Seq > MaxAttempts {
		return bad("attempt exceeds the candidate limit")
	}
	switch a.State {
	case StateReserved, StateExecuting, StateVerified, StateFailed, StateUnknown, StateObserved:
	default:
		return bad("attempt state is not an attempt phase")
	}
	if !terminalDisposition(a.State, a.Disposition) {
		return bad("attempt state and disposition disagree")
	}
	reserved, okR := unixNano(a.Reserved)
	expires, okE := unixNano(a.ExpiresAt)
	if !okR || !okE || !a.ExpiresAt.After(a.Reserved) {
		return bad("attempt times are inconsistent")
	}
	var finished int64
	if a.State.Terminal() {
		var ok bool
		if finished, ok = unixNano(a.Finished); !ok || a.Finished.Before(a.Reserved) {
			return bad("attempt outcome has no valid finish time")
		}
	} else if !a.Finished.IsZero() {
		return bad("an open attempt has a finish time")
	}
	if a.Lane != 0 && !a.Lane.Valid() {
		return bad("attempt names an unknown lane")
	}
	return attemptRecord{
		V: attemptVersion, ID: a.Attempt.ID, Candidate: a.Attempt.Candidate, Seq: a.Attempt.Seq, Prev: a.Attempt.Prev,
		State: a.State, Disposition: a.Disposition, ExpiresAt: expires, Reserved: reserved, Finished: finished, Lane: a.Lane,
	}, nil
}

// Validate checks the record's invariants.
func (a AttemptRecord) Validate() error {
	_, err := a.record()
	return err
}

func (a AttemptRecord) MarshalBinary() ([]byte, error) {
	rec, err := a.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalAttempt decodes a stored attempt and checks its invariants.
func UnmarshalAttempt(data []byte) (AttemptRecord, error) {
	var rec attemptRecord
	if err := openRecord(data, &rec); err != nil {
		return AttemptRecord{}, err
	}
	if rec.V != attemptVersion {
		return AttemptRecord{}, ErrCorruptRecord
	}
	a := AttemptRecord{
		Attempt: Attempt{ID: rec.ID, Candidate: rec.Candidate, Seq: rec.Seq, Prev: rec.Prev},
		State:   rec.State, Disposition: rec.Disposition, ExpiresAt: fromNano(rec.ExpiresAt),
		Reserved: fromNano(rec.Reserved), Finished: fromNano(rec.Finished), Lane: rec.Lane,
	}
	if again, err := a.record(); err != nil || again != rec {
		return AttemptRecord{}, ErrCorruptRecord
	}
	return a, nil
}
