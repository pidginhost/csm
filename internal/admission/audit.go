package admission

import (
	"encoding/binary"
	"sort"
	"time"
)

// Audit bounds of spec 5.4 and 5.17. Every admitted transition leaves one
// row in the outbox until the audit consumer acknowledges it; the ledger
// reserves each row as a fixed slot.
const (
	// MaxAuditRowBytes bounds one encoded audit row.
	MaxAuditRowBytes = 1088
	// AuditKeyLen is the length of a row's key: a kind byte, the action
	// ID and the candidate's transition number.
	AuditKeyLen = 1 + actionIDLen + 4
	// AuditSlotBytes is what one row holds in the outbox, with its key.
	AuditSlotBytes = AuditKeyLen + MaxAuditRowBytes
	// AuditStepsPerAttempt is the most rows one attempt writes: its
	// reservation, its execution and its outcome.
	AuditStepsPerAttempt = 3
	// AttemptAuditBytes is what a reservation holds for its attempt's rows.
	AttemptAuditBytes = AuditStepsPerAttempt * AuditSlotBytes
)

// auditKind is the outbox key kind of audit rows.
const auditKind = 'a'

const auditRowVersion = 2

// AuditRow is the audit record of one admitted transition of an attempt:
// its reservation, its execution or its outcome. (Attempt.ID, Transition)
// keys it, so a consumer delivers it idempotently (spec 5.5). It carries
// what was true at the transition: the intended effect, its expiry, the
// original finding and the root evidence.
type AuditRow struct {
	Attempt Attempt
	// Transition is the candidate's transition count after this step.
	Transition uint32
	// State is the attempt's state after the step: reserved, executing or
	// an outcome with its disposition.
	State       State
	Disposition Disposition
	Lane        Lane
	At          time.Time
	ExpiresAt   time.Time
	Kind        Kind
	Target      Target
	Check       string
	FindingID   string
	Roots       []EvidenceID
	// Tier is the candidate's last assessment; zero when it has none.
	Tier Tier
}

// NewAuditRow is the row for c's transition to attempt a's current state
// at time at.
func NewAuditRow(c Candidate, a AttemptRecord, tier Tier, at time.Time) (AuditRow, error) {
	id, err := c.ID()
	if err != nil {
		return AuditRow{}, err
	}
	if a.Attempt.Candidate != id {
		return AuditRow{}, refuse(ReasonInvalid, "audit row joins an attempt to another candidate")
	}
	if a.Attempt.Seq != c.Attempts || !a.ExpiresAt.Equal(c.ExpiresAt) {
		return AuditRow{}, refuse(ReasonInvalid, "audit row attempt does not match the candidate's current attempt")
	}
	r := AuditRow{
		Attempt: a.Attempt, Transition: c.Transitions, State: a.State, Disposition: a.Disposition, Lane: a.Lane,
		At: at, ExpiresAt: a.ExpiresAt, Kind: c.Key.Kind, Target: c.Key.Target, Check: c.Check,
		FindingID: c.FindingID, Roots: append([]EvidenceID(nil), c.Roots...), Tier: tier,
	}
	_, err = r.record()
	return r, err
}

type auditRowRecord struct {
	V           uint8       `json:"v"`
	ID          ActionID    `json:"id"`
	Candidate   CandidateID `json:"candidate"`
	Seq         uint32      `json:"seq"`
	Transition  uint32      `json:"transition"`
	State       State       `json:"state"`
	Disposition Disposition `json:"disposition,omitempty"`
	Lane        Lane        `json:"lane,omitempty"`
	At          int64       `json:"at"`
	ExpiresAt   int64       `json:"expires_at"`
	Kind        Kind        `json:"kind"`
	Target      string      `json:"target"`
	// Base64 bounds printable check names without JSON escape expansion.
	Check     []byte       `json:"check"`
	FindingID string       `json:"finding_id"`
	Roots     []EvidenceID `json:"roots"`
	Class     Class        `json:"class,omitempty"`
	Severity  Severity     `json:"severity,omitempty"`
}

func (r AuditRow) record() (auditRowRecord, error) {
	bad := func(detail string) (auditRowRecord, error) { return auditRowRecord{}, refuse(ReasonInvalid, detail) }
	if err := r.Attempt.Validate(); err != nil {
		return auditRowRecord{}, err
	}
	if r.Attempt.Seq > MaxAttempts {
		return bad("audit row names no transition of an admitted attempt")
	}
	switch r.State {
	case StateReserved, StateExecuting, StateVerified, StateFailed, StateUnknown, StateObserved:
	default:
		return bad("audit row state is not an attempt phase")
	}
	if !terminalDisposition(r.State, r.Disposition) {
		return bad("audit row state and disposition disagree")
	}
	minimumTransition := 2 * r.Attempt.Seq
	switch r.State {
	case StateExecuting, StateFailed, StateObserved:
		minimumTransition++
	case StateVerified, StateUnknown:
		minimumTransition += 2
	}
	if r.Transition < minimumTransition {
		return bad("audit row has too few transitions for its attempt phase")
	}
	at, okAt := unixNano(r.At)
	expires, okExp := unixNano(r.ExpiresAt)
	if !okAt || !okExp {
		return bad("audit row times are not representable")
	}
	if r.Lane != 0 && !r.Lane.Valid() {
		return bad("audit row names an unknown lane")
	}
	if err := ValidateKindTarget(r.Kind, r.Target); err != nil {
		return auditRowRecord{}, err
	}
	if r.Disposition == DispositionNarrowed && r.Kind != KindChallenge && r.Kind != KindBlockService {
		return bad("only a challenge or service block narrows")
	}
	if !boundedToken(r.Check, 64) || !lowerHex(r.FindingID, 16) {
		return bad("audit row check or finding link is malformed")
	}
	if len(r.Roots) == 0 || len(r.Roots) > MaxRoots || !sort.SliceIsSorted(r.Roots, func(i, j int) bool { return r.Roots[i] < r.Roots[j] }) {
		return bad("audit row roots are empty, too many or unsorted")
	}
	for i, id := range r.Roots {
		if _, err := ParseEvidenceID(string(id)); err != nil || (i > 0 && r.Roots[i-1] == id) {
			return bad("audit row roots are malformed or repeated")
		}
	}
	if r.Tier != (Tier{}) && !r.Tier.Valid() {
		return bad("audit row tier is partial")
	}
	return auditRowRecord{
		V: auditRowVersion, ID: r.Attempt.ID, Candidate: r.Attempt.Candidate, Seq: r.Attempt.Seq,
		Transition: r.Transition, State: r.State, Disposition: r.Disposition, Lane: r.Lane, At: at,
		ExpiresAt: expires, Kind: r.Kind, Target: r.Target.Key(), Check: []byte(r.Check), FindingID: r.FindingID,
		Roots: r.Roots, Class: r.Tier.Class, Severity: r.Tier.Severity,
	}, nil
}

func (r AuditRow) MarshalBinary() ([]byte, error) {
	rec, err := r.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalAuditRow decodes a stored row and checks its invariants.
func UnmarshalAuditRow(data []byte) (AuditRow, error) {
	var rec auditRowRecord
	if err := openRecord(data, &rec); err != nil {
		return AuditRow{}, err
	}
	if rec.V != auditRowVersion || rec.Roots == nil {
		return AuditRow{}, ErrCorruptRecord
	}
	target, err := ParseTargetKey(rec.Target, Caps{IPv6: true})
	if err != nil {
		return AuditRow{}, ErrCorruptRecord
	}
	r := AuditRow{
		Transition: rec.Transition, State: rec.State, Disposition: rec.Disposition, Lane: rec.Lane,
		At: fromNano(rec.At), ExpiresAt: fromNano(rec.ExpiresAt), Kind: rec.Kind, Target: target,
		Check: string(rec.Check), FindingID: rec.FindingID, Roots: rec.Roots, Tier: Tier{Class: rec.Class, Severity: rec.Severity},
	}
	r.Attempt, err = NewAttempt(rec.Candidate, rec.Seq)
	if err != nil || r.Attempt.ID != rec.ID {
		return AuditRow{}, ErrCorruptRecord
	}
	if again, err := r.MarshalBinary(); err != nil || string(again) != string(data) {
		return AuditRow{}, ErrCorruptRecord
	}
	return r, nil
}

// AuditID names one row: the attempt and the candidate's transition.
type AuditID struct {
	Action     ActionID
	Transition uint32
}

// ID is the row's name.
func (r AuditRow) ID() AuditID { return AuditID{Action: r.Attempt.ID, Transition: r.Transition} }

// AuditAck acknowledges the row ID names, written at At. The time fences an
// acknowledgement held past its row's retirement: a re-minted attempt
// writes a later row under the same ID, and the stale acknowledgement must
// not remove it (ruling R1).
type AuditAck struct {
	ID AuditID
	At time.Time
}

// Ack is the row's acknowledgement.
func (r AuditRow) Ack() AuditAck { return AuditAck{ID: r.ID(), At: r.At} }

// Key is the outbox key of the row id names.
func (id AuditID) Key() []byte {
	return binary.BigEndian.AppendUint32(AuditPrefix(id.Action), id.Transition)
}

// AuditPrefix is the key prefix every row of one attempt shares.
func AuditPrefix(id ActionID) []byte { return append([]byte{auditKind}, id...) }

// Key is the row's outbox key. Rows of one attempt sort by transition.
func (r AuditRow) Key() []byte { return r.ID().Key() }

// ParseAuditKey splits a row key into its action and transition.
func ParseAuditKey(k []byte) (ActionID, uint32, error) {
	if len(k) != AuditKeyLen || k[0] != auditKind {
		return "", 0, ErrCorruptRecord
	}
	id, err := ParseActionID(string(k[1 : 1+actionIDLen]))
	transition := binary.BigEndian.Uint32(k[1+actionIDLen:])
	if err != nil || transition == 0 {
		return "", 0, ErrCorruptRecord
	}
	return id, transition, nil
}
