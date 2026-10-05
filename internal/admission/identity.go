package admission

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
	"time"
)

// identityVersion is hashed into every derived ID. Changing the derivation
// requires a new version so old and new IDs never collide.
const identityVersion = 1

// EpisodeID names an offense episode. The engine assigns episodes; a
// producer, check or caller never does. The zero value is invalid.
type EpisodeID [16]byte

func (e EpisodeID) IsZero() bool { return e == EpisodeID{} }

func (e EpisodeID) String() string { return hex.EncodeToString(e[:]) }

// ParseEpisodeID accepts 32 lowercase hex digits naming a nonzero episode.
func ParseEpisodeID(s string) (EpisodeID, error) {
	var e EpisodeID
	if !lowerHex(s, 32) {
		return e, refuse(ReasonInvalid, "episode ID is not 32 lowercase hex digits")
	}
	_, _ = hex.Decode(e[:], []byte(s))
	if e.IsZero() {
		return e, refuse(ReasonInvalid, "episode ID is zero")
	}
	return e, nil
}

// CandidateID is stable for one (kind, target, episode, root-evidence
// generation). Repeat reports of the same root set map to the same ID.
type CandidateID string

// ActionID is stable for one admitted attempt of a candidate, unchanged
// through crash recovery.
type ActionID string

// CandidateKey is everything a CandidateID is derived from.
type CandidateKey struct {
	Kind   Kind
	Target Target
	// Episode is assigned by the engine for the canonical address and
	// logical service.
	Episode EpisodeID
	// Generation counts producer-verified new root sets within the
	// episode, from 1. A new report ID is not a new generation.
	Generation uint32
}

// ValidateKindTarget refuses a kind aimed at the wrong shape of target.
func ValidateKindTarget(k Kind, t Target) error {
	_, hasService := t.Service()
	switch {
	case !k.Valid():
		return refuse(ReasonInvalid, "unknown response kind")
	case t.IsZero():
		return refuse(ReasonInvalid, "no target")
	case k == KindBlockService:
		if !hasService {
			return refuse(ReasonInvalid, "service block needs a service target")
		}
	case hasService:
		return refuse(ReasonInvalid, "only a service block takes a service target")
	case k == KindBlockSubnet:
		if t.IsAddress() {
			return refuse(ReasonInvalid, "subnet block needs a prefix wider than one address")
		}
	case !t.IsAddress():
		return refuse(ReasonInvalid, "response needs a single-address target")
	}
	return nil
}

// ID derives the candidate ID.
func (k CandidateKey) ID() (CandidateID, error) {
	if err := ValidateKindTarget(k.Kind, k.Target); err != nil {
		return "", err
	}
	if k.Episode.IsZero() {
		return "", refuse(ReasonInvalid, "candidate has no episode")
	}
	if k.Generation == 0 {
		return "", refuse(ReasonInvalid, "candidate generation starts at 1")
	}
	h := sha256.New()
	writeField(h, []byte{identityVersion, byte(k.Kind)})
	writeField(h, []byte(k.Target.Key()))
	writeField(h, k.Episode[:])
	writeField(h, binary.BigEndian.AppendUint32(nil, k.Generation))
	return CandidateID("cand_" + hex.EncodeToString(h.Sum(nil)[:16])), nil
}

// ParseCandidateID accepts only the derived form.
func ParseCandidateID(s string) (CandidateID, error) {
	rest, ok := strings.CutPrefix(s, "cand_")
	if !ok || !lowerHex(rest, 32) {
		return "", refuse(ReasonInvalid, "malformed candidate ID")
	}
	return CandidateID(s), nil
}

// ParseActionID accepts only the derived form.
func ParseActionID(s string) (ActionID, error) {
	rest, ok := strings.CutPrefix(s, "act_")
	if !ok || !lowerHex(rest, 32) {
		return "", refuse(ReasonInvalid, "malformed action ID")
	}
	return ActionID(s), nil
}

// Attempt links one admitted attempt to its candidate and to the attempt it
// follows. Replaying or recovering an admitted attempt keeps its ID. A later
// separately admitted attempt gets a new sequence and never overwrites an
// earlier outcome; the ledger enforces admission and predecessor state.
type Attempt struct {
	ID        ActionID
	Candidate CandidateID
	Seq       uint32
	Prev      ActionID
}

func attemptID(c CandidateID, seq uint32) ActionID {
	h := sha256.New()
	writeField(h, []byte{identityVersion})
	writeField(h, []byte(c))
	writeField(h, binary.BigEndian.AppendUint32(nil, seq))
	return ActionID("act_" + hex.EncodeToString(h.Sum(nil)[:16]))
}

// LegacyActionID names the seq-th charge imported from the legacy hourly
// counter for the hour ending at at. Its hash input has a field an
// attempt's never has, so the two never collide.
func LegacyActionID(at time.Time, seq uint32) ActionID {
	h := sha256.New()
	writeField(h, []byte{identityVersion})
	writeField(h, []byte("legacy_hour"))
	writeField(h, binary.BigEndian.AppendUint64(nil, uint64(at.UnixNano())))
	writeField(h, binary.BigEndian.AppendUint32(nil, seq))
	return ActionID("act_" + hex.EncodeToString(h.Sum(nil)[:16]))
}

// NewAttempt derives attempt seq of c. Sequences start at 1.
func NewAttempt(c CandidateID, seq uint32) (Attempt, error) {
	if _, err := ParseCandidateID(string(c)); err != nil {
		return Attempt{}, err
	}
	if seq == 0 {
		return Attempt{}, refuse(ReasonInvalid, "attempt sequence starts at 1")
	}
	a := Attempt{ID: attemptID(c, seq), Candidate: c, Seq: seq}
	if seq > 1 {
		a.Prev = attemptID(c, seq-1)
	}
	return a, nil
}

// Validate recomputes the attempt's derived fields, so a stored attempt
// cannot be relinked to another candidate or sequence.
func (a Attempt) Validate() error {
	want, err := NewAttempt(a.Candidate, a.Seq)
	if err != nil {
		return err
	}
	if a != want {
		return refuse(ReasonInvalid, "attempt identity does not match its candidate and sequence")
	}
	return nil
}

// writeField writes b as a netstring ("<len>:<bytes>") so field
// boundaries cannot shift.
func writeField(h hash.Hash, b []byte) {
	_, _ = h.Write(strconv.AppendInt(nil, int64(len(b)), 10))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write(b)
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
