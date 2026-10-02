package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

// MaxEvidenceBytes bounds one encoded evidence record.
const MaxEvidenceBytes = 1024

const evidenceVersion = 1

// ObservationRef identifies the observation behind evidence by the
// producer's own cursor or sequence, never by a caller-chosen timestamp. A
// detector re-reporting the same observation keeps the same reference.
type ObservationRef struct {
	// Stream is the producer's stream identity, such as a log file identity
	// or a journal boot ID.
	Stream string
	// Cursor is the position or sequence number within Stream.
	Cursor string
	// Version is the producer's revision of this observation, from 1.
	Version uint32
}

// ParserRef names the parser that read the observation.
type ParserRef struct {
	Name    string
	Version uint32
}

// IntelRef is the external source behind reputation evidence and the time
// its verdict expires.
type IntelRef struct {
	Source  string
	Expires time.Time
}

// EvidenceInput is what a producer supplies to Mint.
type EvidenceInput struct {
	Check       string
	FindingID   string
	Severity    Severity
	Observation ObservationRef
	ObservedAt  time.Time
	Parser      ParserRef
	Target      Target
	// Claims say which account the evidence concerns, as the finding read
	// them. Only kinds the producer declared are accepted.
	Claims []Claim
	// Inventory is the server-owned snapshot that verifies Claims. Without
	// one the evidence belongs to the host.
	Inventory *Inventory
	Intel     *IntelRef
}

// EvidenceID names one evidence record. The same observation of the same
// check and target always has the same ID.
type EvidenceID string

// evidenceRecord is the persisted form. Field order is the encoding order.
type evidenceRecord struct {
	Producer        ProducerID `json:"producer"`
	Entry           Entry      `json:"entry"`
	Check           string     `json:"check"`
	Family          Family     `json:"family"`
	Basis           Basis      `json:"basis"`
	FindingID       string     `json:"finding_id"`
	Severity        Severity   `json:"severity"`
	Stream          string     `json:"stream"`
	Cursor          string     `json:"cursor"`
	Version         uint32     `json:"version"`
	ObservedAt      int64      `json:"observed_at"`
	Parser          string     `json:"parser"`
	ParserVersion   uint32     `json:"parser_version"`
	Target          string     `json:"target"`
	OwnerAccount    string     `json:"owner_account,omitempty"`
	OwnerGeneration uint64     `json:"owner_generation,omitempty"`
	IntelSource     string     `json:"intel_source,omitempty"`
	IntelExpires    int64      `json:"intel_expires,omitempty"`
}

// Evidence is an immutable record minted by a registered producer. Its
// fields are only readable; the zero value is not valid evidence.
type Evidence struct {
	rec evidenceRecord
}

func (e Evidence) Producer() ProducerID { return e.rec.Producer }
func (e Evidence) Entry() Entry         { return e.rec.Entry }
func (e Evidence) Check() string        { return e.rec.Check }
func (e Evidence) Family() Family       { return e.rec.Family }
func (e Evidence) Basis() Basis         { return e.rec.Basis }
func (e Evidence) FindingID() string    { return e.rec.FindingID }
func (e Evidence) Severity() Severity   { return e.rec.Severity }

func (e Evidence) Observation() ObservationRef {
	return ObservationRef{Stream: e.rec.Stream, Cursor: e.rec.Cursor, Version: e.rec.Version}
}

func (e Evidence) ObservedAt() time.Time { return time.Unix(0, e.rec.ObservedAt).UTC() }

func (e Evidence) Parser() ParserRef {
	return ParserRef{Name: e.rec.Parser, Version: e.rec.ParserVersion}
}

// Target returns the evidence target. It was validated when the record was
// minted or decoded.
func (e Evidence) Target() Target {
	t, _ := ParseTargetKey(e.rec.Target, Caps{IPv6: true})
	return t
}

func (e Evidence) Owner() Owner {
	return Owner{account: e.rec.OwnerAccount, generation: e.rec.OwnerGeneration}
}

func (e Evidence) Intel() (IntelRef, bool) {
	if e.rec.IntelSource == "" {
		return IntelRef{}, false
	}
	return IntelRef{Source: e.rec.IntelSource, Expires: time.Unix(0, e.rec.IntelExpires).UTC()}, true
}

// Equal reports whether two records are identical. A producer publishing a
// different record under an existing ID is a conflict, never an update.
func (e Evidence) Equal(o Evidence) bool { return e.rec == o.rec }

// SameExceptFinding reports whether o records the same observation as e,
// field for field, apart from the finding that reported it. Such a record
// is a later report of the published original, not a conflicting one.
func (e Evidence) SameExceptFinding(o Evidence) bool {
	a, b := e.rec, o.rec
	a.FindingID, b.FindingID = "", ""
	return a == b
}

// ID derives the evidence ID from producer, check, observation and target.
func (e Evidence) ID() EvidenceID {
	h := sha256.New()
	writeField(h, []byte{identityVersion})
	writeField(h, []byte(e.rec.Producer))
	writeField(h, []byte(e.rec.Check))
	writeField(h, []byte(e.rec.Stream))
	writeField(h, []byte(e.rec.Cursor))
	writeField(h, binary.BigEndian.AppendUint32(nil, e.rec.Version))
	writeField(h, []byte(e.rec.Target))
	return EvidenceID("ev_" + hex.EncodeToString(h.Sum(nil)[:16]))
}

// Mint validates in and returns evidence bound to this producer. The
// producer's entry and the check's current family and basis are recorded;
// callers cannot choose them.
func (p *Producer) Mint(in EvidenceInput) (Evidence, error) {
	if p == nil || p.reg == nil {
		return Evidence{}, refuse(ReasonPolicy, "producer is not registered")
	}
	spec, ok := p.reg.Spec(p.id)
	if !ok {
		return Evidence{}, refuse(ReasonPolicy, "producer is not registered")
	}
	canonical, pol, ok := p.reg.lookup(in.Check)
	if !ok || !spec.publishes(canonical) {
		return Evidence{}, refuse(ReasonPolicy, "check is not registered for this producer")
	}
	for _, c := range in.Claims {
		if !slices.Contains(spec.Claims, c.Kind) {
			return Evidence{}, refuse(ReasonPolicy, "claim kind is not declared for this producer")
		}
	}
	owner := HostOwner()
	if in.Inventory != nil {
		owner = in.Inventory.Resolve(in.Claims...)
	}
	rec := evidenceRecord{
		Producer:        p.id,
		Entry:           spec.Entry,
		Check:           canonical,
		Family:          pol.Family,
		Basis:           pol.Basis,
		FindingID:       in.FindingID,
		Severity:        in.Severity,
		Stream:          in.Observation.Stream,
		Cursor:          in.Observation.Cursor,
		Version:         in.Observation.Version,
		Parser:          in.Parser.Name,
		ParserVersion:   in.Parser.Version,
		Target:          in.Target.Key(),
		OwnerAccount:    owner.account,
		OwnerGeneration: owner.generation,
	}
	var err error
	rec.ObservedAt, err = evidenceTime(in.ObservedAt)
	if err != nil {
		return Evidence{}, err
	}
	if in.Intel != nil {
		rec.IntelSource = in.Intel.Source
		rec.IntelExpires, err = evidenceTime(in.Intel.Expires)
		if err != nil {
			return Evidence{}, err
		}
	}
	if err := validateRecord(rec); err != nil {
		return Evidence{}, err
	}
	if rec.Severity < pol.MinSeverity {
		return Evidence{}, refuse(ReasonPolicy, "finding severity is below the check's evidence floor")
	}
	e := Evidence{rec: rec}
	if b, err := e.MarshalBinary(); err != nil || len(b) > MaxEvidenceBytes {
		return Evidence{}, refuse(ReasonInvalid, "evidence record exceeds its size bound")
	}
	return e, nil
}

// UnixNano is undefined outside its representable range. Refuse such input
// instead of persisting a different observation time or intel expiry.
func evidenceTime(t time.Time) (int64, error) {
	if t.IsZero() {
		return 0, nil
	}
	n := t.UnixNano()
	if !time.Unix(0, n).Equal(t) {
		return 0, refuse(ReasonInvalid, "evidence time is outside the supported range")
	}
	return n, nil
}

// validateRecord checks everything that does not need the registry. Decode
// runs it too, so a stored record is held to the same rules as a new one.
func validateRecord(r evidenceRecord) error {
	switch {
	case !ValidProducerID(r.Producer) || !r.Entry.Valid():
		return refuse(ReasonInvalid, "evidence producer or entry is malformed")
	case r.Family == FamilyNone || ValidPolicy(r.Family, r.Basis) != nil:
		return refuse(ReasonPolicy, "evidence family and basis are not an admissible pair")
	case !lowerHex(r.FindingID, 16):
		return refuse(ReasonInvalid, "finding ID is not 16 lowercase hex digits")
	case !r.Severity.Valid():
		return refuse(ReasonInvalid, "evidence severity is invalid")
	case !boundedToken(r.Stream, 128) || !boundedToken(r.Cursor, 128) || r.Version == 0:
		return refuse(ReasonInvalid, "observation reference is missing or malformed")
	case r.ObservedAt <= 0:
		return refuse(ReasonInvalid, "observation time is missing")
	case !boundedToken(r.Parser, 64) || r.ParserVersion == 0:
		return refuse(ReasonInvalid, "parser provenance is missing or malformed")
	case !boundedToken(r.Check, 64):
		return refuse(ReasonInvalid, "check name is malformed")
	}
	t, err := ParseTargetKey(r.Target, Caps{IPv6: true})
	if err != nil {
		return err
	}
	if _, isService := t.Service(); isService {
		return refuse(ReasonInvalid, "evidence names an address or prefix, not a service")
	}
	if r.OwnerAccount == "" {
		if r.OwnerGeneration != 0 {
			return refuse(ReasonInvalid, "host owner carries a generation")
		}
	} else if !ValidAccountName(r.OwnerAccount) || r.OwnerGeneration == 0 {
		return refuse(ReasonInvalid, "owner account is malformed")
	}
	intel := r.IntelSource != "" || r.IntelExpires != 0
	switch {
	case intel != (r.Family == FamilyReputation):
		return refuse(ReasonInvalid, "intel source is required for reputation evidence and only for it")
	case intel && (!boundedToken(r.IntelSource, 64) || r.IntelExpires <= r.ObservedAt):
		return refuse(ReasonInvalid, "intel source or expiry is malformed")
	}
	return nil
}

// boundedToken accepts 1-max bytes of printable ASCII without spaces.
func boundedToken(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// MarshalBinary encodes 'E', the version, the JSON record and the first 8
// bytes of the SHA-256 of everything before it.
func (e Evidence) MarshalBinary() ([]byte, error) {
	body, err := json.Marshal(e.rec)
	if err != nil {
		return nil, err
	}
	out := append([]byte{'E', evidenceVersion}, body...)
	sum := sha256.Sum256(out)
	return append(out, sum[:8]...), nil
}

// UnmarshalEvidence checks record structure, checksum and canonical encoding.
// A checksum detects corruption, not authorship. Only the database owner's
// trusted evidence store may supply bytes; publication must reject an existing
// ID with different content using Equal.
func UnmarshalEvidence(data []byte) (Evidence, error) {
	if len(data) > MaxEvidenceBytes || len(data) < 2+2+8 {
		return Evidence{}, refuse(ReasonInvalid, "evidence record has an impossible length")
	}
	if data[0] != 'E' || data[1] != evidenceVersion {
		return Evidence{}, refuse(ReasonInvalid, "evidence record version is not supported")
	}
	head, sum := data[:len(data)-8], data[len(data)-8:]
	if want := sha256.Sum256(head); !bytes.Equal(sum, want[:8]) {
		return Evidence{}, refuse(ReasonInvalid, "evidence record checksum mismatch")
	}
	dec := json.NewDecoder(bytes.NewReader(head[2:]))
	dec.DisallowUnknownFields()
	var rec evidenceRecord
	if err := dec.Decode(&rec); err != nil || dec.More() {
		return Evidence{}, refuse(ReasonInvalid, "evidence record body does not decode")
	}
	if err := validateRecord(rec); err != nil {
		return Evidence{}, err
	}
	e := Evidence{rec: rec}
	if again, err := e.MarshalBinary(); err != nil || !bytes.Equal(again, data) {
		return Evidence{}, refuse(ReasonInvalid, "evidence record is not in canonical form")
	}
	return e, nil
}
