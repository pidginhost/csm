package admission

import (
	"bytes"
	"encoding/binary"
	"math"
	"time"
)

// MaxEffectRecordBytes bounds one encoded effect record. With a known set
// of capacity C, slot admission bounds new records to C times the sum of
// this size and effectKeyLen, plus the evicted records kept until their
// expiry. A reduced limit or an unavailable snapshot can leave more
// records until their expiry sweep.
const MaxEffectRecordBytes = 512

// effectRecordVersion is the encoding of a record without an eviction;
// a record that names a victim or an evictor is evictionRecordVersion.
const (
	effectRecordVersion   = 1
	evictionRecordVersion = 2
)

// effectKeyLen is the length of an effect record's key: its expiry, then
// its action.
const effectKeyLen = 8 + actionIDLen

// EffectRecord is an automatic block's hold on a temporary set slot (spec
// 5.6). The ledger writes it when the block's attempt is reserved, so
// pending and live reservations count together; the verified outcome
// records the first application, and the record leaves when the attempt
// fails, its uncertainty is retired or its expiry passes. The occupancy
// partition, the lane of the charge and the evidence eligibility are
// separate recorded fields.
type EffectRecord struct {
	Action    ActionID
	Target    Target
	Partition Partition
	Lane      Lane
	Tier      Tier
	// Scope is the fairness scope key of the block's candidate.
	Scope        string
	Direct       bool
	Corroborated bool
	ExpiresAt    time.Time
	// Applied is the admission time the verified outcome was recorded,
	// zero while the attempt is pending; Elapsed is the ceiling's elapsed
	// time then, so a minimum hold needs both wall and elapsed time, as a
	// charge's window does.
	Applied time.Time
	Elapsed time.Duration
	// Victim is the verified record a pending block claimed to evict
	// (spec 5.6); zero when the block took a free slot, and cleared when
	// its application is verified.
	Victim EffectRef
	// EvictedBy is the pending block that claimed this verified record as
	// its victim. Evicted is set when that block's application is
	// verified: the record then holds no slot and stays, as the ledger's
	// record of the eviction, until its expiry sweep.
	EvictedBy ActionID
	Evicted   bool
}

// EffectRef names an effect record by its action and expiry, which make
// its key, or an import, which has no record, by its effect name and
// expiry.
type EffectRef struct {
	Action    ActionID
	ExpiresAt time.Time
}

// Key is the storage key of the record r names; an import has none.
func (r EffectRef) Key() ([]byte, error) { return EffectRecordKey(r.Action, r.ExpiresAt) }

// Imported reports whether r names an import rather than a record.
func (r EffectRef) Imported() bool { return ImportedVictim(r.Action) }

// Verified reports whether the block's application was verified.
func (e EffectRecord) Verified() bool { return !e.Applied.IsZero() }

// Holds reports whether the record holds a set slot: every record does
// until an eviction of it is verified.
func (e EffectRecord) Holds() bool { return !e.Evicted }

type effectRecordRecord struct {
	V            uint8     `json:"v"`
	Target       string    `json:"target"`
	Partition    Partition `json:"partition"`
	Lane         Lane      `json:"lane"`
	Class        Class     `json:"class"`
	Severity     Severity  `json:"severity"`
	Scope        string    `json:"scope"`
	Direct       bool      `json:"direct,omitempty"`
	Corroborated bool      `json:"corroborated,omitempty"`
	Applied      int64     `json:"applied,omitempty"`
	Elapsed      int64     `json:"elapsed,omitempty"`
	Victim       ActionID  `json:"victim,omitempty"`
	VictimEnds   int64     `json:"victim_expires,omitempty"`
	EvictedBy    ActionID  `json:"evicted_by,omitempty"`
	Evicted      bool      `json:"evicted,omitempty"`
}

func (e EffectRecord) record() ([]byte, effectRecordRecord, error) {
	bad := func(detail string) ([]byte, effectRecordRecord, error) {
		return nil, effectRecordRecord{}, refuse(ReasonInvalid, detail)
	}
	if _, err := ParseActionID(string(e.Action)); err != nil {
		return bad("effect names no action")
	}
	if err := ValidateKindTarget(KindBlockIP, e.Target); err != nil {
		return bad("effect has no single-address target")
	}
	expires, ok := unixNano(e.ExpiresAt)
	switch {
	case !ok || expires < 0:
		return bad("effect has no expiry after the epoch")
	case !e.Partition.Valid() || !e.Lane.Valid():
		return bad("effect has no partition or lane")
	case e.Partition == PartitionReserved && PartitionOf(e.Lane) != PartitionReserved:
		return bad("general work never holds a reserved slot")
	case !e.Tier.Valid():
		return bad("effect tier is invalid")
	case e.Direct && e.Corroborated, (e.Direct || e.Corroborated) && e.Tier.Class != ClassC3:
		return bad("effect has impossible reserved evidence")
	case !boundedToken(e.Scope, 128):
		return bad("effect scope is malformed")
	case e.Elapsed < 0, e.Elapsed > 0 && e.Applied.IsZero():
		return bad("effect elapsed time has no application")
	case e.Victim != EffectRef{} && e.Verified():
		return bad("a verified block keeps no victim claim")
	case e.EvictedBy != "" && !e.Verified():
		return bad("only a verified block is a victim")
	case e.Evicted && e.EvictedBy == "":
		return bad("an evicted block names no evictor")
	case e.Victim.Action != "" && e.Victim.Action == e.Action, e.EvictedBy != "" && e.EvictedBy == e.Action:
		return bad("a block cannot evict itself")
	}
	rec := effectRecordRecord{V: effectRecordVersion, Target: e.Target.Key(), Partition: e.Partition, Lane: e.Lane, Class: e.Tier.Class,
		Severity: e.Tier.Severity, Scope: e.Scope, Direct: e.Direct, Corroborated: e.Corroborated, Elapsed: int64(e.Elapsed)}
	if e.Victim != (EffectRef{}) {
		ends, inRange := unixNano(e.Victim.ExpiresAt)
		if _, err := ParseVictimID(string(e.Victim.Action)); err != nil || !inRange || ends <= 0 {
			return bad("effect victim is malformed")
		}
		rec.Victim, rec.VictimEnds = e.Victim.Action, ends
	}
	if e.EvictedBy != "" {
		if _, err := ParseActionID(string(e.EvictedBy)); err != nil {
			return bad("effect evictor is malformed")
		}
		rec.EvictedBy, rec.Evicted = e.EvictedBy, e.Evicted
	}
	if rec.Victim != "" || rec.EvictedBy != "" {
		rec.V = evictionRecordVersion
	}
	if e.Verified() {
		if rec.Applied, ok = unixNano(e.Applied); !ok || rec.Applied < 0 {
			return bad("effect has no application after the epoch")
		}
	}
	key, err := EffectRecordKey(e.Action, e.ExpiresAt)
	return key, rec, err
}

// Key is the effect record's storage key.
func (e EffectRecord) Key() ([]byte, error) {
	key, _, err := e.record()
	return key, err
}

// EffectRecordKey is the storage key of the record action's block holds
// until expiresAt. Big-endian nanoseconds sort by expiry, so a walk in key
// order meets the effects that end first.
func EffectRecordKey(action ActionID, expiresAt time.Time) ([]byte, error) {
	expires, ok := unixNano(expiresAt)
	if _, err := ParseActionID(string(action)); err != nil || !ok || expires < 0 {
		return nil, refuse(ReasonInvalid, "effect key needs an action and an expiry after the epoch")
	}
	key := binary.BigEndian.AppendUint64(make([]byte, 0, effectKeyLen), uint64(expires))
	return append(key, action...), nil
}

func (e EffectRecord) MarshalBinary() ([]byte, error) {
	_, rec, err := e.record()
	if err != nil {
		return nil, err
	}
	data, err := sealRecord(rec)
	if err == nil && len(data) > MaxEffectRecordBytes {
		return nil, refuse(ReasonInvalid, "effect record is too large")
	}
	return data, err
}

// UnmarshalEffectRecord decodes a stored effect record from its key and
// value and checks its invariants.
func UnmarshalEffectRecord(key, data []byte) (EffectRecord, error) {
	var rec effectRecordRecord
	if len(data) > MaxEffectRecordBytes || openRecord(data, &rec) != nil || len(key) != effectKeyLen {
		return EffectRecord{}, ErrCorruptRecord
	}
	expires := binary.BigEndian.Uint64(key[:8])
	if expires > 1<<63-1 {
		return EffectRecord{}, ErrCorruptRecord
	}
	target, err := ParseTargetKey(rec.Target, Caps{IPv6: true})
	if err != nil {
		return EffectRecord{}, ErrCorruptRecord
	}
	e := EffectRecord{Action: ActionID(key[8:]), Target: target, Partition: rec.Partition, Lane: rec.Lane,
		Tier: Tier{Class: rec.Class, Severity: rec.Severity}, Scope: rec.Scope, Direct: rec.Direct, Corroborated: rec.Corroborated,
		ExpiresAt: fromNano(int64(expires)), Applied: fromNano(rec.Applied), Elapsed: time.Duration(rec.Elapsed),
		EvictedBy: rec.EvictedBy, Evicted: rec.Evicted}
	if rec.Victim != "" {
		e.Victim = EffectRef{Action: rec.Victim, ExpiresAt: fromNano(rec.VictimEnds)}
	}
	again, againRec, err := e.record()
	if err != nil || !bytes.Equal(again, key) || againRec != rec {
		return EffectRecord{}, ErrCorruptRecord
	}
	return e, nil
}

const effectTallyVersion = 1

// EffectTally counts the effect records of each partition. The ledger
// changes it with every record it writes or removes, so occupancy never
// walks the records.
type EffectTally struct {
	General, Reserved int
}

type effectTallyRecord struct {
	V        uint8 `json:"v"`
	General  int   `json:"general"`
	Reserved int   `json:"reserved"`
}

// Add counts delta more records in partition p. Invalid counts, underflow
// and overflow return the original tally with an error.
func (t EffectTally) Add(p Partition, delta int) (EffectTally, error) {
	n := &t.General
	switch p {
	case PartitionGeneral:
	case PartitionReserved:
		n = &t.Reserved
	default:
		return t, refuse(ReasonInvalid, "effect tally names no partition")
	}
	if t.General < 0 || t.Reserved < 0 || delta < -*n || delta > math.MaxInt-*n {
		return t, ErrCorruptRecord
	}
	*n += delta
	return t, nil
}

// Occupy adds the counted records to the automatic entries of o. Invalid
// counts or overflow return the original occupancy with an error.
func (t EffectTally) Occupy(o SetOccupancy) (SetOccupancy, error) {
	if t.General < 0 || t.Reserved < 0 || o.General < 0 || o.Reserved < 0 ||
		t.General > math.MaxInt-o.General || t.Reserved > math.MaxInt-o.Reserved {
		return o, ErrCorruptRecord
	}
	o.General += t.General
	o.Reserved += t.Reserved
	return o, nil
}

func (t EffectTally) MarshalBinary() ([]byte, error) {
	if t.General < 0 || t.Reserved < 0 {
		return nil, refuse(ReasonInvalid, "effect tally is negative")
	}
	return sealRecord(effectTallyRecord{V: effectTallyVersion, General: t.General, Reserved: t.Reserved})
}

// UnmarshalEffectTally decodes a stored effect tally.
func UnmarshalEffectTally(data []byte) (EffectTally, error) {
	var rec effectTallyRecord
	if openRecord(data, &rec) != nil || rec.V != effectTallyVersion || rec.General < 0 || rec.Reserved < 0 {
		return EffectTally{}, ErrCorruptRecord
	}
	return EffectTally{General: rec.General, Reserved: rec.Reserved}, nil
}
