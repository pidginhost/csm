package admission

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"
)

// MaxIntentBytes bounds one encoded intent, with the victim of an
// evicting block.
const MaxIntentBytes = 384

// UnknownHoldBytes is what an unknown outcome holds in the recovery reserve
// besides its history and its rows: its intent and the slot of the row that
// retires it.
const UnknownHoldBytes = AuditSlotBytes + MaxIntentBytes

// AttemptRecoveryBytes is the room one reservation needs in the recovery
// reserve besides its history: its attempt's audit rows and what an unknown
// outcome holds.
const AttemptRecoveryBytes = AttemptAuditBytes + UnknownHoldBytes

// intentVersion is the encoding of an intent without a victim; an
// evicting intent is victimIntentVersion.
const (
	intentVersion       = 1
	victimIntentVersion = 2
)

// BatchID names one execution batch.
type BatchID string

// NewBatchID derives the ID of the batch whose members are members: from
// the set, not its order, so executing the same members again names the
// same batch and any other set names another.
func NewBatchID(members []ActionID) (BatchID, error) {
	if len(members) == 0 || len(members) > MaxBatchMembers {
		return "", refuse(ReasonInvalid, "a batch has one to MaxBatchMembers members")
	}
	sorted := slices.Clone(members)
	slices.Sort(sorted)
	h := sha256.New()
	writeField(h, []byte{identityVersion})
	writeField(h, []byte("batch"))
	for i, id := range sorted {
		if _, err := ParseActionID(string(id)); err != nil {
			return "", err
		}
		if i > 0 && sorted[i-1] == id {
			return "", refuse(ReasonInvalid, "a batch names a member twice")
		}
		writeField(h, []byte(id))
	}
	return BatchID("bat_" + hex.EncodeToString(h.Sum(nil)[:16])), nil
}

// ParseBatchID accepts only the derived form.
func ParseBatchID(s string) (BatchID, error) {
	rest, ok := strings.CutPrefix(s, "bat_")
	if !ok || !lowerHex(rest, 32) {
		return "", refuse(ReasonInvalid, "malformed batch ID")
	}
	return BatchID(s), nil
}

// Intent is what one attempt may apply, recorded before the attempt
// dispatches any host change (spec 5.4): the batch it runs in, its kind,
// its target and the absolute expiry of the effect. Every member adds its
// target until that expiry; a member that evicts also removes its victim.
// The ledger keeps it while the attempt runs and, after an unknown
// outcome, until recovery retires the uncertainty, so a restart knows
// which effects are unproven.
type Intent struct {
	Action    ActionID
	Batch     BatchID
	Kind      Kind
	Target    Target
	ExpiresAt time.Time
	// Victim is the automatic block the member evicts; zero when it takes
	// a free slot. Only a block_ip member evicts, one victim for its one
	// unit (spec 5.6).
	Victim Victim
}

// Victim is an automatic block an evicting member removes: its action, its
// address and the absolute expiry it was applied with.
type Victim struct {
	Action    ActionID
	Target    Target
	ExpiresAt time.Time
}

// VictimOutcome is what a verified block's attempt did to the victim it
// claimed, as the applier proved it.
type VictimOutcome uint8

const (
	// VictimRemoved: the batch removed the victim and its readback proved
	// it gone, so the victim is evicted.
	VictimRemoved VictimOutcome = iota + 1
	// VictimSpared: the batch never removed the victim, which returns to
	// the pool with its slot.
	VictimSpared
	// VictimUnproven: the batch sent the removal without proving it. The
	// victim may still be enforced: the attempt's outcome is unknown,
	// which keeps the claim until the victim's expiry.
	VictimUnproven
)

type intentRecord struct {
	V         uint8    `json:"v"`
	Action    ActionID `json:"action"`
	Batch     BatchID  `json:"batch"`
	Kind      Kind     `json:"kind"`
	Target    string   `json:"target"`
	ExpiresAt int64    `json:"expires_at"`
	Victim    ActionID `json:"victim,omitempty"`
	VictimAt  string   `json:"victim_target,omitempty"`
	VictimEnd int64    `json:"victim_expires,omitempty"`
}

func (in Intent) record() (intentRecord, error) {
	if _, err := ParseActionID(string(in.Action)); err != nil {
		return intentRecord{}, err
	}
	if _, err := ParseBatchID(string(in.Batch)); err != nil {
		return intentRecord{}, err
	}
	if err := ValidateKindTarget(in.Kind, in.Target); err != nil {
		return intentRecord{}, err
	}
	expires, ok := unixNano(in.ExpiresAt)
	if !ok || expires < 0 {
		return intentRecord{}, refuse(ReasonInvalid, "intent has no expiry after the epoch")
	}
	rec := intentRecord{V: intentVersion, Action: in.Action, Batch: in.Batch, Kind: in.Kind, Target: in.Target.Key(), ExpiresAt: expires}
	if in.Victim == (Victim{}) {
		return rec, nil
	}
	v := in.Victim
	ends, ok := unixNano(v.ExpiresAt)
	switch {
	case in.Kind != KindBlockIP:
		return intentRecord{}, refuse(ReasonInvalid, "only a block_ip member evicts")
	case ValidateKindTarget(KindBlockIP, v.Target) != nil:
		return intentRecord{}, refuse(ReasonInvalid, "intent victim is not an address")
	case v.Target == in.Target || v.Action == in.Action:
		return intentRecord{}, refuse(ReasonInvalid, "a member cannot evict itself")
	case !ok || ends <= 0:
		return intentRecord{}, refuse(ReasonInvalid, "intent victim has no expiry after the epoch")
	}
	if _, err := ParseActionID(string(v.Action)); err != nil {
		return intentRecord{}, err
	}
	rec.V, rec.Victim, rec.VictimAt, rec.VictimEnd = victimIntentVersion, v.Action, v.Target.Key(), ends
	return rec, nil
}

// Validate checks the intent's invariants.
func (in Intent) Validate() error {
	_, err := in.record()
	return err
}

func (in Intent) MarshalBinary() ([]byte, error) {
	rec, err := in.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalIntent decodes a stored intent and checks its invariants.
func UnmarshalIntent(data []byte) (Intent, error) {
	var rec intentRecord
	if err := openRecord(data, &rec); err != nil {
		return Intent{}, err
	}
	target, err := ParseTargetKey(rec.Target, Caps{IPv6: true})
	if err != nil {
		return Intent{}, ErrCorruptRecord
	}
	in := Intent{Action: rec.Action, Batch: rec.Batch, Kind: rec.Kind, Target: target, ExpiresAt: fromNano(rec.ExpiresAt)}
	if rec.Victim != "" {
		victim, err := ParseTargetKey(rec.VictimAt, Caps{IPv6: true})
		if err != nil {
			return Intent{}, ErrCorruptRecord
		}
		in.Victim = Victim{Action: rec.Victim, Target: victim, ExpiresAt: fromNano(rec.VictimEnd)}
	}
	if again, err := in.record(); err != nil || again != rec {
		return Intent{}, ErrCorruptRecord
	}
	return in, nil
}
