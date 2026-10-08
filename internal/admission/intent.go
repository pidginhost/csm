package admission

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"
)

// MaxIntentBytes bounds one encoded intent.
const MaxIntentBytes = 256

// UnknownHoldBytes is what an unknown outcome holds in the recovery reserve
// besides its history and its rows: its intent and the slot of the row that
// retires it.
const UnknownHoldBytes = AuditSlotBytes + MaxIntentBytes

// AttemptRecoveryBytes is the room one reservation needs in the recovery
// reserve besides its history: its attempt's audit rows and what an unknown
// outcome holds.
const AttemptRecoveryBytes = AttemptAuditBytes + UnknownHoldBytes

const intentVersion = 1

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
// target until that expiry; nothing is removed. The ledger keeps it while
// the attempt runs and, after an unknown outcome, until recovery retires
// the uncertainty, so a restart knows which effects are unproven.
type Intent struct {
	Action    ActionID
	Batch     BatchID
	Kind      Kind
	Target    Target
	ExpiresAt time.Time
}

type intentRecord struct {
	V         uint8    `json:"v"`
	Action    ActionID `json:"action"`
	Batch     BatchID  `json:"batch"`
	Kind      Kind     `json:"kind"`
	Target    string   `json:"target"`
	ExpiresAt int64    `json:"expires_at"`
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
	return intentRecord{V: intentVersion, Action: in.Action, Batch: in.Batch, Kind: in.Kind, Target: in.Target.Key(), ExpiresAt: expires}, nil
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
	if again, err := in.record(); err != nil || again != rec {
		return Intent{}, ErrCorruptRecord
	}
	return in, nil
}
