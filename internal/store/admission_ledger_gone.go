package store

import (
	"bytes"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// HeldEffect names a verified block the ledger counts as held, for the
// owner to ask the firewall whether it still is.
type HeldEffect struct {
	Action    admission.ActionID
	Target    admission.Target
	ExpiresAt time.Time
}

// HeldEffects lists at most limit verified, held, unclaimed blocks in
// expiry order, wrapping after the last completed batch. ObserveHeld
// advances the cursor after two answered checks, so a held prefix cannot
// starve the tail when configured capacity exceeds one engine call.
func (l *AdmissionLedger) HeldEffects(limit int) ([]HeldEffect, error) {
	if limit <= 0 {
		return nil, refusal(admission.ReasonInvalid, "a list of held blocks needs a positive limit")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []HeldEffect
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(admissionEffectsBucket))
		if b == nil {
			return nil
		}
		cur := b.Cursor()
		k, v := cur.First()
		if len(l.heldAfter) != 0 {
			k, v = cur.Seek(l.heldAfter)
			if bytes.Equal(k, l.heldAfter) {
				k, v = cur.Next()
			}
			if k == nil {
				k, v = cur.First()
			}
		}
		start := bytes.Clone(k)
		for k != nil && len(out) < limit {
			rec, err := admission.UnmarshalEffectRecord(k, v)
			if err != nil {
				return err
			}
			if rec.Verified() && rec.Holds() && rec.EvictedBy == "" {
				out = append(out, HeldEffect{Action: rec.Action, Target: rec.Target, ExpiresAt: rec.ExpiresAt})
			}
			k, v = cur.Next()
			if k == nil {
				k, v = cur.First()
			}
			if bytes.Equal(k, start) {
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ObserveHeld takes the firewall's answer for a list HeldEffects gave:
// held[i] says whether the block asked[i] names is still held. A block
// missed by two consecutive answers left the kernel before its expiry (an
// operator unblock, undo or flush, or a lost element), which needs no
// trusted clock (spec 5.2): its record is gone from the first miss's
// reading and frees its slot. A record that changed in between is left to
// what changed it. It reports how many records it marked; an error marks
// none and keeps all previous misses, accepting neither new misses nor
// held replies from the failed answer.
func (l *AdmissionLedger) ObserveHeld(asked []HeldEffect, held []bool) (int, error) {
	if len(asked) != len(held) {
		return 0, refusal(admission.ReasonInvalid, "firewall answers do not match the held blocks")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return 0, err
	}
	missed := make(map[admission.ActionID]time.Time)
	var gone []HeldEffect
	var since []time.Time
	err = l.db.bolt.View(func(tx *bolt.Tx) error {
		for i, h := range asked {
			_, _, eligible, readErr := heldRecord(tx, h)
			if readErr != nil {
				return readErr
			}
			if !eligible || held[i] {
				continue
			}
			if first, ok := l.missed[h.Action]; ok {
				gone, since = append(gone, h), append(since, first)
			} else {
				missed[h.Action] = now
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	marked := 0
	if len(gone) > 0 {
		err = l.update("gone", func(tx *bolt.Tx) error {
			marked = 0
			for i, h := range gone {
				ok, txErr := markGone(tx, h, since[i])
				if txErr != nil {
					return txErr
				}
				if ok {
					marked++
				}
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	l.missed = missed
	l.heldPass = !l.heldPass
	if !l.heldPass && len(asked) != 0 {
		last := asked[len(asked)-1]
		// Every key was validated before accepting this answer.
		l.heldAfter, _ = admission.EffectRecordKey(last.Action, last.ExpiresAt)
	}
	return marked, nil
}

// markGone marks the record h names gone at since, if it is still a
// verified, held and unclaimed record of h's target.
func markGone(tx *bolt.Tx, h HeldEffect, since time.Time) (bool, error) {
	rec, key, eligible, err := heldRecord(tx, h)
	if err != nil || !eligible {
		return false, err
	}
	if err = addEffectTally(tx, rec.Partition, -1); err != nil {
		return false, err
	}
	rec.Gone = since
	data, err := rec.MarshalBinary()
	if err != nil {
		return false, err
	}
	if err = raiseSchema(tx, admissionSchemaEffectGone); err != nil {
		return false, err
	}
	return true, tx.Bucket([]byte(admissionEffectsBucket)).Put(key, data)
}

// heldRecord checks the identity before the answer counts as a miss.
// A pending, claimed, swept or already gone record contributes nothing.
func heldRecord(tx *bolt.Tx, h HeldEffect) (admission.EffectRecord, []byte, bool, error) {
	key, err := admission.EffectRecordKey(h.Action, h.ExpiresAt)
	if err != nil {
		return admission.EffectRecord{}, nil, false, err
	}
	b := tx.Bucket([]byte(admissionEffectsBucket))
	if b == nil {
		return admission.EffectRecord{}, nil, false, nil
	}
	raw := b.Get(key)
	if raw == nil {
		return admission.EffectRecord{}, nil, false, nil
	}
	rec, err := admission.UnmarshalEffectRecord(key, raw)
	if err != nil {
		return admission.EffectRecord{}, nil, false, err
	}
	if rec.Target != h.Target {
		return admission.EffectRecord{}, nil, false, refusal(admission.ReasonInvalid, "held answer names another target")
	}
	if !rec.Verified() || !rec.Holds() || rec.EvictedBy != "" {
		return admission.EffectRecord{}, nil, false, nil
	}
	return rec, key, true, nil
}
