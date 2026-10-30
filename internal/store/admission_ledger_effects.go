package store

import (
	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

const (
	// admissionEffectsBucket holds one record per automatic block that
	// holds a temporary set slot, keyed by expiry (spec 5.6).
	admissionEffectsBucket = "adm:effects"
	// admissionSchemaEffects is the schema of a ledger holding effect
	// records: their bucket and their tally. The first record writes it;
	// older builds refuse the ledger rather than forget the slots its
	// blocks hold.
	admissionSchemaEffects = 12
)

// effectTallyKey holds the effect records' tally in the queue state bucket.
var effectTallyKey = []byte("effects")

// loadEffectTally is the stored tally; zero before the first record.
func loadEffectTally(tx *bolt.Tx) (admission.EffectTally, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(effectTallyKey)
	if raw == nil {
		return admission.EffectTally{}, nil
	}
	return admission.UnmarshalEffectTally(raw)
}

func putEffectTally(tx *bolt.Tx, t admission.EffectTally) error {
	data, err := t.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Put(effectTallyKey, data)
}

// effectKey is the key of the record attempt a holds, if any.
func effectKey(a admission.AttemptRecord) ([]byte, error) {
	return admission.EffectRecordKey(a.Attempt.ID, a.ExpiresAt)
}

// holdSlot records that reserved attempt a of block c holds a temporary
// set slot in the partition of its lane. The first record creates the
// bucket and raises the schema.
func (q *queueTx) holdSlot(c admission.Candidate, a admission.AttemptRecord, e admission.QueueEntry) error {
	rec := admission.EffectRecord{
		Action: a.Attempt.ID, Target: c.Key.Target, Partition: admission.PartitionOf(a.Lane), Lane: a.Lane,
		Tier: e.Tier, Scope: c.Scope.Key(), Direct: e.Direct, Corroborated: e.Corroborated, ExpiresAt: a.ExpiresAt,
	}
	key, err := rec.Key()
	if err != nil {
		return err
	}
	data, err := rec.MarshalBinary()
	if err != nil {
		return err
	}
	b, err := q.tx.CreateBucketIfNotExists([]byte(admissionEffectsBucket))
	if err != nil {
		return err
	}
	if b.Get(key) != nil {
		return admission.ErrCorruptRecord
	}
	if err = raiseSchema(q.tx, admissionSchemaEffects); err != nil {
		return err
	}
	tally, err := loadEffectTally(q.tx)
	if err != nil {
		return err
	}
	if tally, err = tally.Add(rec.Partition, 1); err != nil {
		return err
	}
	if err = putEffectTally(q.tx, tally); err != nil {
		return err
	}
	return b.Put(key, data)
}

// loadEffect is the record attempt a holds; false when it holds none.
func loadEffect(tx *bolt.Tx, a admission.AttemptRecord) (admission.EffectRecord, []byte, bool, error) {
	b := tx.Bucket([]byte(admissionEffectsBucket))
	if b == nil {
		return admission.EffectRecord{}, nil, false, nil
	}
	key, err := effectKey(a)
	if err != nil {
		return admission.EffectRecord{}, nil, false, err
	}
	raw := b.Get(key)
	if raw == nil {
		return admission.EffectRecord{}, key, false, nil
	}
	rec, err := admission.UnmarshalEffectRecord(key, raw)
	return rec, key, err == nil, err
}

// markApplied records the verified application of attempt a's block at
// admission time, with the ceiling's elapsed time as the proof a minimum
// hold needs. An attempt without a record (a preview, or one reserved by
// an earlier build) holds no slot.
func (q *queueTx) markApplied(a admission.AttemptRecord) error {
	rec, key, found, err := loadEffect(q.tx, a)
	if err != nil || !found {
		return err
	}
	ceiling, err := loadCeilingState(q.tx)
	if err != nil {
		return err
	}
	rec.Applied, rec.Elapsed = q.now, ceiling.Elapsed
	data, err := rec.MarshalBinary()
	if err != nil {
		return err
	}
	return q.tx.Bucket([]byte(admissionEffectsBucket)).Put(key, data)
}

// releaseSlot removes the record attempt a holds, if any.
func (q *queueTx) releaseSlot(a admission.AttemptRecord) error {
	rec, key, found, err := loadEffect(q.tx, a)
	if err != nil || !found {
		return err
	}
	return deleteEffect(q.tx, key, rec)
}

func deleteEffect(tx *bolt.Tx, key []byte, rec admission.EffectRecord) error {
	tally, err := loadEffectTally(tx)
	if err != nil {
		return err
	}
	if tally, err = tally.Add(rec.Partition, -1); err != nil {
		return err
	}
	if err = putEffectTally(tx, tally); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionEffectsBucket)).Delete(key)
}

// sweepEffects removes the records whose expiry has passed at a trusted
// admission time now, soonest first. A degraded reading proves no expiry,
// as for an unknown outcome's retirement, so it removes nothing.
func sweepEffects(tx *bolt.Tx, tick admission.ClockTick) error {
	b := tx.Bucket([]byte(admissionEffectsBucket))
	if b == nil || tick.Degraded {
		return nil
	}
	var expired [][]byte
	var recs []admission.EffectRecord
	cur := b.Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		rec, err := admission.UnmarshalEffectRecord(k, v)
		if err != nil {
			return err
		}
		if tick.Now.Before(rec.ExpiresAt) {
			break
		}
		expired, recs = append(expired, k), append(recs, rec)
	}
	for i, k := range expired {
		if err := deleteEffect(tx, k, recs[i]); err != nil {
			return err
		}
	}
	return nil
}

// proveEffects checks at opening that effect records exist exactly when
// the schema announces them, decode, and match their tally.
func proveEffects(tx *bolt.Tx) error {
	b := tx.Bucket([]byte(admissionEffectsBucket))
	announced := tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey)[0] >= admissionSchemaEffects
	tallied := tx.Bucket([]byte(admissionQueueStateBucket)).Get(effectTallyKey) != nil
	if (b != nil) != announced || announced != tallied {
		return admission.ErrCorruptRecord
	}
	if b == nil {
		return nil
	}
	var counted admission.EffectTally
	if err := b.ForEach(func(k, v []byte) error {
		rec, err := admission.UnmarshalEffectRecord(k, v)
		if err != nil {
			return err
		}
		counted, err = counted.Add(rec.Partition, 1)
		return err
	}); err != nil {
		return err
	}
	tally, err := loadEffectTally(tx)
	if err != nil {
		return err
	}
	if tally != counted {
		return admission.ErrCorruptRecord
	}
	return nil
}

// effectsStatus reads the slots the records hold and the expiry of the
// first one.
func effectsStatus(tx *bolt.Tx, out *admission.EffectsStatus) error {
	tally, err := loadEffectTally(tx)
	if err != nil {
		return err
	}
	out.General, out.Reserved = tally.General, tally.Reserved
	if b := tx.Bucket([]byte(admissionEffectsBucket)); b != nil {
		if k, v := b.Cursor().First(); k != nil {
			rec, decodeErr := admission.UnmarshalEffectRecord(k, v)
			if decodeErr != nil {
				return decodeErr
			}
			out.Next = rec.ExpiresAt
		}
	}
	return nil
}
