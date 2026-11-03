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

// effectLayout reports whether the effect records exist and refuses a
// layout schema rules out: none below 12, bucket and tally at 12, and at
// 13, which records nothing of them, both or neither, and only after the
// live start.
func effectLayout(tx *bolt.Tx, schema byte) (bool, error) {
	state := tx.Bucket([]byte(admissionQueueStateBucket))
	if state == nil {
		return false, admission.ErrCorruptRecord
	}
	present := tx.Bucket([]byte(admissionEffectsBucket)) != nil
	tallied := state.Get(effectTallyKey) != nil
	var ok bool
	switch {
	case schema < admissionSchemaEffects:
		ok = !present && !tallied
	case schema == admissionSchemaEffects:
		ok = present && tallied
	default:
		ok = present == tallied && (!present || state.Get(liveStartKey) != nil)
	}
	if !ok {
		return false, admission.ErrCorruptRecord
	}
	return present, nil
}

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
// set slot in the partition of its lane or, when it evicts, of its victim,
// which it claims in the same transaction (spec 5.6: the slot keeps its
// partition). The first record creates the bucket and raises the schema.
func (q *queueTx) holdSlot(c admission.Candidate, a admission.AttemptRecord, e admission.QueueEntry, victim admission.EvictionVictim) error {
	rec := admission.EffectRecord{
		Action: a.Attempt.ID, Target: c.Key.Target, Partition: admission.PartitionOf(a.Lane), Lane: a.Lane,
		Tier: e.Tier, Scope: c.Scope.Key(), Direct: e.Direct, Corroborated: e.Corroborated, ExpiresAt: a.ExpiresAt,
	}
	if victim != (admission.EvictionVictim{}) {
		rec.Partition, rec.Victim = victim.Partition, admission.EffectRef{Action: victim.Action, ExpiresAt: victim.ExpiresAt}
		// An import has no record: this record alone holds the claim.
		if !rec.Victim.Imported() {
			if err := q.claimVictim(rec.Victim, rec.Action); err != nil {
				return err
			}
		}
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
	if err = addEffectTally(q.tx, rec.Partition, 1); err != nil {
		return err
	}
	return b.Put(key, data)
}

// claimVictim names block as the pending evictor of the verified,
// unclaimed record ref names.
func (q *queueTx) claimVictim(ref admission.EffectRef, block admission.ActionID) error {
	key, err := ref.Key()
	if err != nil {
		return err
	}
	b := q.tx.Bucket([]byte(admissionEffectsBucket))
	if b == nil {
		return admission.ErrCorruptRecord
	}
	raw := b.Get(key)
	if raw == nil {
		return admission.ErrCorruptRecord
	}
	rec, err := admission.UnmarshalEffectRecord(key, raw)
	if err != nil {
		return err
	}
	if !rec.Verified() || !rec.Holds() || rec.EvictedBy != "" {
		return admission.ErrCorruptRecord
	}
	rec.EvictedBy = block
	data, err := rec.MarshalBinary()
	if err != nil {
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
// hold needs, and what it did to the victim it claimed (v): a proven
// removal evicts the victim, whose record gives up its slot and stays,
// evicted, until its expiry; a spared victim returns to the pool. An
// attempt without a record (a preview, or one reserved by an earlier
// build) holds no slot.
func (q *queueTx) markApplied(a admission.AttemptRecord, v admission.VictimOutcome) error {
	rec, key, found, err := loadEffect(q.tx, a)
	if err != nil || !found {
		return err
	}
	ceiling, err := loadCeilingState(q.tx)
	if err != nil {
		return err
	}
	if rec.Victim != (admission.EffectRef{}) {
		if err = q.endClaim(rec.Victim, rec.Action, v == admission.VictimRemoved); err != nil {
			return err
		}
	}
	rec.Applied, rec.Elapsed, rec.Victim = q.now, ceiling.Elapsed, admission.EffectRef{}
	data, err := rec.MarshalBinary()
	if err != nil {
		return err
	}
	return q.tx.Bucket([]byte(admissionEffectsBucket)).Put(key, data)
}

// releaseSlot removes the record attempt a holds, if any, and gives back
// the claim on its victim.
func (q *queueTx) releaseSlot(a admission.AttemptRecord) error {
	rec, key, found, err := loadEffect(q.tx, a)
	if err != nil || !found {
		return err
	}
	if rec.Victim != (admission.EffectRef{}) {
		if err = q.endClaim(rec.Victim, rec.Action, false); err != nil {
			return err
		}
	}
	return deleteEffect(q.tx, key, rec)
}

// endClaim ends block's claim on the record ref names: evicted, it gives
// up its slot; otherwise it returns to the victim pool. A victim swept at
// its own expiry needs neither, and an import has no record: the firewall
// stops listing it once it is gone.
func (q *queueTx) endClaim(ref admission.EffectRef, block admission.ActionID, evicted bool) error {
	if ref.Imported() {
		return nil
	}
	key, err := ref.Key()
	if err != nil {
		return err
	}
	b := q.tx.Bucket([]byte(admissionEffectsBucket))
	raw := b.Get(key)
	if raw == nil {
		return nil
	}
	rec, err := admission.UnmarshalEffectRecord(key, raw)
	if err != nil {
		return err
	}
	if rec.EvictedBy != block || rec.Evicted {
		return admission.ErrCorruptRecord
	}
	if evicted {
		if err = addEffectTally(q.tx, rec.Partition, -1); err != nil {
			return err
		}
		rec.Evicted = true
	} else {
		rec.EvictedBy = ""
	}
	data, err := rec.MarshalBinary()
	if err != nil {
		return err
	}
	return b.Put(key, data)
}

func addEffectTally(tx *bolt.Tx, p admission.Partition, delta int) error {
	tally, err := loadEffectTally(tx)
	if err != nil {
		return err
	}
	if tally, err = tally.Add(p, delta); err != nil {
		return err
	}
	return putEffectTally(tx, tally)
}

// deleteEffect removes a record; one that still holds its slot leaves the
// tally, an evicted one left it at its eviction.
func deleteEffect(tx *bolt.Tx, key []byte, rec admission.EffectRecord) error {
	if rec.Holds() {
		if err := addEffectTally(tx, rec.Partition, -1); err != nil {
			return err
		}
	}
	return tx.Bucket([]byte(admissionEffectsBucket)).Delete(key)
}

// claimedVictim is the victim reserved attempt a's record claimed, as an
// intent names it; zero when it claimed none, the victim's record is gone
// at its own expiry, or the firewall no longer lists the import it
// claimed among imports. Execution clears a vanished claim in the same
// transaction so a v1 intent cannot hide a still-recorded removal.
func claimedVictim(tx *bolt.Tx, a admission.AttemptRecord, imports []admission.EvictionVictim) (admission.Victim, error) {
	rec, ownKey, found, err := loadEffect(tx, a)
	if err != nil || !found || rec.Victim == (admission.EffectRef{}) {
		return admission.Victim{}, err
	}
	var raw []byte
	var key []byte
	if rec.Victim.Imported() {
		for _, v := range imports {
			if v.Action == rec.Victim.Action && v.ExpiresAt.Equal(rec.Victim.ExpiresAt) {
				return admission.Victim{Action: v.Action, Target: v.Target, ExpiresAt: v.ExpiresAt}, nil
			}
		}
	} else {
		if key, err = rec.Victim.Key(); err != nil {
			return admission.Victim{}, err
		}
		raw = tx.Bucket([]byte(admissionEffectsBucket)).Get(key)
	}
	if raw == nil {
		rec.Victim = admission.EffectRef{}
		data, encodeErr := rec.MarshalBinary()
		if encodeErr != nil {
			return admission.Victim{}, encodeErr
		}
		return admission.Victim{}, tx.Bucket([]byte(admissionEffectsBucket)).Put(ownKey, data)
	}
	victim, err := admission.UnmarshalEffectRecord(key, raw)
	if err != nil {
		return admission.Victim{}, err
	}
	return admission.Victim{Action: victim.Action, Target: victim.Target, ExpiresAt: victim.ExpiresAt}, nil
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
		if recs[i].Victim != (admission.EffectRef{}) {
			a, err := loadAttempt(tx, recs[i].Action)
			if err != nil {
				return err
			}
			if a.State == admission.StateReserved {
				q := queueTx{tx: tx}
				if err := q.endClaim(recs[i].Victim, recs[i].Action, false); err != nil {
					return err
				}
			}
		}
		if err := deleteEffect(tx, k, recs[i]); err != nil {
			return err
		}
	}
	return nil
}

// proveEffects checks that effect records exist exactly when
// the schema announces them, decode, and match their tally.
func proveEffects(tx *bolt.Tx) error {
	b := tx.Bucket([]byte(admissionEffectsBucket))
	schema := tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey)
	if len(schema) != 1 || schema[0] < admissionSchemaVersion || schema[0] > admissionSchemaEpisodeElapsed {
		return ErrAdmissionSchema
	}
	if present, err := effectLayout(tx, schema[0]); err != nil || !present {
		return err
	}
	var counted admission.EffectTally
	records := map[admission.ActionID]admission.EffectRecord{}
	if err := b.ForEach(func(k, v []byte) error {
		rec, err := admission.UnmarshalEffectRecord(k, v)
		if err != nil {
			return err
		}
		if _, seen := records[rec.Action]; seen {
			return admission.ErrCorruptRecord
		}
		records[rec.Action] = rec
		if rec.Holds() {
			counted, err = counted.Add(rec.Partition, 1)
		}
		return err
	}); err != nil {
		return err
	}
	if !evictionsAgree(tx, records) {
		return admission.ErrCorruptRecord
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

// evictionsAgree proves each eviction from both ends while both records
// remain (either may be swept at its own expiry first): a pending block
// names a victim it claimed, a claimed victim names a pending block that
// names it back, and an evicted victim names a verified block. Retained
// attempts distinguish a swept evictor from a prematurely missing one.
func evictionsAgree(tx *bolt.Tx, records map[admission.ActionID]admission.EffectRecord) bool {
	clock, err := loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
	if err != nil {
		return false
	}
	claimedImports := map[admission.ActionID]bool{}
	for _, rec := range records {
		if rec.Victim.Imported() {
			// No victim record can prove the import has only one claimant.
			if claimedImports[rec.Victim.Action] {
				return false
			}
			claimedImports[rec.Victim.Action] = true
			if rec.Partition != admission.PartitionGeneral || !admission.ImportTier.Less(rec.Tier) {
				return false
			}
		} else if rec.Victim.Action != "" {
			victim, ok := records[rec.Victim.Action]
			if ok {
				if !victim.ExpiresAt.Equal(rec.Victim.ExpiresAt) || victim.EvictedBy != rec.Action || victim.Evicted || victim.Partition != rec.Partition || !evicts(rec, victim) || victim.Target == rec.Target {
					return false
				}
			} else if clock.Now().Before(rec.Victim.ExpiresAt) {
				return false
			}
		}
		if rec.EvictedBy == "" {
			continue
		}
		if block, ok := records[rec.EvictedBy]; ok {
			claimed := block.Victim == admission.EffectRef{Action: rec.Action, ExpiresAt: rec.ExpiresAt}
			if rec.Evicted != block.Verified() || rec.Evicted == claimed || rec.Partition != block.Partition || !evicts(block, rec) || rec.Target == block.Target {
				return false
			}
		} else if raw := tx.Bucket([]byte(admissionAttemptsBucket)).Get([]byte(rec.EvictedBy)); raw != nil {
			a, decodeErr := admission.UnmarshalAttempt(raw)
			if decodeErr != nil || clock.Now().Before(a.ExpiresAt) || (rec.Evicted && a.State != admission.StateVerified) || (!rec.Evicted && a.State != admission.StateExecuting && a.State != admission.StateUnknown) {
				return false
			}
		} else if clock.Now().Before(rec.Applied.Add(admission.HistoryRetention)) {
			// An evictor cannot have finished before its victim was applied.
			return false
		}
	}
	return true
}

// evicts reports whether block may take victim's slot: a strictly lower
// victim, or an equal-tier one rotation took in the partition of the
// block's own lane (spec 5.6: rotation never crosses partitions).
func evicts(block, victim admission.EffectRecord) bool {
	return victim.Tier.Less(block.Tier) || (victim.Tier == block.Tier && admission.PartitionOf(block.Lane) == victim.Partition)
}

// effectsStatus reads the slots the records hold and the expiry of the
// first one.
func effectsStatus(tx *bolt.Tx, out *admission.EffectsStatus) error {
	if err := proveEffects(tx); err != nil {
		return err
	}
	tally, err := loadEffectTally(tx)
	if err != nil {
		return err
	}
	out.General, out.Reserved = tally.General, tally.Reserved
	if b := tx.Bucket([]byte(admissionEffectsBucket)); b != nil {
		cur := b.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			rec, decodeErr := admission.UnmarshalEffectRecord(k, v)
			if decodeErr != nil {
				return decodeErr
			}
			if rec.Holds() {
				out.Next = rec.ExpiresAt
				break
			}
		}
	}
	return nil
}

// A swept evictor still owns its execution intent until finishAttempt
// deletes it. End that claim before deletion as markApplied would (v for
// a verified block); ordinary records use the markApplied/releaseSlot
// paths instead.
func (q *queueTx) endSweptClaim(a admission.AttemptRecord, verified bool, v admission.VictimOutcome) error {
	_, _, found, err := loadEffect(q.tx, a)
	if err != nil || found {
		return err
	}
	in, _, err := loadIntent(q.tx, a.Attempt.ID)
	if err != nil || in.Victim == (admission.Victim{}) {
		return err
	}
	return q.endClaim(admission.EffectRef{Action: in.Victim.Action, ExpiresAt: in.Victim.ExpiresAt}, a.Attempt.ID, verified && v == admission.VictimRemoved)
}

// Both records can expire independently. While either remains it must
// agree with the intent, including the victim address. Missing records
// are accepted only where expiry or history retention permits them.
func proveIntentVictim(tx *bolt.Tx, a admission.AttemptRecord, in admission.Intent) error {
	rec, _, found, err := loadEffect(tx, a)
	if err != nil {
		return err
	}
	ref := admission.EffectRef{}
	if in.Victim != (admission.Victim{}) {
		ref = admission.EffectRef{Action: in.Victim.Action, ExpiresAt: in.Victim.ExpiresAt}
	}
	if found && rec.Victim != ref {
		return admission.ErrCorruptRecord
	}
	b := tx.Bucket([]byte(admissionEffectsBucket))
	if b == nil {
		if ref != (admission.EffectRef{}) {
			return admission.ErrCorruptRecord
		}
		return nil
	}
	// The member may have been swept first. Its claimed victim still
	// proves that the intent cannot omit or substitute the removal.
	if !found {
		if err = b.ForEach(func(k, v []byte) error {
			victim, decodeErr := admission.UnmarshalEffectRecord(k, v)
			if decodeErr != nil {
				return decodeErr
			}
			if victim.EvictedBy == a.Attempt.ID && (victim.Evicted || ref != (admission.EffectRef{Action: victim.Action, ExpiresAt: victim.ExpiresAt})) {
				return admission.ErrCorruptRecord
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if ref == (admission.EffectRef{}) || ref.Imported() {
		return nil
	}
	key, err := ref.Key()
	if err != nil {
		return err
	}
	if raw := b.Get(key); raw != nil {
		victim, decodeErr := admission.UnmarshalEffectRecord(key, raw)
		if decodeErr != nil || victim.Target != in.Victim.Target || victim.EvictedBy != a.Attempt.ID || victim.Evicted {
			return admission.ErrCorruptRecord
		}
	} else {
		clock, clockErr := loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
		if clockErr != nil || clock.Now().Before(ref.ExpiresAt) {
			return admission.ErrCorruptRecord
		}
		if raw := tx.Bucket([]byte(admissionAttemptsBucket)).Get([]byte(ref.Action)); raw != nil {
			victim, decodeErr := admission.UnmarshalAttempt(raw)
			if decodeErr != nil || victim.State != admission.StateVerified || !victim.ExpiresAt.Equal(ref.ExpiresAt) {
				return admission.ErrCorruptRecord
			}
			c, loadErr := loadCandidate(tx, victim.Attempt.Candidate)
			if loadErr != nil || c.Key.Target != in.Victim.Target || c.Key.Kind != admission.KindBlockIP {
				return admission.ErrCorruptRecord
			}
		}
	}
	return nil
}
