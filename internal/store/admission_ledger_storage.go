package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var storageStateKey = []byte("storage")

// Ring kinds of the rings bucket. An entry's key is its kind and its
// big-endian position; its value is the ID it keeps.
const (
	ringEnded = 'e'
	ringLoose = 'l'
)

func ringKey(kind byte, pos uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte{kind}, pos)
}

func loadStorageState(tx *bolt.Tx) (admission.StorageState, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(storageStateKey)
	if raw == nil {
		return admission.StorageState{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalStorageState(raw)
}

func putStorageState(tx *bolt.Tx, s admission.StorageState) error {
	data, err := s.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Put(storageStateKey, data)
}

// historyCostOf is the history cost of c from the stored size of each root.
func historyCostOf(tx *bolt.Tx, c admission.Candidate) (uint32, error) {
	evidence := tx.Bucket([]byte(admissionEvidenceBucket))
	sizes := make([]int, len(c.Roots))
	for i, id := range c.Roots {
		raw := evidence.Get([]byte(id))
		if raw == nil {
			return 0, admission.ErrCorruptRecord
		}
		sizes[i] = len(raw)
	}
	return admission.HistoryCost(c, sizes)
}

// putHistoryEntry stores an entry with its retirement keys.
func putHistoryEntry(tx *bolt.Tx, id admission.CandidateID, h admission.HistoryEntry) error {
	data, err := h.MarshalBinary()
	if err != nil {
		return err
	}
	keys, err := h.RetireKeys(id)
	if err != nil {
		return err
	}
	retire := tx.Bucket([]byte(admissionRetireBucket))
	for _, k := range keys {
		if err = retire.Put(k, nil); err != nil {
			return err
		}
	}
	return tx.Bucket([]byte(admissionHistoryBucket)).Put([]byte(id), data)
}

// upgradeLedgerToSchemaFour adds storage accounting to a schema 3 ledger
// inside the opening transaction. Every stored candidate's roots are
// counted. A candidate that ended before any attempt joins the ended ring
// in queue order. One with an attempt gets a history entry charged its
// history cost on the allowance of its latest attempt; an unresolved one is
// pinned in the recovery reserve. Evidence no candidate names joins the
// loose ring in observation order. Each ring keeps its newest entries. The
// allowances start without credit, since recent spend is unknown, and may
// start over their size. This upgrade records the schema.
func upgradeLedgerToSchemaFour(tx *bolt.Tx) error {
	if err := validateUnownedRows(tx); err != nil {
		return err
	}
	state := tx.Bucket([]byte(admissionQueueStateBucket))
	if state.Get(storageStateKey) != nil || state.Bucket(storageStateKey) != nil {
		return admission.ErrCorruptRecord
	}
	for _, name := range admissionStorageBuckets {
		if _, err := tx.CreateBucket([]byte(name)); err != nil {
			return err
		}
	}
	clock, err := loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
	if err != nil {
		return err
	}
	var s admission.StorageState
	refs := map[admission.EvidenceID]uint32{}
	type ending struct {
		id admission.CandidateID
		c  admission.Candidate
	}
	var endings []ending
	err = tx.Bucket([]byte(admissionCandidatesBucket)).ForEach(func(k, v []byte) error {
		c, walkErr := admission.UnmarshalCandidate(v)
		if walkErr != nil {
			return walkErr
		}
		id, _ := c.ID()
		if string(id) != string(k) {
			return admission.ErrCorruptRecord
		}
		for _, root := range c.Roots {
			refs[root]++
		}
		if c.Attempts == 0 {
			if c.State.Terminal() {
				endings = append(endings, ending{id, c})
			}
			return nil
		}
		last, walkErr := currentAttempt(tx, c)
		if walkErr != nil {
			return walkErr
		}
		cost, walkErr := historyCostOf(tx, c)
		if walkErr != nil {
			return walkErr
		}
		h := admission.HistoryEntry{RootMask: (1 << len(c.Roots)) - 1}
		if last.Lane == 0 || last.Lane == admission.LaneGeneral {
			h.General, s.General.Used = cost, s.General.Used+uint64(cost)
		} else {
			h.Reserved, s.Reserved.Used = cost, s.Reserved.Used+uint64(cost)
		}
		if c.State.Terminal() {
			// An outcome ended when its attempt finished. A queue ending
			// after a failed attempt left no time: count it from now.
			h.Ended = clock.Now()
			if last.State == c.State {
				h.Ended = last.Finished
			}
			if c.State == admission.StateUnknown {
				h.Pinned = true
				if s, walkErr = s.PinHistory(h.General, h.Reserved); walkErr != nil {
					return walkErr
				}
			} else {
				h.Eligible, _ = admission.HistoryTimes(h.Ended, c.ExpiresAt, c.State == admission.StateVerified)
			}
		}
		return putHistoryEntry(tx, id, h)
	})
	if err != nil {
		return err
	}
	// Prove every root before pruning old candidates can erase its count.
	for root := range refs {
		if tx.Bucket([]byte(admissionEvidenceBucket)).Get([]byte(root)) == nil {
			return admission.ErrCorruptRecord
		}
	}
	sort.Slice(endings, func(i, j int) bool {
		if !endings[i].c.FirstQueued.Equal(endings[j].c.FirstQueued) {
			return endings[i].c.FirstQueued.Before(endings[j].c.FirstQueued)
		}
		return endings[i].id < endings[j].id
	})
	rings := tx.Bucket([]byte(admissionRingsBucket))
	candidates := tx.Bucket([]byte(admissionCandidatesBucket))
	for i, e := range endings {
		if len(endings)-i > admission.MaxEndedCandidates {
			for _, root := range e.c.Roots {
				refs[root]--
			}
			if err = candidates.Delete([]byte(e.id)); err != nil {
				return err
			}
			continue
		}
		var pos uint64
		s.Ended, pos = s.Ended.Push()
		if err = rings.Put(ringKey(ringEnded, pos), []byte(e.id)); err != nil {
			return err
		}
	}
	type looseEvidence struct {
		id admission.EvidenceID
		at time.Time
	}
	var loose []looseEvidence
	var expired []admission.EvidenceID
	evidence, references := tx.Bucket([]byte(admissionEvidenceBucket)), tx.Bucket([]byte(admissionRefsBucket))
	err = evidence.ForEach(func(k, v []byte) error {
		e, walkErr := admission.UnmarshalEvidence(v)
		if walkErr != nil {
			return corruptRecord(walkErr)
		}
		id := admission.EvidenceID(k)
		if e.ID() != id {
			return admission.ErrCorruptRecord
		}
		n, named := refs[id]
		delete(refs, id)
		if !named || n == 0 {
			if named && !clock.Now().Before(e.ObservedAt().Add(admission.SupportLookback)) {
				expired = append(expired, id)
				return nil
			}
			loose = append(loose, looseEvidence{id, e.ObservedAt()})
			return nil
		}
		data, walkErr := admission.EvidenceRefs{Refs: n}.MarshalBinary()
		if walkErr != nil {
			return walkErr
		}
		return references.Put(k, data)
	})
	if err != nil {
		return err
	}
	for _, id := range expired {
		if err = deleteEvidence(tx, id); err != nil {
			return err
		}
	}
	sort.Slice(loose, func(i, j int) bool {
		if !loose[i].at.Equal(loose[j].at) {
			return loose[i].at.Before(loose[j].at)
		}
		return loose[i].id < loose[j].id
	})
	reports := tx.Bucket([]byte(admissionReportsBucket))
	for i, e := range loose {
		if len(loose)-i > admission.MaxLooseEvidence {
			if err = evidence.Delete([]byte(e.id)); err != nil {
				return err
			}
			if err = reports.Delete([]byte(e.id)); err != nil {
				return err
			}
			continue
		}
		var pos uint64
		s.Loose, pos = s.Loose.Push()
		if err = rings.Put(ringKey(ringLoose, pos), []byte(e.id)); err != nil {
			return err
		}
		data, encErr := admission.EvidenceRefs{Loose: pos}.MarshalBinary()
		if encErr != nil {
			return encErr
		}
		if err = references.Put([]byte(e.id), data); err != nil {
			return err
		}
	}
	if err = putStorageState(tx, s); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion})
}

// loadStorage loads the storage state and proves it against the stored
// entries: the history entries must add up to each allowance's usage and
// the recovery reserve, and each ring must hold as many entries as it
// counts, at positions it has handed out.
func loadStorage(tx *bolt.Tx) (admission.StorageState, error) {
	s, err := loadStorageState(tx)
	if err != nil {
		return s, err
	}
	var general, reserved, recovery uint64
	err = tx.Bucket([]byte(admissionHistoryBucket)).ForEach(func(k, v []byte) error {
		if _, parseErr := admission.ParseCandidateID(string(k)); parseErr != nil {
			return admission.ErrCorruptRecord
		}
		h, decodeErr := admission.UnmarshalHistoryEntry(v)
		switch {
		case decodeErr != nil:
			return decodeErr
		case h.Pinned:
			recovery += uint64(h.Charged())
		default:
			general += uint64(h.General)
			reserved += uint64(h.Reserved)
		}
		return nil
	})
	if err != nil {
		return s, err
	}
	if general != s.General.Used || reserved != s.Reserved.Used || recovery != s.Recovery {
		return s, admission.ErrCorruptRecord
	}
	var ended, loose admission.RingState
	err = tx.Bucket([]byte(admissionRingsBucket)).ForEach(func(k, v []byte) error {
		if len(k) != 9 || v == nil {
			return admission.ErrCorruptRecord
		}
		pos := binary.BigEndian.Uint64(k[1:])
		if pos == 0 {
			return admission.ErrCorruptRecord
		}
		switch k[0] {
		case ringEnded:
			ended.Count++
			ended.Last = max(ended.Last, pos)
		case ringLoose:
			loose.Count++
			loose.Last = max(loose.Last, pos)
		default:
			return admission.ErrCorruptRecord
		}
		return nil
	})
	if err != nil {
		return s, err
	}
	if ended.Count != s.Ended.Count || ended.Last > s.Ended.Last || loose.Count != s.Loose.Count || loose.Last > s.Loose.Last {
		return s, admission.ErrCorruptRecord
	}
	return s, proveStorageLinks(tx)
}

// Storage is the committed storage state.
func (l *AdmissionLedger) Storage() (admission.StorageState, error) {
	var s admission.StorageState
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		s, err = loadStorageState(tx)
		return err
	})
	return s, err
}

// storageState is the transaction's storage state, loaded on first use.
func (q *queueTx) storageState() (*admission.StorageState, error) {
	if !q.storageLoaded {
		s, err := loadStorageState(q.tx)
		if err != nil {
			return nil, err
		}
		q.storage, q.storageLoaded = s, true
	}
	return &q.storage, nil
}

func loadRefs(tx *bolt.Tx, id admission.EvidenceID) (admission.EvidenceRefs, error) {
	raw := tx.Bucket([]byte(admissionRefsBucket)).Get([]byte(id))
	if raw == nil {
		return admission.EvidenceRefs{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalEvidenceRefs(raw)
}

func putRefs(tx *bolt.Tx, id admission.EvidenceID, r admission.EvidenceRefs) error {
	data, err := r.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionRefsBucket)).Put([]byte(id), data)
}

// loosen gives evidence no candidate names the next loose position.
func (q *queueTx) loosen(id admission.EvidenceID) error {
	s, err := q.storageState()
	if err != nil {
		return err
	}
	var pos uint64
	s.Loose, pos = s.Loose.Push()
	q.storageDirty = true
	if err = q.tx.Bucket([]byte(admissionRingsBucket)).Put(ringKey(ringLoose, pos), []byte(id)); err != nil {
		return err
	}
	return putRefs(q.tx, id, admission.EvidenceRefs{Loose: pos})
}

// name records one more stored candidate naming id as a root. Loose
// evidence leaves its ring position.
func (q *queueTx) name(id admission.EvidenceID) error {
	r, err := loadRefs(q.tx, id)
	if err != nil {
		return err
	}
	if r.Loose != 0 {
		rings := q.tx.Bucket([]byte(admissionRingsBucket))
		key := ringKey(ringLoose, r.Loose)
		if string(rings.Get(key)) != string(id) {
			return admission.ErrCorruptRecord
		}
		s, err := q.storageState()
		if err != nil {
			return err
		}
		if s.Loose, err = s.Loose.Remove(); err != nil {
			return err
		}
		q.storageDirty = true
		if err = rings.Delete(key); err != nil {
			return err
		}
		r = admission.EvidenceRefs{}
	}
	r.Refs++
	return putRefs(q.tx, id, r)
}

// unname records that one stored candidate no longer names id. Evidence no
// candidate names keeps a loose position while it could still support a
// candidate, and is removed once it cannot.
func (q *queueTx) unname(id admission.EvidenceID) error {
	r, err := loadRefs(q.tx, id)
	if err != nil {
		return err
	}
	if r.Refs == 0 {
		return admission.ErrCorruptRecord
	}
	if r.Refs--; r.Refs > 0 {
		return putRefs(q.tx, id, r)
	}
	e, err := loadStoredEvidence(q.tx, id)
	if errors.Is(err, admission.ErrEvidenceUnpublished) {
		return admission.ErrCorruptRecord
	}
	if err != nil {
		return err
	}
	if q.now.Before(e.ObservedAt().Add(admission.SupportLookback)) {
		return q.loosen(id)
	}
	return deleteEvidence(q.tx, id)
}

// ended records a candidate that has just ended. One that ended before any
// attempt is not history: it takes the next ended position, and only the
// newest are kept. An admitted one's history is dated: it may be retired
// after the review window and, if verified, its effect's lifetime; an
// unresolved outcome is pinned in the recovery reserve instead.
func (q *queueTx) ended(id admission.CandidateID, c admission.Candidate) error {
	if c.Attempts > 0 {
		h, found, err := loadHistoryEntry(q.tx, id)
		if err != nil {
			return err
		}
		if !found || !h.Ended.IsZero() {
			return admission.ErrCorruptRecord
		}
		h.Ended = q.now
		if c.State == admission.StateUnknown {
			s, err := q.storageState()
			if err != nil {
				return err
			}
			if *s, err = s.PinHistory(h.General, h.Reserved); err != nil {
				return err
			}
			h.Pinned, q.storageDirty = true, true
		} else {
			h.Eligible, _ = admission.HistoryTimes(q.now, c.ExpiresAt, c.State == admission.StateVerified)
		}
		return putHistoryEntry(q.tx, id, h)
	}
	s, err := q.storageState()
	if err != nil {
		return err
	}
	var pos uint64
	s.Ended, pos = s.Ended.Push()
	q.storageDirty = true
	return q.tx.Bucket([]byte(admissionRingsBucket)).Put(ringKey(ringEnded, pos), []byte(id))
}

// deleteEvidence removes a record no candidate names, with its report
// links and reference count.
func deleteEvidence(tx *bolt.Tx, id admission.EvidenceID) error {
	// Prove the records before removal so eviction cannot conceal damage.
	e, err := loadStoredEvidence(tx, id)
	if err != nil {
		return corruptRecord(err)
	}
	if _, err = loadReports(tx, e); err != nil {
		return err
	}
	for _, name := range []string{admissionEvidenceBucket, admissionReportsBucket, admissionRefsBucket} {
		if err := tx.Bucket([]byte(name)).Delete([]byte(id)); err != nil {
			return err
		}
	}
	return nil
}

// flushStorage keeps each ring within its bound, oldest out first, and
// writes the state back if it changed. It runs when the transaction's
// work is done, so a record named late in the transaction is kept.
func (q *queueTx) flushStorage() error {
	if !q.storageDirty {
		return nil
	}
	s := &q.storage
	cur := q.tx.Bucket([]byte(admissionRingsBucket)).Cursor()
	// Removed endings can loosen their roots, so they go first.
	for s.Ended.Count > admission.MaxEndedCandidates {
		k, v := cur.Seek([]byte{ringEnded})
		if len(k) != 9 || k[0] != ringEnded || v == nil || binary.BigEndian.Uint64(k[1:]) == 0 {
			return admission.ErrCorruptRecord
		}
		id := admission.CandidateID(v)
		c, err := loadCandidate(q.tx, id)
		if errors.Is(err, errCandidateMissing) || (err == nil && (!c.State.Terminal() || c.Attempts != 0)) {
			return admission.ErrCorruptRecord
		}
		if err != nil {
			return err
		}
		if err = cur.Delete(); err != nil {
			return err
		}
		if err = q.tx.Bucket([]byte(admissionCandidatesBucket)).Delete([]byte(id)); err != nil {
			return err
		}
		for _, root := range c.Roots {
			if err = q.unname(root); err != nil {
				return err
			}
		}
		if s.Ended, err = s.Ended.Remove(); err != nil {
			return err
		}
	}
	for s.Loose.Count > admission.MaxLooseEvidence {
		k, v := cur.Seek([]byte{ringLoose})
		if len(k) != 9 || k[0] != ringLoose || v == nil || binary.BigEndian.Uint64(k[1:]) == 0 {
			return admission.ErrCorruptRecord
		}
		id := admission.EvidenceID(v)
		r, err := loadRefs(q.tx, id)
		if err != nil {
			return err
		}
		if r.Loose != binary.BigEndian.Uint64(k[1:]) {
			return admission.ErrCorruptRecord
		}
		if err = cur.Delete(); err != nil {
			return err
		}
		if err = deleteEvidence(q.tx, id); err != nil {
			return err
		}
		if s.Loose, err = s.Loose.Remove(); err != nil {
			return err
		}
	}
	q.storageDirty = false
	return putStorageState(q.tx, *s)
}

func loadHistoryEntry(tx *bolt.Tx, id admission.CandidateID) (admission.HistoryEntry, bool, error) {
	raw := tx.Bucket([]byte(admissionHistoryBucket)).Get([]byte(id))
	if raw == nil {
		return admission.HistoryEntry{}, false, nil
	}
	h, err := admission.UnmarshalHistoryEntry(raw)
	return h, true, err
}

// chargeHistory charges an admitted candidate's history to the allowance of
// the lane it was admitted on: what its history cost grew by since its last
// reservation, from the lane's credit and within its allowance. A
// reservation is refused while the candidate would not fit the recovery
// reserve if its outcome were unresolved.
func (q *queueTx) chargeHistory(id admission.CandidateID, c admission.Candidate, lane admission.Lane) error {
	cost, err := historyCostOf(q.tx, c)
	if err != nil {
		return err
	}
	h, found, err := loadHistoryEntry(q.tx, id)
	if err != nil {
		return err
	}
	if c.Attempts > 1 && !found || found && !h.Ended.IsZero() {
		return admission.ErrCorruptRecord
	}
	s, err := q.storageState()
	if err != nil {
		return err
	}
	if room, roomErr := q.recoveryRoom(); roomErr != nil {
		return roomErr
	} else if uint64(max(cost, h.Charged())) > room {
		err = refusal(admission.ReasonPendingRecovery, "outstanding outcomes fill the recovery reserve")
		return err
	}
	if cost <= h.Charged() {
		return nil
	}
	grown := cost - h.Charged()
	// A charge the credit cannot cover is refused after this, and the
	// whole reservation, retirements included, rolls back.
	if err = q.retireForRoom(lane, uint64(grown)); err != nil {
		return err
	}
	next, err := s.ChargeHistory(lane, grown)
	if err != nil {
		return err
	}
	if lane == admission.LaneGeneral {
		h.General += grown
	} else {
		h.Reserved += grown
	}
	h.RootMask = (1 << len(c.Roots)) - 1
	if err = putHistoryEntry(q.tx, id, h); err != nil {
		return err
	}
	*s, q.storageDirty = next, true
	return nil
}

// retireForRoom retires ended history of lane's allowance that may be
// retired, oldest first, until the allowance has room for need bytes or
// nothing more may be retired.
func (q *queueTx) retireForRoom(lane admission.Lane, need uint64) error {
	s, err := q.storageState()
	if err != nil {
		return err
	}
	kind := retireKind(lane)
	cur := q.tx.Bucket([]byte(admissionRetireBucket)).Cursor()
	for s.HistoryRoom(lane) < need {
		k, _ := cur.Seek([]byte{kind})
		if k == nil || k[0] != kind {
			return nil
		}
		_, at, id, err := admission.ParseRetireKey(k)
		if err != nil {
			return err
		}
		if at.After(q.now) {
			return nil
		}
		if err = q.retire(id, k); err != nil {
			return err
		}
	}
	return nil
}

// retirementsPerTick bounds the retirements one Tick makes, so a backlog
// after downtime clears over several ticks instead of in one long clock
// transaction. Pressure retires what it needs at once.
const retirementsPerTick = 64

// retireAtTarget retires ended history whose target has passed, oldest
// target first, at most retirementsPerTick of them.
func (q *queueTx) retireAtTarget() error {
	cur := q.tx.Bucket([]byte(admissionRetireBucket)).Cursor()
	for n := 0; n < retirementsPerTick; n++ {
		k, _ := cur.Seek([]byte{admission.RetireTarget})
		if k == nil || k[0] != admission.RetireTarget {
			return nil
		}
		_, at, id, err := admission.ParseRetireKey(k)
		if err != nil {
			return err
		}
		if at.After(q.now) {
			return nil
		}
		if err = q.retire(id, k); err != nil {
			return err
		}
	}
	return nil
}

// meterStorage credits a tick's elapsed time to the history allowances and
// retires the history whose target has passed, in the clock's transaction.
func (l *AdmissionLedger) meterStorage(tx *bolt.Tx, tick admission.ClockTick) error {
	q, err := openQueueWith(tx, l.reg, l.Inventory(), tick.Now)
	if err != nil {
		return err
	}
	s, err := q.storageState()
	if err != nil {
		return err
	}
	if *s, err = s.Advance(tick.Elapsed); err != nil {
		return err
	}
	q.storageDirty = true
	if err = q.retireAtTarget(); err != nil {
		return err
	}
	return q.flushStorage()
}

// retire removes an ended candidate's details: its record, its attempts,
// its history entry and index keys. Its bytes return to their allowances
// and its roots are released. key is the index key that led here; it must
// be one of the entry's own.
func (q *queueTx) retire(id admission.CandidateID, key []byte) error {
	h, found, err := loadHistoryEntry(q.tx, id)
	if err != nil {
		return err
	}
	if !found {
		return admission.ErrCorruptRecord
	}
	c, err := loadCandidate(q.tx, id)
	if errors.Is(err, errCandidateMissing) || (err == nil && (!c.State.Terminal() || c.Attempts == 0)) {
		return admission.ErrCorruptRecord
	}
	if err != nil {
		return err
	}
	keys, err := h.RetireKeys(id)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(keys, func(k []byte) bool { return bytes.Equal(k, key) }) {
		return admission.ErrCorruptRecord
	}
	// Deletion must not conceal missing or inconsistent attempt history.
	if _, err = currentAttempt(q.tx, c); err != nil {
		return err
	}
	retireIndex := q.tx.Bucket([]byte(admissionRetireBucket))
	for _, k := range keys {
		if retireIndex.Get(k) == nil {
			return admission.ErrCorruptRecord
		}
		if err = retireIndex.Delete(k); err != nil {
			return err
		}
	}
	attempts := q.tx.Bucket([]byte(admissionAttemptsBucket))
	for seq := uint32(1); seq <= c.Attempts; seq++ {
		a, idErr := admission.NewAttempt(id, seq)
		if idErr != nil {
			return idErr
		}
		if err = attempts.Delete([]byte(a.ID)); err != nil {
			return err
		}
	}
	for _, name := range []string{admissionHistoryBucket, admissionCandidatesBucket} {
		if err = q.tx.Bucket([]byte(name)).Delete([]byte(id)); err != nil {
			return err
		}
	}
	for _, root := range c.Roots {
		if err = q.unname(root); err != nil {
			return err
		}
	}
	s, err := q.storageState()
	if err != nil {
		return err
	}
	if *s, err = s.ReleaseHistory(h.General, h.Reserved); err != nil {
		return err
	}
	q.storageDirty = true
	return nil
}

// historyNeed is what reserving lc now would charge its lane's history, and
// whether its details would fit the recovery reserve.
func (q *queueTx) historyNeed(lc liveCandidate, room uint64) (uint32, uint32, bool, error) {
	cost, err := historyCostOf(q.tx, lc.c)
	if err != nil {
		return 0, 0, false, err
	}
	h, found, err := loadHistoryEntry(q.tx, lc.id)
	if err != nil {
		return 0, 0, false, err
	}
	if lc.c.Attempts > 0 && !found {
		return 0, 0, false, admission.ErrCorruptRecord
	}
	recovery := max(cost, h.Charged())
	fits := uint64(recovery) <= room
	if cost <= h.Charged() {
		return 0, recovery, fits, nil
	}
	return cost - h.Charged(), recovery, fits, nil
}

func retireKind(lane admission.Lane) byte {
	if lane == admission.LaneGeneral {
		return admission.RetireGeneral
	}
	return admission.RetireReserved
}

// retirable is the bytes of lane's allowance that ended history which may
// be retired now holds, counted until they reach limit.
func (q *queueTx) retirable(lane admission.Lane, limit uint64) (uint64, error) {
	kind := retireKind(lane)
	var sum uint64
	cur := q.tx.Bucket([]byte(admissionRetireBucket)).Cursor()
	for k, _ := cur.Seek([]byte{kind}); k != nil && k[0] == kind && sum < limit; k, _ = cur.Next() {
		_, at, id, err := admission.ParseRetireKey(k)
		if err != nil {
			return 0, err
		}
		if at.After(q.now) {
			break
		}
		h, found, err := loadHistoryEntry(q.tx, id)
		if err != nil {
			return 0, err
		}
		if !found {
			return 0, admission.ErrCorruptRecord
		}
		if lane == admission.LaneGeneral {
			sum += uint64(h.General)
		} else {
			sum += uint64(h.Reserved)
		}
	}
	return sum, nil
}

// historyBudgets are the history bytes each lane may charge now: its
// credit, bounded by the room its allowance has once retirable history is
// retired.
func (q *queueTx) historyBudgets() (general, reserved uint64, err error) {
	s, err := q.storageState()
	if err != nil {
		return 0, 0, err
	}
	budget := func(lane admission.Lane) (uint64, error) {
		size, _ := admission.HistoryLanes()
		used := s.General.Used
		if lane != admission.LaneGeneral {
			_, size = admission.HistoryLanes()
			used = s.Reserved.Used
		}
		// Subtract first so even a grandfathered overfull allowance cannot wrap.
		need := used - min(used, size-s.HistoryCredit(lane))
		r, walkErr := q.retirable(lane, need)
		return s.HistoryBudget(lane, r), walkErr
	}
	if general, err = budget(admission.LaneGeneral); err != nil {
		return 0, 0, err
	}
	reserved, err = budget(admission.LaneDirect)
	return general, reserved, err
}

// nextRetirable is when the oldest history of lane's allowance that may not
// be retired yet becomes retirable.
func (q *queueTx) nextRetirable(lane admission.Lane) (time.Time, bool, error) {
	kind := retireKind(lane)
	after := fmt.Appendf(nil, "%c%019d", kind, q.now.UnixNano()+1)
	k, _ := q.tx.Bucket([]byte(admissionRetireBucket)).Cursor().Seek(after)
	if k == nil || k[0] != kind {
		return time.Time{}, false, nil
	}
	_, at, _, err := admission.ParseRetireKey(k)
	return at, err == nil, err
}

// validateUnownedRows checks rows that candidate and evidence walks do not
// necessarily reach. An upgrade must not silently retain or discard them.
func validateUnownedRows(tx *bolt.Tx) error {
	if err := tx.Bucket([]byte(admissionReportsBucket)).ForEach(func(k, v []byte) error {
		if v == nil {
			return admission.ErrCorruptRecord
		}
		raw := tx.Bucket([]byte(admissionEvidenceBucket)).Get(k)
		e, err := admission.UnmarshalEvidence(raw)
		if err != nil || string(e.ID()) != string(k) {
			return admission.ErrCorruptRecord
		}
		_, err = loadReports(tx, e)
		return err
	}); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionAttemptsBucket)).ForEach(func(k, v []byte) error {
		a, err := admission.UnmarshalAttempt(v)
		if err != nil || string(a.Attempt.ID) != string(k) {
			return admission.ErrCorruptRecord
		}
		c, err := loadCandidate(tx, a.Attempt.Candidate)
		if err != nil || a.Attempt.Seq > c.Attempts {
			return admission.ErrCorruptRecord
		}
		return nil
	})
}

// recoveryRoom also holds space for every outstanding attempt. Finishing
// several such attempts as unknown cannot overbook the recovery reserve.
func (q *queueTx) recoveryRoom() (uint64, error) {
	s, err := q.storageState()
	if err != nil {
		return 0, err
	}
	if s.Recovery >= admission.RecoveryReserveBytes {
		return 0, nil
	}
	room := uint64(admission.RecoveryReserveBytes) - s.Recovery
	live, err := q.live()
	if err != nil {
		return 0, err
	}
	for _, lc := range live {
		if lc.c.State != admission.StateReserved && lc.c.State != admission.StateExecuting {
			continue
		}
		h, found, loadErr := loadHistoryEntry(q.tx, lc.id)
		if loadErr != nil {
			return 0, loadErr
		}
		if !found {
			return 0, admission.ErrCorruptRecord
		}
		if uint64(h.Charged()) > room {
			return 0, nil
		}
		room -= uint64(h.Charged())
	}
	return room, nil
}

// remapHistoryRoots preserves the paid roots' identity when sorting new
// retry support changes their positions in the candidate.
func (q *queueTx) remapHistoryRoots(c admission.Candidate, merged []admission.EvidenceID) error {
	if c.Attempts == 0 {
		return nil
	}
	id, _ := c.ID()
	h, found, err := loadHistoryEntry(q.tx, id)
	if err != nil {
		return err
	}
	if !found || h.RootMask == 0 || h.RootMask>>len(c.Roots) != 0 {
		return admission.ErrCorruptRecord
	}
	var mask uint32
	for i, root := range c.Roots {
		if h.RootMask&(1<<i) != 0 {
			mask |= 1 << slices.Index(merged, root)
		}
	}
	h.RootMask = mask
	return putHistoryEntry(q.tx, id, h)
}

// trimUnreservedRoots returns retry-only support to the loose ring when a
// queued candidate ends without another reservation. Paid evidence stays.
func (q *queueTx) trimUnreservedRoots(c *admission.Candidate) error {
	if c.Attempts == 0 {
		return nil
	}
	id, _ := c.ID()
	h, found, err := loadHistoryEntry(q.tx, id)
	if err != nil {
		return err
	}
	if !found || h.RootMask == 0 || h.RootMask>>len(c.Roots) != 0 {
		return admission.ErrCorruptRecord
	}
	var roots []admission.EvidenceID
	for i, root := range c.Roots {
		if h.RootMask&(1<<i) != 0 {
			roots = append(roots, root)
		} else if err = q.unname(root); err != nil {
			return err
		}
	}
	c.Roots = roots
	h.RootMask = (1 << len(roots)) - 1
	return putHistoryEntry(q.tx, id, h)
}

// proveStorageLinks checks ownership as well as totals. No uncharged row,
// missing reference or foreign retirement key may survive a reopen.
func proveStorageLinks(tx *bolt.Tx) error {
	if err := validateUnownedRows(tx); err != nil {
		return err
	}
	refs := map[admission.EvidenceID]uint32{}
	history := map[string]bool{}
	ended := map[string]bool{}
	queued := map[string]bool{}
	keys := map[string]bool{}
	if err := tx.Bucket([]byte(admissionCandidatesBucket)).ForEach(func(k, _ []byte) error {
		c, err := loadCandidate(tx, admission.CandidateID(k))
		if err != nil {
			return corruptRecord(err)
		}
		for _, root := range c.Roots {
			refs[root]++
		}
		if !c.State.Terminal() {
			queued[string(k)] = true
		}
		if c.Attempts == 0 {
			if c.State.Terminal() {
				ended[string(k)] = true
			}
			return nil
		}
		last, err := currentAttempt(tx, c)
		if err != nil {
			return err
		}
		h, found, err := loadHistoryEntry(tx, admission.CandidateID(k))
		if err != nil {
			return err
		}
		if !found || h.RootMask == 0 || h.RootMask>>len(c.Roots) != 0 || c.State.Terminal() == h.Ended.IsZero() || h.Pinned != (c.State == admission.StateUnknown) {
			return admission.ErrCorruptRecord
		}
		if c.State != admission.StateQueued && h.RootMask != (1<<len(c.Roots))-1 {
			return admission.ErrCorruptRecord
		}
		paid := c
		paid.Roots = nil
		for i, root := range c.Roots {
			if h.RootMask&(1<<i) != 0 {
				paid.Roots = append(paid.Roots, root)
			}
		}
		cost, err := historyCostOf(tx, paid)
		if err != nil || h.Charged() < cost {
			return admission.ErrCorruptRecord
		}
		if c.State.Terminal() {
			if last.State == c.State && !h.Ended.Equal(last.Finished) {
				return admission.ErrCorruptRecord
			}
			if !h.Pinned {
				eligible, _ := admission.HistoryTimes(h.Ended, c.ExpiresAt, c.State == admission.StateVerified)
				if !h.Eligible.Equal(eligible) {
					return admission.ErrCorruptRecord
				}
			}
		}
		history[string(k)] = true
		retire, err := h.RetireKeys(admission.CandidateID(k))
		if err != nil {
			return err
		}
		for _, key := range retire {
			keys[string(key)] = true
		}
		return nil
	}); err != nil {
		return err
	}
	for _, check := range []struct {
		name string
		want map[string]bool
	}{
		{admissionHistoryBucket, history}, {admissionRetireBucket, keys}, {admissionQueueBucket, queued},
	} {
		b := tx.Bucket([]byte(check.name))
		if err := b.ForEach(func(k, v []byte) error {
			if !check.want[string(k)] || b.Bucket(k) != nil {
				return admission.ErrCorruptRecord
			}
			if check.name == admissionRetireBucket && len(v) != 0 {
				return admission.ErrCorruptRecord
			}
			if check.name == admissionQueueBucket {
				if _, err := admission.UnmarshalQueueEntry(v); err != nil {
					return err
				}
			}
			delete(check.want, string(k))
			return nil
		}); err != nil {
			return err
		}
		if len(check.want) != 0 {
			return admission.ErrCorruptRecord
		}
	}
	loose := map[admission.EvidenceID]uint64{}
	if err := tx.Bucket([]byte(admissionRingsBucket)).ForEach(func(k, v []byte) error {
		if len(k) != 9 {
			return admission.ErrCorruptRecord
		}
		switch k[0] {
		case ringEnded:
			if !ended[string(v)] {
				return admission.ErrCorruptRecord
			}
			delete(ended, string(v))
		case ringLoose:
			id := admission.EvidenceID(v)
			if refs[id] != 0 || loose[id] != 0 {
				return admission.ErrCorruptRecord
			}
			loose[id] = binary.BigEndian.Uint64(k[1:])
		default:
			return admission.ErrCorruptRecord
		}
		return nil
	}); err != nil {
		return err
	}
	if len(ended) != 0 {
		return admission.ErrCorruptRecord
	}
	evidence := map[string]bool{}
	if err := tx.Bucket([]byte(admissionEvidenceBucket)).ForEach(func(k, v []byte) error {
		e, err := admission.UnmarshalEvidence(v)
		if err != nil || string(e.ID()) != string(k) {
			return admission.ErrCorruptRecord
		}
		r, err := loadRefs(tx, e.ID())
		if err != nil {
			return err
		}
		if r.Refs != refs[e.ID()] || r.Loose != loose[e.ID()] {
			return admission.ErrCorruptRecord
		}
		delete(refs, e.ID())
		delete(loose, e.ID())
		evidence[string(k)] = true
		return nil
	}); err != nil {
		return err
	}
	if len(refs) != 0 || len(loose) != 0 {
		return admission.ErrCorruptRecord
	}
	return tx.Bucket([]byte(admissionRefsBucket)).ForEach(func(k, _ []byte) error {
		if !evidence[string(k)] {
			return admission.ErrCorruptRecord
		}
		return nil
	})
}
