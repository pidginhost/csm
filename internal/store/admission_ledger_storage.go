package store

import (
	"encoding/binary"
	"errors"
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
	return s, nil
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
// newest are kept.
func (q *queueTx) ended(id admission.CandidateID, c admission.Candidate) error {
	if c.Attempts > 0 {
		return nil
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
