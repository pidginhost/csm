package store

import (
	"encoding/binary"
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
	err = tx.Bucket([]byte(admissionRingsBucket)).ForEach(func(k, _ []byte) error {
		if len(k) != 9 {
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

// deleteEvidence removes a record no candidate names, with its report
// links and reference count.
func deleteEvidence(tx *bolt.Tx, id admission.EvidenceID) error {
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
	for s.Loose.Count > admission.MaxLooseEvidence {
		k, v := cur.Seek([]byte{ringLoose})
		if k == nil || k[0] != ringLoose {
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
