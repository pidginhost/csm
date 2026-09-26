package store

import (
	"errors"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var (
	queueStateKey    = []byte("queue")
	queueCountersKey = []byte("counters")
)

func initializeQueueState(b *bolt.Bucket) error {
	state, err := admission.QueueState{}.MarshalBinary()
	if err != nil {
		return err
	}
	counters, err := admission.QueueCounters{}.MarshalBinary()
	if err != nil {
		return err
	}
	if err := b.Put(queueStateKey, state); err != nil {
		return err
	}
	return b.Put(queueCountersKey, counters)
}

// upgradeLedgerToSchemaTwo adds the queue buckets to a schema 1 ledger
// inside the opening transaction. Every live candidate gets an unassessed
// entry holding a general position; the first current reading assesses and
// places it. A damaged candidate refuses the upgrade, and the transaction
// leaves the schema 1 ledger exactly as it was.
func upgradeLedgerToSchemaTwo(tx *bolt.Tx) error {
	for _, name := range admissionQueueBuckets {
		if _, err := tx.CreateBucket([]byte(name)); err != nil {
			return err
		}
	}
	queue := tx.Bucket([]byte(admissionQueueBucket))
	live := 0
	var nextSweep time.Time
	err := tx.Bucket([]byte(admissionCandidatesBucket)).ForEach(func(k, v []byte) error {
		c, err := admission.UnmarshalCandidate(v)
		if err != nil {
			return err
		}
		if id, _ := c.ID(); string(id) != string(k) {
			return admission.ErrCorruptRecord
		}
		if c.State.Terminal() {
			return nil
		}
		live++
		if c.State == admission.StateQueued && (nextSweep.IsZero() || c.FirstQueued.Before(nextSweep)) {
			nextSweep = c.FirstQueued
		}
		// Eligibility is unknown until a current reading. Every imported
		// candidate must fit the general partition without borrowing reserve.
		if live > admission.PartitionGeneral.DurableCapacity() {
			return refusal(admission.ReasonQueueOverflow, "legacy queue exceeds unassessed capacity")
		}
		data, err := admission.QueueEntry{Partition: admission.PartitionGeneral}.MarshalBinary()
		if err != nil {
			return err
		}
		return queue.Put(k, data)
	})
	if err != nil {
		return err
	}
	if err := initializeQueueState(tx.Bucket([]byte(admissionQueueStateBucket))); err != nil {
		return err
	}
	// Unassessed queued work is due at the first current reading, even if
	// an arrival reaches the ledger before an explicit recovery sweep.
	if err := putQueueState(tx, admission.QueueState{NextSweep: nextSweep}); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion})
}

func loadQueueState(tx *bolt.Tx) (admission.QueueState, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(queueStateKey)
	if raw == nil {
		return admission.QueueState{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalQueueState(raw)
}

func loadQueueCounters(tx *bolt.Tx) (admission.QueueCounters, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(queueCountersKey)
	if raw == nil {
		return admission.QueueCounters{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalQueueCounters(raw)
}

// loadQueueEntry loads the entry of a live candidate. A live candidate
// without one, or an entry without its candidate, is a damaged ledger.
func loadQueueEntry(tx *bolt.Tx, id admission.CandidateID) (admission.QueueEntry, error) {
	raw := tx.Bucket([]byte(admissionQueueBucket)).Get([]byte(id))
	if raw == nil {
		return admission.QueueEntry{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalQueueEntry(raw)
}

func putQueueState(tx *bolt.Tx, s admission.QueueState) error {
	data, err := s.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Put(queueStateKey, data)
}

func putQueueCounters(tx *bolt.Tx, q admission.QueueCounters) error {
	data, err := q.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Put(queueCountersKey, data)
}

func putQueueEntry(tx *bolt.Tx, id admission.CandidateID, q admission.QueueEntry) error {
	data, err := q.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueBucket)).Put([]byte(id), data)
}

// queueTx is the queue bookkeeping of one write transaction. State and
// counters load once, the view is built on first use, and flush writes back
// what changed, so every queue change commits with the candidate records it
// depends on.
type queueTx struct {
	tx       *bolt.Tx
	reg      *admission.Registry
	inv      *admission.Inventory
	now      time.Time
	state    admission.QueueState
	counters admission.QueueCounters
	view     *admission.QueueView
	// seq orders the arrivals decided in this transaction.
	seq                     uint64
	stateDirty, countsDirty bool
}

func (l *AdmissionLedger) openQueue(tx *bolt.Tx, now time.Time) (*queueTx, error) {
	return openQueueWith(tx, l.reg, l.Inventory(), now)
}

func openQueueWith(tx *bolt.Tx, reg *admission.Registry, inv *admission.Inventory, now time.Time) (*queueTx, error) {
	state, err := loadQueueState(tx)
	if err != nil {
		return nil, err
	}
	counters, err := loadQueueCounters(tx)
	if err != nil {
		return nil, err
	}
	return &queueTx{tx: tx, reg: reg, inv: inv, now: now, state: state, counters: counters}, nil
}

func (q *queueTx) flush() error {
	if q.view != nil && q.view.Cursors() != q.state.Cursors {
		q.state.Cursors, q.stateDirty = q.view.Cursors(), true
	}
	if q.stateDirty {
		if err := putQueueState(q.tx, q.state); err != nil {
			return err
		}
	}
	if q.countsDirty {
		return putQueueCounters(q.tx, q.counters)
	}
	return nil
}

func queueItem(id admission.CandidateID, c admission.Candidate, e admission.QueueEntry) admission.QueueItem {
	return admission.QueueItem{
		Key: string(id), Scope: c.Scope.Key(), Partition: e.Partition, Tier: e.Tier, Eligible: e.Eligible(),
		Queued: c.FirstQueued, Fixed: c.State != admission.StateQueued || !e.Assessed(),
	}
}

type liveCandidate struct {
	id    admission.CandidateID
	c     admission.Candidate
	entry admission.QueueEntry
}

// live loads every live candidate with its entry. An entry must name a
// live candidate: an ended or missing one is a damaged ledger.
func (q *queueTx) live() ([]liveCandidate, error) {
	var out []liveCandidate
	err := q.tx.Bucket([]byte(admissionQueueBucket)).ForEach(func(k, raw []byte) error {
		entry, err := admission.UnmarshalQueueEntry(raw)
		if err != nil {
			return err
		}
		id := admission.CandidateID(k)
		c, err := loadCandidate(q.tx, id)
		if err != nil || c.State.Terminal() {
			return admission.ErrCorruptRecord
		}
		if c.Attempts > 0 {
			if _, err = currentAttempt(q.tx, c); err != nil {
				return err
			}
		}
		out = append(out, liveCandidate{id: id, c: c, entry: entry})
		return nil
	})
	return out, err
}

func (q *queueTx) queueView() (*admission.QueueView, error) {
	if q.view != nil {
		return q.view, nil
	}
	all, err := q.live()
	if err != nil {
		return nil, err
	}
	v := admission.NewDurableQueueView(q.state.Cursors)
	for _, lc := range all {
		if err := v.Add(queueItem(lc.id, lc.c, lc.entry)); err != nil {
			return nil, admission.ErrCorruptRecord
		}
	}
	q.view = v
	return v, nil
}

func (q *queueTx) count(event admission.QueueEvent, reason admission.Reason, tier admission.Tier) error {
	q.countsDirty = true
	return q.counters.Add(admission.CountKey{Event: event, Reason: reason, Class: tier.Class, Severity: tier.Severity})
}

// noteDeadlines brings the next sweep forward to the earliest time the
// queued candidate may need attention without a new report.
func (q *queueTx) noteDeadlines(c admission.Candidate, e admission.QueueEntry) {
	due := c.AgeOut
	if c.Attempts > 0 && c.ExpiresAt.Before(due) {
		due = c.ExpiresAt
	}
	if !e.Assessed() {
		due = q.now
	} else if e.NextChange.Before(due) {
		due = e.NextChange
	}
	if q.state.NextSweep.IsZero() || due.Before(q.state.NextSweep) {
		q.state.NextSweep, q.stateDirty = due, true
	}
}

// release deletes a candidate's entry when it leaves the queue for good and
// counts why. A queue event with no reason counts nothing.
func (q *queueTx) release(id admission.CandidateID, e admission.QueueEntry, event admission.QueueEvent, reason admission.Reason) error {
	if err := q.tx.Bucket([]byte(admissionQueueBucket)).Delete([]byte(id)); err != nil {
		return err
	}
	if q.view != nil {
		q.view.Remove(string(id))
	}
	if event == 0 {
		return nil
	}
	return q.count(event, reason, e.Tier)
}

// end ends a queued candidate for reason and releases its position.
func (q *queueTx) end(lc liveCandidate, reason admission.Reason) error {
	state, ok := terminalFor[reason.Disposition()]
	if !ok || lc.c.State != admission.StateQueued || !admission.CanTransition(lc.c.State, state) {
		return admission.ErrTransitionConflict
	}
	c := lc.c
	c.State, c.Disposition, c.Reason, c.NotBefore = state, reason.Disposition(), reason, time.Time{}
	c.Transitions++
	if err := putCandidate(q.tx, c); err != nil {
		return err
	}
	return q.release(lc.id, lc.entry, admission.EventEnded, reason)
}

// endByKey ends the queued candidate a view decision displaced.
func (q *queueTx) endByKey(key string, reason admission.Reason) error {
	id := admission.CandidateID(key)
	c, err := loadCandidate(q.tx, id)
	if err != nil {
		return err
	}
	e, err := loadQueueEntry(q.tx, id)
	if err != nil {
		return err
	}
	return q.end(liveCandidate{id: id, c: c, entry: e}, reason)
}

// entryFor turns an assessment into the entry fields it decides.
func entryFor(a admission.Assessment) admission.QueueEntry {
	return admission.QueueEntry{Tier: a.Tier, Direct: a.DirectC3, Corroborated: a.Corroborated, NextChange: a.NextChange}
}

// insert decides a queue position for a new candidate and records its
// entry. A displaced candidate ends as queue overflow in the same
// transaction; a refused arrival is a queue overflow refusal.
func (q *queueTx) insert(id admission.CandidateID, c admission.Candidate, e admission.QueueEntry) error {
	v, err := q.queueView()
	if err != nil {
		return err
	}
	q.seq++
	it := queueItem(id, c, e)
	it.Seq = q.seq
	placed, ok := v.Admit(it)
	if !ok {
		return refusal(admission.ReasonQueueOverflow, "queue has no position for the candidate")
	}
	if placed.Displaced {
		if err := q.endByKey(placed.Victim.Key, admission.ReasonQueueOverflow); err != nil {
			return err
		}
	}
	e.Partition = placed.Partition
	q.noteDeadlines(c, e)
	return putQueueEntry(q.tx, id, e)
}

// reassess records a new assessment for a queued candidate and returns the
// candidate as stored. One that lost its reserved eligibility leaves the
// reserved partition and is placed again among general work, where it can
// displace newer work or, finding no position, end as queue overflow. One
// that gained eligibility moves to a free reserved position.
func (q *queueTx) reassess(lc liveCandidate, next admission.QueueEntry) (admission.Candidate, error) {
	v, err := q.queueView()
	if err != nil {
		return lc.c, err
	}
	next.Partition = lc.entry.Partition
	v.Remove(string(lc.id))
	switch {
	case lc.entry.Partition == admission.PartitionReserved && !next.Eligible():
		placed, ok := v.Admit(queueItem(lc.id, lc.c, next))
		if !ok {
			lc.entry = next
			if err = q.end(lc, admission.ReasonQueueOverflow); err != nil {
				return lc.c, err
			}
			return loadCandidate(q.tx, lc.id)
		}
		if placed.Displaced {
			if err = q.endByKey(placed.Victim.Key, admission.ReasonQueueOverflow); err != nil {
				return lc.c, err
			}
		}
		next.Partition = placed.Partition
	case next.Eligible() && v.Room(admission.PartitionReserved):
		next.Partition = admission.PartitionReserved
		err = v.Add(queueItem(lc.id, lc.c, next))
	default:
		err = v.Add(queueItem(lc.id, lc.c, next))
	}
	if err != nil {
		return lc.c, err
	}
	q.noteDeadlines(lc.c, next)
	return lc.c, putQueueEntry(q.tx, lc.id, next)
}

// check revalidates a queued candidate against current policy and
// inventory and, when timed, assesses it at q.now. A refusal is the reason
// the candidate must end; any other error is returned. A root that is no
// longer published is damage, not a refusal: evidence is never removed.
func (q *queueTx) check(lc liveCandidate, timed bool) (admission.Assessment, admission.Reason, error) {
	c := lc.c
	roots, err := loadRoots(q.tx, q.reg, c.Roots)
	if errors.Is(err, admission.ErrEvidenceUnpublished) {
		return admission.Assessment{}, 0, admission.ErrCorruptRecord
	}
	if _, refused := admission.ReasonOf(err); err != nil && !refused {
		return admission.Assessment{}, 0, err
	}
	if timed && (!q.now.Before(c.AgeOut) || (c.Attempts > 0 && !q.now.Before(c.ExpiresAt))) {
		return admission.Assessment{}, admission.ReasonStale, nil
	}
	if err == nil {
		_, err = scopeOwner(q.inv, roots)
	}
	var a admission.Assessment
	if err == nil && timed {
		a, err = admission.Assess(c.Key.Target, roots, q.now)
	}
	if reason, refused := admission.ReasonOf(err); refused {
		return admission.Assessment{}, reason, nil
	}
	return a, 0, err
}

// revalidate checks queued candidates in queue order, oldest first. With
// all, every one is checked against policy, inventory and time; otherwise
// only those whose deadline has passed or that were never assessed. It then
// recomputes the next sweep from what is still queued.
func (q *queueTx) revalidate(all bool) error {
	live, err := q.live()
	if err != nil {
		return err
	}
	if _, err = q.queueView(); err != nil {
		return err
	}
	sort.Slice(live, func(i, j int) bool {
		if !live[i].c.FirstQueued.Equal(live[j].c.FirstQueued) {
			return live[i].c.FirstQueued.Before(live[j].c.FirstQueued)
		}
		return live[i].id < live[j].id
	})
	type assessedCandidate struct {
		liveCandidate
		next admission.QueueEntry
	}
	var staying, moving []assessedCandidate
	for _, lc := range live {
		if lc.c.State != admission.StateQueued {
			continue
		}
		due := !lc.entry.Assessed() || !q.now.Before(lc.entry.NextChange) || !q.now.Before(lc.c.AgeOut) ||
			(lc.c.Attempts > 0 && !q.now.Before(lc.c.ExpiresAt))
		if !all && !due {
			continue
		}
		a, reason, checkErr := q.check(lc, true)
		if checkErr != nil {
			return checkErr
		}
		if reason != 0 {
			if err = q.end(lc, reason); err != nil {
				return err
			}
			continue
		}
		next := entryFor(a)
		if lc.entry.Partition == admission.PartitionReserved && !next.Eligible() {
			q.view.Remove(string(lc.id))
			moving = append(moving, assessedCandidate{lc, next})
		} else {
			staying = append(staying, assessedCandidate{lc, next})
		}
	}
	// Release invalid work and refresh every retained tier before choosing
	// victims. Otherwise an older demotion competes with expired occupancy
	// or yesterday's priority, and can be dropped despite available room.
	for _, pending := range append(staying, moving...) {
		if _, err = q.reassess(pending.liveCandidate, pending.next); err != nil {
			return err
		}
	}
	return q.resweep()
}

// resweep recomputes the next sweep from the queued candidates.
func (q *queueTx) resweep() error {
	live, err := q.live()
	if err != nil {
		return err
	}
	q.state.NextSweep, q.stateDirty = time.Time{}, true
	for _, lc := range live {
		if lc.c.State == admission.StateQueued {
			q.noteDeadlines(lc.c, lc.entry)
		}
	}
	return nil
}

// sweep revalidates the candidates whose deadlines have passed, if any.
func (q *queueTx) sweep() error {
	if q.state.NextSweep.IsZero() || q.now.Before(q.state.NextSweep) {
		return nil
	}
	return q.revalidate(false)
}

// checkOwners ends every queued candidate whose roots no longer resolve to
// a current owner or pass current policy. It needs no clock.
func (q *queueTx) checkOwners() error {
	live, err := q.live()
	if err != nil {
		return err
	}
	for _, lc := range live {
		if lc.c.State != admission.StateQueued {
			continue
		}
		_, reason, err := q.check(lc, false)
		if err != nil {
			return err
		}
		if reason != 0 {
			if err = q.end(lc, reason); err != nil {
				return err
			}
		}
	}
	return nil
}

// Revalidate checks every queued candidate against current policy,
// inventory and the admission clock. A candidate that no longer qualifies
// ends with the refusal's reason; the others take their new assessment,
// which can move them between partitions.
func (l *AdmissionLedger) Revalidate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return err
	}
	return l.update("revalidate", func(tx *bolt.Tx) error {
		q, err := l.openQueue(tx, now)
		if err != nil {
			return err
		}
		if err = q.revalidate(true); err != nil {
			return err
		}
		return q.flush()
	})
}
