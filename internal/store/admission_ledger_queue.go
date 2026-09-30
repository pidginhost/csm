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
	scheduleStateKey = []byte("schedule")
	ingressStateKey  = []byte("ingress")
)

func initializeQueueState(b *bolt.Bucket) error {
	for _, rec := range []struct {
		key   []byte
		value interface{ MarshalBinary() ([]byte, error) }
	}{
		{queueStateKey, admission.QueueState{}},
		{queueCountersKey, admission.QueueCounters{}},
		{scheduleStateKey, admission.ScheduleState{}},
		{ingressStateKey, admission.IngressState{}},
	} {
		data, err := rec.value.MarshalBinary()
		if err != nil {
			return err
		}
		if err = b.Put(rec.key, data); err != nil {
			return err
		}
	}
	return nil
}

// upgradeLedgerToSchemaTwo adds the queue buckets to a schema 1 ledger
// inside the opening transaction. Every live candidate gets an unassessed
// entry holding a general position; the first current reading assesses and
// places it. A damaged candidate or attempt history refuses the upgrade,
// and the transaction leaves the schema 1 ledger exactly as it was. The
// upgrade that completes the chain records the schema.
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
		// The queue reads a live candidate's attempt history on every walk,
		// so the upgrade proves it now rather than commit an unusable queue.
		if c.Attempts > 0 {
			if _, err = currentAttempt(tx, c); err != nil {
				return err
			}
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
	return putQueueState(tx, admission.QueueState{NextSweep: nextSweep})
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
	// storage is loaded on first use; flush trims its rings and writes it
	// back if it changed.
	storage                     admission.StorageState
	storageLoaded, storageDirty bool
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
		if err := putQueueCounters(q.tx, q.counters); err != nil {
			return err
		}
	}
	return q.flushStorage()
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
	if err := q.trimUnreservedRoots(&c); err != nil {
		return err
	}
	c.State, c.Disposition, c.Reason, c.NotBefore = state, reason.Disposition(), reason, time.Time{}
	c.Transitions++
	if err := putCandidate(q.tx, c); err != nil {
		return err
	}
	if err := q.release(lc.id, lc.entry, admission.EventEnded, reason); err != nil {
		return err
	}
	if err := q.gap(admission.GapEnded, reason, 0, lc.entry, lc.id, c, c.Transitions); err != nil {
		return err
	}
	return q.ended(lc.id, c)
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
	err = l.update("revalidate", func(tx *bolt.Tx) error {
		q, txErr := l.openQueue(tx, now)
		if txErr != nil {
			return txErr
		}
		if txErr = q.revalidate(true); txErr != nil {
			return txErr
		}
		return q.flush()
	})
	if err == nil {
		l.revalidated = true
	}
	return err
}

func loadScheduleState(tx *bolt.Tx) (admission.ScheduleState, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(scheduleStateKey)
	if raw == nil {
		return admission.ScheduleState{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalScheduleState(raw)
}

func putScheduleState(tx *bolt.Tx, s admission.ScheduleState) error {
	data, err := s.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Put(scheduleStateKey, data)
}

// unitCost is the block cost of every candidate kind the ledger queues: one
// address, prefix or service tuple (spec 5.6).
const unitCost = 1

// Schedule picks the next candidates to serve under lim and records the
// scheduler's new position; the picks stay queued until the engine
// reserves or ends them. Each lane serves at most what the ceiling lets it
// charge and its history allowance can take now; work that would not fit
// the recovery reserve waits. The first schedule of a reopened ledger
// checks every queued candidate first; later ones end the candidates whose
// deadlines passed. Each pick is revalidated before it is returned: one
// that no longer qualifies ends, and its turn goes to the next candidate.
func (l *AdmissionLedger) Schedule(lim admission.ScheduleLimits) ([]admission.Pick, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return nil, err
	}
	var picks []admission.Pick
	if err = l.update("schedule", func(tx *bolt.Tx) error {
		q, txErr := l.openQueue(tx, now)
		if txErr != nil {
			return txErr
		}
		if picks, txErr = l.scheduleTx(q, lim); txErr != nil {
			return txErr
		}
		return q.flush()
	}); err != nil {
		return nil, err
	}
	l.revalidated = true
	return picks, nil
}

func (l *AdmissionLedger) scheduleTx(q *queueTx, lim admission.ScheduleLimits) ([]admission.Pick, error) {
	// Revalidate directly rather than through sweep: an upgraded ledger's
	// unassessed candidates are due before any deadline is recorded.
	if err := q.revalidate(!l.revalidated); err != nil {
		return nil, err
	}
	st, err := loadScheduleState(q.tx)
	if err != nil {
		return nil, err
	}
	lim, _, err = q.scheduleLimits(lim)
	if err != nil {
		return nil, err
	}
	live, err := q.live()
	if err != nil {
		return nil, err
	}
	items, byID, err := q.scheduleItems(live, lim.RecoveryBytes)
	if err != nil {
		return nil, err
	}
	// A pick that fails revalidation ends, and the schedule is computed
	// again from the stored position without it, so its turn is not spent.
	for {
		picks, next, schedErr := admission.Schedule(items, st, lim)
		if schedErr != nil {
			return nil, schedErr
		}
		refused := map[admission.CandidateID]bool{}
		for _, p := range picks {
			_, reason, checkErr := q.check(byID[p.ID], true)
			if checkErr != nil {
				return nil, checkErr
			}
			if reason == 0 {
				continue
			}
			if checkErr = q.end(byID[p.ID], reason); checkErr != nil {
				return nil, checkErr
			}
			refused[p.ID] = true
		}
		if len(refused) == 0 {
			return picks, putScheduleState(q.tx, next)
		}
		kept := items[:0:0]
		for _, it := range items {
			if !refused[it.ID] {
				kept = append(kept, it)
			}
		}
		items = kept
	}
}

// scheduleLimits lowers the caller's lane bounds to what the ceiling can
// charge now and sets each lane's history budget.
func (q *queueTx) scheduleLimits(lim admission.ScheduleLimits) (admission.ScheduleLimits, admission.CeilingState, error) {
	ceiling, err := loadCeilingState(q.tx)
	if err != nil {
		return lim, ceiling, err
	}
	lim.General = min(lim.General, ceiling.Budget(admission.LaneGeneral))
	lim.Reserved = min(lim.Reserved, ceiling.Budget(admission.LaneDirect))
	lim.RecoveryBytes, err = q.recoveryRoom()
	if err != nil {
		return lim, ceiling, err
	}
	lim.GeneralBytes, lim.ReservedBytes, err = q.historyBudgets()
	return lim, ceiling, err
}

// scheduleItems are the queued candidates as the scheduler sees them, each
// with the history a reservation of it would charge now. One whose details
// would not fit the recovery reserve is not ready: it waits for recovery to
// settle unresolved outcomes.
func (q *queueTx) scheduleItems(live []liveCandidate, room uint64) ([]admission.ScheduleItem, map[admission.CandidateID]liveCandidate, error) {
	byID := map[admission.CandidateID]liveCandidate{}
	var items []admission.ScheduleItem
	for _, lc := range live {
		if lc.c.State != admission.StateQueued {
			continue
		}
		bytes, recovery, fits, err := q.historyNeed(lc, room)
		if err != nil {
			return nil, nil, err
		}
		byID[lc.id] = lc
		items = append(items, admission.ScheduleItem{
			ID: lc.id, Scope: lc.c.Scope.Key(), Tier: lc.entry.Tier, Direct: lc.entry.Direct,
			Corroborated: lc.entry.Corroborated, Queued: lc.c.FirstQueued, Cost: unitCost, Bytes: bytes, Recovery: recovery,
			Ready: fits && !q.now.Before(lc.c.NotBefore),
		})
	}
	return items, byID, nil
}

// NextWake is the earliest admission time at which queued work changes
// without a new report: a retry wait ends, a queued deadline passes, or
// ready work gains ceiling budget or history budget on a lane it can use.
// It is the stored admission time when a schedule would serve ready work
// already. The engine's timer ticks and schedules then. ok is false when
// nothing waits.
func (l *AdmissionLedger) NextWake() (time.Time, bool, error) {
	var wake time.Time
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		clock, err := loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
		if err != nil {
			return err
		}
		q, err := openQueueWith(tx, l.reg, l.Inventory(), clock.Now())
		if err != nil {
			return err
		}
		live, err := q.live()
		if err != nil {
			return err
		}
		// Stored sweep times may outlive a released position. Derive the
		// wake from live queued work in this same read transaction.
		q.state.NextSweep = time.Time{}
		for _, lc := range live {
			if lc.c.State == admission.StateQueued {
				q.noteDeadlines(lc.c, lc.entry)
			}
		}
		wake = q.state.NextSweep
		earliest := func(t time.Time) {
			if wake.IsZero() || t.Before(wake) {
				wake = t
			}
		}
		lim, ceiling, err := q.scheduleLimits(admission.ScheduleLimits{General: admission.MaxCeiling, Reserved: admission.MaxCeiling, Members: admission.MaxBatchMembers})
		if err != nil {
			return err
		}
		items, byID, err := q.scheduleItems(live, lim.RecoveryBytes)
		if err != nil {
			return err
		}
		// A due sweep must assess imported entries before the scheduler
		// can use their tiers. Overdue work needs attention now.
		if !wake.IsZero() && !wake.After(clock.Now()) {
			wake = clock.Now()
			return nil
		}
		var general, reserved bool
		for _, it := range items {
			// A retry cannot become ready at its backoff while recovery
			// space is unavailable. Its validity deadlines still apply.
			if uint64(it.Recovery) > lim.RecoveryBytes {
				continue
			}
			if nb := byID[it.ID].c.NotBefore; nb.After(clock.Now()) {
				earliest(nb)
			}
			if it.Ready {
				general, reserved = true, reserved || it.Direct || it.Corroborated
			}
		}
		if !general {
			return nil
		}
		st, err := loadScheduleState(tx)
		if err != nil {
			return err
		}
		picks, _, err := admission.Schedule(items, st, lim)
		if err != nil {
			return err
		}
		if len(picks) > 0 {
			earliest(clock.Now())
			return nil
		}
		storage, err := q.storageState()
		if err != nil {
			return err
		}
		// Only a lane without ceiling budget needs the window's charges.
		var charges []admission.Charge
		for _, lane := range []admission.Lane{admission.LaneGeneral, admission.LaneDirect} {
			if lane == admission.LaneDirect && !reserved {
				continue
			}
			if ceiling.Budget(lane) > 0 {
				// Probe the actual next head with a full byte budget. Its
				// earned turn, rather than a fixed quantum, sets the timer.
				probe := lim
				probe.Members = 1
				room := lim.GeneralBytes
				if lane == admission.LaneGeneral {
					probe.Reserved, probe.GeneralBytes = 0, admission.MaxHistoryBytes
				} else {
					probe.General, probe.ReservedBytes = 0, admission.MaxHistoryBytes
					room = lim.ReservedBytes
				}
				heads, _, probeErr := admission.Schedule(items, st, probe)
				if probeErr != nil {
					return probeErr
				}
				if len(heads) == 0 {
					continue
				}
				need := uint64(heads[0].Bytes)
				if room < need {
					// Recompute room without the credit cap, including an
					// upgrade's excess, before choosing credit or retirement.
					copy := *storage
					full := admission.NewStorageState()
					copy.General.Credit, copy.Reserved.Credit = full.General.Credit, full.Reserved.Credit
					size, _ := admission.HistoryLanes()
					used := copy.General.Used
					if lane != admission.LaneGeneral {
						_, size = admission.HistoryLanes()
						used = copy.Reserved.Used
					}
					r, retErr := q.retirable(lane, used-min(used, size-need))
					if retErr != nil {
						return retErr
					}
					room = copy.HistoryBudget(lane, r)
				}
				if room >= need {
					if d, ok := storage.UntilHistoryCost(lane, heads[0].Bytes); ok {
						earliest(clock.Now().Add(d))
					}
				} else if at, ok, nextErr := q.nextRetirable(lane); nextErr != nil {
					return nextErr
				} else if ok {
					earliest(at)
				}
				continue
			}
			if charges == nil {
				if charges, err = loadCharges(tx); err != nil {
					return err
				}
			}
			if d, ok := ceiling.UntilBudget(lane, charges, clock.Now()); ok {
				earliest(clock.Now().Add(d))
			}
		}
		return nil
	})
	return wake, !wake.IsZero(), err
}
