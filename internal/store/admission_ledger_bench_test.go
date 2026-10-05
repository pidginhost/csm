package store

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// These benchmarks measure the queue at its worst: every durable general
// position held and every candidate carrying the maximum number of roots.
// Each call below scans the whole live queue. They measure and do not gate.

// fillRoots queues n candidates in one transaction, each from roots fresh
// observations of its own documentation address.
func (f *ledgerFixture) fillRoots(n, roots int) {
	f.t.Helper()
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	if err := f.l.update("fill", func(tx *bolt.Tx) error {
		q, err := f.l.openQueue(tx, f.l.now)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			f.fills++
			target := fmt.Sprintf("2001:db8::%x", f.fills)
			var ids []admission.EvidenceID
			for r := 0; r < roots; r++ {
				e := f.mint(evidenceSpec{target: target, cursor: fmt.Sprintf("fill=%d/%d", f.fills, r)})
				if _, err = publishTx(q, f.reg, e); err != nil {
					return err
				}
				ids = append(ids, e.ID())
			}
			req := f.request(target, ids[0], ids[1:]...)
			key := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: req.Episode, Generation: req.Generation}
			id, err := key.ID()
			if err != nil {
				return err
			}
			all, err := rootSet(req)
			if err != nil {
				return err
			}
			if _, _, err = f.l.enqueueTx(q, req, key, id, all); err != nil {
				return err
			}
		}
		return q.flush()
	}); err != nil {
		f.t.Fatal(err)
	}
}

func fullLedger(b *testing.B) *ledgerFixture {
	b.Helper()
	f := newLedgerFixture(b)
	f.fillRoots(admission.PartitionGeneral.DurableCapacity(), admission.MaxRoots)
	if n := f.candidateCount(); n != admission.PartitionGeneral.DurableCapacity() {
		b.Fatalf("queued %d candidates", n)
	}
	return f
}

// The history budget, not the batch bound, limits these picks: each
// candidate carries the most roots.
func BenchmarkAdmissionLedgerScheduleFullQueue(b *testing.B) {
	f := fullLedger(b)
	lim := admission.ScheduleLimits{General: admission.MaxBatchMembers, Members: admission.MaxBatchMembers}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if picks, err := f.l.Schedule(lim); err != nil || len(picks) == 0 {
			b.Fatalf("schedule: %d picks, %v", len(picks), err)
		}
	}
}

func BenchmarkAdmissionLedgerRevalidateFullQueue(b *testing.B) {
	f := fullLedger(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := f.l.Revalidate(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdmissionLedgerRefreshInventoryFullQueue(b *testing.B) {
	f := fullLedger(b)
	obs := admission.InventoryObservation{Accounts: []string{"alice", "bob"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := f.l.RefreshInventory(obs); err != nil {
			b.Fatal(err)
		}
	}
}

// A full group of arrivals against the full queue: each one is refused for
// overflow, the costliest path through admission.
func BenchmarkAdmissionLedgerEnqueueGroupFullQueue(b *testing.B) {
	f := fullLedger(b)
	f.begin()
	next := netip.MustParseAddr("2001:db8:1::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		group := make([]admission.Arrival, admission.MaxArrivalGroup)
		for j := range group {
			f.fills++
			group[j] = f.arrival(evidenceSpec{target: next.String(), cursor: fmt.Sprintf("group=%d", f.fills)})
			next = next.Next()
		}
		b.StartTimer()
		results, _, err := f.l.EnqueueGroup(group, nil)
		if err != nil || len(results) != len(group) {
			b.Fatalf("group: %d results, %v", len(results), err)
		}
	}
}

// fullWindow sets the largest ceiling and fills its whole window with
// general and reserved charges spent now, as a sustained flood would.
func fullWindow(b *testing.B) *ledgerFixture {
	b.Helper()
	f := newLedgerFixture(b)
	if err := f.l.SetCeiling(admission.MaxCeiling); err != nil {
		b.Fatal(err)
	}
	general, reserved := admission.CeilingLanes(admission.MaxCeiling)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		for i := uint32(0); i < general+reserved; i++ {
			lane := admission.LaneGeneral
			if i >= general {
				lane = admission.LaneCorroborated
			}
			if err := putCharge(tx, f.ledgerCharge(f.wall, i+1, lane, 0), true); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	return f
}

// Opening proves every retained charge against the ceiling's usage.
func BenchmarkAdmissionLedgerOpenFullWindow(b *testing.B) {
	f := fullWindow(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			b.Fatal(err)
		}
	}
}

// Ready work behind a full window: NextWake walks the charges to find when
// a lane gains room.
func BenchmarkAdmissionLedgerNextWakeFullWindow(b *testing.B) {
	f := fullWindow(b)
	f.queued()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok, err := f.l.NextWake(); err != nil || !ok {
			b.Fatalf("wake: %v %v", ok, err)
		}
	}
}

// One tick releasing a whole window at once, after an hour's gap.
func BenchmarkAdmissionLedgerTickReleasesFullWindow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f := fullWindow(b)
		b.StartTimer()
		f.tickAt(f.wall.Add(admission.CeilingWindow))
		b.StopTimer()
		if s := f.ceilingState(); s.General.Used != 0 || s.Reserved.Used != 0 {
			b.Fatalf("window not released: %+v", s)
		}
		b.StartTimer()
	}
}

// A tick proves the retained window even when no charge can leave it.
func BenchmarkAdmissionLedgerTickRetainsFullWindow(b *testing.B) {
	f := fullWindow(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.tickAt(f.wall)
	}
	b.StopTimer()
	if s := f.ceilingState(); s.General.Used+s.Reserved.Used != admission.MaxCeiling {
		b.Fatalf("retained window changed: %+v", s)
	}
}

// Ready work across a full queue of the largest candidates: NextWake
// computes every candidate's history and runs a schedule to decide whether
// work is due now.
func BenchmarkAdmissionLedgerNextWakeFullQueue(b *testing.B) {
	f := fullLedger(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok, err := f.l.NextWake(); err != nil || !ok {
			b.Fatalf("wake: %v %v", ok, err)
		}
	}
}

// fullHistory fills every allowance and the recovery reserve with the
// smallest history entries, the most entries the budgets can hold, and
// fills both rings.
func fullHistory(b *testing.B) *ledgerFixture {
	b.Helper()
	f := newLedgerFixture(b)
	id := f.queued()
	base, loadErr := f.l.Candidate(id)
	if loadErr != nil {
		b.Fatal(loadErr)
	}
	general, reserved := admission.HistoryLanes()
	if setupErr := f.db.bolt.Update(func(tx *bolt.Tx) error {
		s, err := loadStorageState(tx)
		if err != nil {
			return err
		}
		rootRefs, err := loadRefs(tx, base.Roots[0])
		if err != nil {
			return err
		}
		var generation uint32 = 1000000000
		put := func(lane admission.Lane, pinned bool) (uint32, error) {
			generation++
			c := base
			c.Key.Generation = generation
			c.Attempts, c.State, c.Disposition, c.Transitions = 1, admission.StateVerified, admission.DispositionApplied, 4
			if pinned {
				c.State, c.Disposition = admission.StateUnknown, admission.DispositionUnknown
			}
			c.ExpiresAt = f.wall.Add(time.Hour)
			cid, memberErr := c.ID()
			if memberErr != nil {
				return 0, memberErr
			}
			a, memberErr := admission.NewAttempt(cid, 1)
			if memberErr != nil {
				return 0, memberErr
			}
			cost, memberErr := historyCostOf(tx, c)
			if memberErr != nil {
				return 0, memberErr
			}
			if memberErr = putCandidate(tx, c); memberErr != nil {
				return 0, memberErr
			}
			if memberErr = putAttempt(tx, admission.AttemptRecord{Attempt: a, State: c.State, Disposition: c.Disposition, ExpiresAt: c.ExpiresAt, Reserved: f.wall, Finished: f.wall, Lane: lane}); memberErr != nil {
				return 0, memberErr
			}
			h := admission.HistoryEntry{RootMask: 1, Ended: f.wall, Eligible: f.wall.Add(admission.HistoryRetention), Pinned: pinned}
			if pinned {
				h.Eligible = time.Time{}
			}
			if lane == admission.LaneGeneral {
				h.General = cost
			} else {
				h.Reserved = cost
			}
			rootRefs.Refs++
			return cost, putHistoryEntry(tx, cid, h)
		}
		// The fixed-width generation keeps every candidate at the same cost.
		sized := base
		sized.Key.Generation = generation
		cost, err := historyCostOf(tx, sized)
		if err != nil {
			return err
		}
		for _, allowance := range []struct {
			used   *uint64
			size   uint64
			lane   admission.Lane
			pinned bool
		}{
			{&s.General.Used, general, admission.LaneGeneral, false},
			{&s.Reserved.Used, reserved, admission.LaneDirect, false},
			{&s.Recovery, admission.RecoveryReserveBytes, admission.LaneGeneral, true},
		} {
			for *allowance.used+uint64(cost) <= allowance.size {
				actual, putErr := put(allowance.lane, allowance.pinned)
				if putErr != nil {
					return putErr
				}
				if actual != cost {
					return fmt.Errorf("benchmark history cost changed")
				}
				*allowance.used += uint64(actual)
			}
		}
		rings := tx.Bucket([]byte(admissionRingsBucket))
		for s.Ended.Count < admission.MaxEndedCandidates {
			generation++
			c := base
			c.Key.Generation = generation
			c.State, c.Disposition, c.Reason, c.Transitions = admission.StateRefused, admission.DispositionRefused, admission.ReasonProtected, 2
			cid, idErr := c.ID()
			if idErr != nil {
				return idErr
			}
			if err = putCandidate(tx, c); err != nil {
				return err
			}
			rootRefs.Refs++
			var pos uint64
			s.Ended, pos = s.Ended.Push()
			if err = rings.Put(ringKey(ringEnded, pos), []byte(cid)); err != nil {
				return err
			}
		}
		if err = putRefs(tx, base.Roots[0], rootRefs); err != nil {
			return err
		}
		for s.Loose.Count < admission.MaxLooseEvidence {
			var pos uint64
			s.Loose, pos = s.Loose.Push()
			e := f.mint(evidenceSpec{target: "192.0.2.12", cursor: fmt.Sprintf("loose=%d", pos)})
			data, err := e.MarshalBinary()
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(e.ID()), data); err != nil {
				return err
			}
			if err = putRefs(tx, e.ID(), admission.EvidenceRefs{Loose: pos}); err != nil {
				return err
			}
			if err = rings.Put(ringKey(ringLoose, pos), []byte(e.ID())); err != nil {
				return err
			}
		}
		return putStorageState(tx, s)
	}); setupErr != nil {
		b.Fatal(setupErr)
	}
	return f
}

func BenchmarkAdmissionLedgerOpenFullHistory(b *testing.B) {
	f := fullHistory(b)
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			b.Fatal(err)
		}
	}
}

func (f *ledgerFixture) queuedIDs() []admission.CandidateID {
	f.t.Helper()
	var ids []admission.CandidateID
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueBucket)).ForEach(func(k, _ []byte) error {
			ids = append(ids, admission.CandidateID(k))
			return nil
		})
	}); err != nil {
		f.t.Fatal(err)
	}
	return ids
}

// retirableHistory ends n applied candidates of the most roots. Setup
// refills history credit directly between them, since ticking that long
// would age the queue out.
func retirableHistory(b *testing.B, n int) *ledgerFixture {
	b.Helper()
	f := newLedgerFixture(b)
	f.fillRoots(n, admission.MaxRoots)
	for _, id := range f.queuedIDs() {
		f.adjustStorage(func(s *admission.StorageState) { *s, _ = s.Advance(admission.HistoryBurst) })
		_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		if err != nil {
			b.Fatal(err)
		}
		if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
			b.Fatal(err)
		}
		if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
			b.Fatal(err)
		}
	}
	// Retirement waits for the audit consumer's acknowledgement.
	f.ackAll()
	return f
}

// fillHistoryAllowance fills the remaining general allowance with complete
// copies of one ended candidate's graph. Shared roots retain one reference
// per candidate and each copy pays its own full history cost.
func (f *ledgerFixture) fillHistoryAllowance() {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		k, _ := tx.Bucket([]byte(admissionHistoryBucket)).Cursor().First()
		base, err := loadCandidate(tx, admission.CandidateID(k))
		if err != nil {
			return err
		}
		attempt, err := currentAttempt(tx, base)
		if err != nil {
			return err
		}
		h, _, err := loadHistoryEntry(tx, admission.CandidateID(k))
		if err != nil {
			return err
		}
		s, err := loadStorageState(tx)
		if err != nil {
			return err
		}
		general, _ := admission.HistoryLanes()
		for generation := uint32(1000000000); ; generation++ {
			c := base
			c.Key.Generation = generation
			cost, err := historyCostOf(tx, c)
			if err != nil {
				return err
			}
			if uint64(cost) > general-s.General.Used {
				break
			}
			id, _ := c.ID()
			attempt.Attempt, err = admission.NewAttempt(id, 1)
			if err != nil {
				return err
			}
			if err = putCandidate(tx, c); err != nil {
				return err
			}
			if err = putAttempt(tx, attempt); err != nil {
				return err
			}
			h.General = cost
			if err = putHistoryEntry(tx, id, h); err != nil {
				return err
			}
			for _, root := range c.Roots {
				r, err := loadRefs(tx, root)
				if err != nil {
					return err
				}
				r.Refs++
				if err = putRefs(tx, root, r); err != nil {
					return err
				}
			}
			s.General.Used += uint64(cost)
		}
		return putStorageState(tx, s)
	}); err != nil {
		f.t.Fatal(err)
	}
}

// A reservation of the largest candidate into a full allowance retires the
// eligible history it needs room from, each retirement releasing a
// candidate of the most roots.
func BenchmarkAdmissionLedgerReserveRetiresUnderPressure(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f := retirableHistory(b, 4)
		f.tickAt(f.wall.Add(admission.HistoryRetention))
		f.fillRoots(1, admission.MaxRoots)
		next := f.queuedIDs()
		if len(next) != 1 {
			b.Fatalf("queued %d candidates", len(next))
		}
		f.fillHistoryAllowance()
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			b.Fatalf("pressure fixture does not pass open: %v", err)
		}
		var cost uint32
		if err := f.db.bolt.View(func(tx *bolt.Tx) error {
			c, err := loadCandidate(tx, next[0])
			if err != nil {
				return err
			}
			cost, err = historyCostOf(tx, c)
			return err
		}); err != nil {
			b.Fatal(err)
		}
		before := f.storageState().General.Used
		if f.storageState().HistoryRoom(admission.LaneGeneral) >= uint64(cost) {
			b.Fatal("pressure fixture has room without retirement")
		}
		b.StartTimer()
		if _, _, _, err := f.l.Reserve(next[0], admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if used := f.storageState().General.Used; used >= before+uint64(cost) {
			b.Fatal("reservation did not retire history")
		}
		b.StartTimer()
	}
}

// One tick retiring a full batch of candidates of the most roots at their
// target.
func BenchmarkAdmissionLedgerTickRetiresABatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f := retirableHistory(b, retirementsPerTick)
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		f.tickAt(f.wall.Add(admission.HistoryTarget))
		b.StopTimer()
		if s := f.storageState(); s.General.Used != 0 {
			b.Fatalf("a batch at its target was not retired: %+v", s.General)
		}
		b.StartTimer()
	}
}

// fullOutbox fills the history as fullHistory does, then the notice share
// with keyed records of full examples, half of them quiet, and the reserve
// with the audit rows of as many ended candidates as its slots hold.
func fullOutbox(b *testing.B) *ledgerFixture {
	b.Helper()
	f := fullHistory(b)
	reasons := []admission.Reason{
		admission.ReasonProtected, admission.ReasonAttribution, admission.ReasonInvalid, admission.ReasonPolicy,
		admission.ReasonStaleIdentity, admission.ReasonCollateral, admission.ReasonBreaker,
		admission.ReasonEnvelopeNoAlternative, admission.ReasonUnsupportedContainment, admission.ReasonStale,
		admission.ReasonIngressInterruption, admission.ReasonEngineUnavailable,
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		s, err := loadStorageState(tx)
		if err != nil {
			return err
		}
		example, _ := admission.ParseCandidateID("cand_" + fmt.Sprintf("%032x", 1))
		for i := 0; s.NoticeRecords < admission.MaxNoticeRecords; i++ {
			key := admission.NoticeKey{Kind: admission.NoticeWithheld, Reason: reasons[i%len(reasons)], Check: fmt.Sprintf("check_%d", i/len(reasons)), Effect: admission.EffectAddress}
			r := admission.NewNoticeRecord(key)
			for j := 0; j < admission.MaxNoticeExamples; j++ {
				if r, err = r.Add(f.wall, example, uint32(j+1)); err != nil {
					return err
				}
			}
			if i%2 == 0 {
				if r, err = r.Ack(r.Count, f.wall); err != nil {
					return err
				}
			}
			if err = storeNoticeRecord(tx, admission.NewNoticeRecord(key), r); err != nil {
				return err
			}
			s.NoticeRecords++
		}
		// Rows of ended candidates keep their history unretirable.
		cur := tx.Bucket([]byte(admissionHistoryBucket)).Cursor()
		for k, v := cur.First(); k != nil && s.AuditSlots+admission.AuditStepsPerAttempt <= admission.MaxAuditSlots/2; k, v = cur.Next() {
			h, err := admission.UnmarshalHistoryEntry(v)
			if err != nil {
				return err
			}
			id := admission.CandidateID(k)
			c, err := loadCandidate(tx, id)
			if err != nil {
				return err
			}
			a, err := currentAttempt(tx, c)
			if err != nil {
				return err
			}
			keys, err := h.RetireKeys(id)
			if err != nil {
				return err
			}
			for _, rk := range keys {
				if err = tx.Bucket([]byte(admissionRetireBucket)).Delete(rk); err != nil {
					return err
				}
			}
			for step := uint32(0); step < admission.AuditStepsPerAttempt; step++ {
				row, err := admission.NewAuditRow(c, a, admission.Tier{}, f.wall)
				if err != nil {
					return err
				}
				row.Transition = step + 2
				switch step {
				case 0:
					row.State, row.Disposition = admission.StateReserved, 0
				case 1:
					row.State, row.Disposition = admission.StateExecuting, 0
				}
				data, err := row.MarshalBinary()
				if err != nil {
					return err
				}
				if err = tx.Bucket([]byte(admissionOutboxBucket)).Put(row.Key(), data); err != nil {
					return err
				}
			}
			s.AuditSlots += admission.AuditStepsPerAttempt
		}
		return putStorageState(tx, s)
	}); err != nil {
		b.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		b.Fatal(err)
	}
	return f
}

// Opening proves every notice record, quiet index key and audit row.
func BenchmarkAdmissionLedgerOpenFullOutbox(b *testing.B) {
	f := fullOutbox(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			b.Fatal(err)
		}
	}
}

// Status reads every section of a full ledger in one read transaction.
func BenchmarkAdmissionLedgerStatusFullOutbox(b *testing.B) {
	f := fullOutbox(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := f.l.Status()
		if s.Storage.Error != "" || s.Notices.Error != "" || s.Outbox.AuditRows == 0 {
			b.Fatalf("status = %+v %+v", s.Storage, s.Outbox)
		}
	}
}

// Reading the records due walks the whole notice share.
func BenchmarkAdmissionLedgerPendingNoticesFullOutbox(b *testing.B) {
	f := fullOutbox(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if due, err := f.l.PendingNotices(); err != nil || len(due) == 0 {
			b.Fatalf("due = %d, %v", len(due), err)
		}
	}
}

// benchmarkRestore captures only the records an iteration changes. Resetting
// them outside the timer keeps each iteration at the same occupancy without
// rebuilding or retaining another full ledger.
func benchmarkRestore(f *ledgerFixture, keys map[string][][]byte) func() {
	f.t.Helper()
	type record struct {
		bucket     string
		key, value []byte
	}
	var records []record
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		for name, list := range keys {
			bucket := tx.Bucket([]byte(name))
			for _, key := range list {
				records = append(records, record{name, bytes.Clone(key), bytes.Clone(bucket.Get(key))})
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	wall, since, now := f.wall, f.since, f.l.now
	return func() {
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
			for _, r := range records {
				bucket := tx.Bucket([]byte(r.bucket))
				var err error
				if r.value == nil {
					err = bucket.Delete(r.key)
				} else {
					err = bucket.Put(r.key, r.value)
				}
				if err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			f.t.Fatal(err)
		}
		f.wall, f.since, f.l.now = wall, since, now
	}
}

// Acknowledging a batch of complete attempts from a full outbox writes
// their retirement keys in the same transaction.
func BenchmarkAdmissionLedgerAckAuditFullOutbox(b *testing.B) {
	f := fullOutbox(b)
	rows, err := f.l.PendingAudit(999)
	if err != nil || len(rows) != 999 {
		b.Fatalf("rows = %d, %v", len(rows), err)
	}
	ids := make([]admission.AuditAck, 0, len(rows))
	keys := map[string][][]byte{admissionQueueStateBucket: {storageStateKey}}
	for _, r := range rows {
		ids = append(ids, r.Ack())
		keys[admissionOutboxBucket] = append(keys[admissionOutboxBucket], r.Key())
	}
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		seen := map[admission.CandidateID]bool{}
		for _, r := range rows {
			if seen[r.Attempt.Candidate] {
				continue
			}
			seen[r.Attempt.Candidate] = true
			h, found, loadErr := loadHistoryEntry(tx, r.Attempt.Candidate)
			if loadErr != nil || !found {
				return admission.ErrCorruptRecord
			}
			retire, keyErr := h.RetireKeys(r.Attempt.Candidate)
			if keyErr != nil {
				return keyErr
			}
			keys[admissionRetireBucket] = append(keys[admissionRetireBucket], retire...)
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	restore := benchmarkRestore(f, keys)
	before := f.storageState().AuditSlots
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = f.l.AckAudit(ids); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if got := f.storageState().AuditSlots; got != before-uint64(len(rows)) {
			b.Fatalf("audit slots %d -> %d", before, got)
		}
		restore()
		b.StartTimer()
	}
}

// A Critical gap whose new key finds the notice share full counts in the
// overflow record and the Critical summary.
func BenchmarkAdmissionLedgerDeferIntoOverflow(b *testing.B) {
	f := fullOutbox(b)
	id := f.criticalQueued()
	reasons := []admission.Reason{admission.ReasonCeiling, admission.ReasonStorageShare}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.l.Defer(id, reasons[i%2]); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	var overflow admission.NoticeRecord
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		overflow, _, err = loadNoticeRecord(tx, admission.OverflowKey(admission.NoticeCapacity))
		return err
	}); err != nil || overflow.Count != uint64(b.N) {
		b.Fatalf("overflow = %d, %v; want %d", overflow.Count, err, b.N)
	}
}

// One tick removing a batch of quiet records from a full notice share.
func BenchmarkAdmissionLedgerTickRemovesQuietNotices(b *testing.B) {
	f := fullOutbox(b)
	f.tickAt(f.wall.Add(time.Hour - time.Second))
	at := f.wall.Add(time.Second)
	keys := map[string][][]byte{
		admissionMetaBucket:       {admissionClockKey},
		admissionQueueStateBucket: {storageStateKey, ceilingStateKey},
	}
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		for _, name := range []string{admissionChargesBucket, admissionWindowsBucket} {
			if err := tx.Bucket([]byte(name)).ForEach(func(k, _ []byte) error {
				keys[name] = append(keys[name], bytes.Clone(k))
				return nil
			}); err != nil {
				return err
			}
		}
		cur := tx.Bucket([]byte(admissionOutboxBucket)).Cursor()
		for k, _ := cur.Seek([]byte{'q'}); k != nil && k[0] == 'q' && len(keys[admissionOutboxBucket]) < 2*quietRemovalsPerTick; k, _ = cur.Next() {
			due, key, err := admission.ParseQuietKey(k)
			if err != nil || due.After(at) {
				return admission.ErrCorruptRecord
			}
			notice, err := key.Bytes()
			if err != nil {
				return err
			}
			keys[admissionOutboxBucket] = append(keys[admissionOutboxBucket], bytes.Clone(k), notice)
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	if len(keys[admissionOutboxBucket]) != 2*quietRemovalsPerTick {
		b.Fatal("fixture has too few quiet notices")
	}
	restore := benchmarkRestore(f, keys)
	before := f.storageState().NoticeRecords
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.tickAt(at)
		b.StopTimer()
		if got := f.storageState().NoticeRecords; got != before-quietRemovalsPerTick {
			b.Fatalf("records %d -> %d", before, got)
		}
		restore()
		b.StartTimer()
	}
}
