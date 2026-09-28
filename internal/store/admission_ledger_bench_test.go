package store

import (
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
