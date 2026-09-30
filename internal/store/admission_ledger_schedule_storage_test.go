package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A schedule serves at most what the history budget can pay for, and each
// pick carries the history it will charge.
func TestAdmissionLedgerScheduleServesWithinHistory(t *testing.T) {
	f := newLedgerFixture(t)
	ids := f.fill(3, evidenceSpec{})
	cost := f.cost(ids[0])
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = uint64(2*cost+cost/2) * uint64(time.Second) })
	picks := f.schedule(admission.ScheduleLimits{General: 10, Members: 10})
	if len(picks) != 2 {
		t.Fatalf("picks within two candidates' history = %+v", picks)
	}
	for _, p := range picks {
		if p.Bytes != cost {
			t.Fatalf("pick %s carries %d bytes, want %d", p.ID, p.Bytes, cost)
		}
		if _, _, _, err := f.l.Reserve(p.ID, p.Lane, f.wall.Add(time.Hour)); err != nil {
			t.Fatalf("reserve %+v: %v", p, err)
		}
	}
	if picks = f.schedule(admission.ScheduleLimits{General: 10, Members: 10}); len(picks) != 0 {
		t.Fatalf("picks past the history budget = %+v", picks)
	}
}

// History that may be retired counts toward the budget: a full allowance
// still schedules work once older history has left its review window, and
// the reservation retires it.
func TestAdmissionLedgerScheduleCountsRetirableHistory(t *testing.T) {
	general, _ := admission.HistoryLanes()
	f := newLedgerFixture(t)
	old := f.applied(time.Hour)
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryRetention))
	f.nextGeneration()
	id := f.queued()
	f.adjustStorage(func(s *admission.StorageState) { s.General.Used = general })
	picks := f.schedule(admission.ScheduleLimits{General: 10, Members: 10})
	if len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("picks with retirable history = %+v", picks)
	}
	if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Candidate(old); err != errCandidateMissing {
		t.Fatalf("retirable history: %v", err)
	}
}

// Work whose details would not fit the recovery reserve waits: it is not
// picked, and it sets no wake of its own.
func TestAdmissionLedgerScheduleWaitsForTheRecoveryReserve(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, uint64(f.cost(id))-1) })
	if picks := f.schedule(admission.ScheduleLimits{General: 10, Members: 10}); len(picks) != 0 {
		t.Fatalf("picks beyond the recovery reserve = %+v", picks)
	}
	c, err := f.l.Candidate(id)
	if err != nil {
		t.Fatal(err)
	}
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(c.AgeOut) {
		t.Fatalf("wake = %v %v %v, want only the age-out %v", wake, ok, err, c.AgeOut)
	}
}

// A lane with ceiling budget but too little history credit wakes when its
// credit covers its next head; once the credit covers the head, the
// work is due now.
func TestAdmissionLedgerNextWakeWaitsForHistoryCredit(t *testing.T) {
	general, _ := admission.HistoryLanes()
	f := newLedgerFixture(t)
	id := f.queued()
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = 0 })
	rate := admission.HistoryRate(general)
	want := time.Duration((uint64(f.cost(id))*uint64(time.Second) + rate - 1) / rate)
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall.Add(want)) {
		t.Fatalf("wake = %v %v %v, want %v", wake, ok, err, f.wall.Add(want))
	}
	f.tickAt(wake)
	if wake, ok, err = f.l.NextWake(); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("with the credit earned, wake = %v %v %v, want now", wake, ok, err)
	}
}

// A lane whose allowance is full of history in its review window wakes
// when the oldest of it may be retired, if that comes before the waiting
// work ages out: not at history already eligible that cannot make room,
// and not at credit that is merely short, since the room binds.
func TestAdmissionLedgerNextWakeWaitsForRetirableHistory(t *testing.T) {
	general, _ := admission.HistoryLanes()
	f := newLedgerFixture(t)
	f.applied(time.Hour)
	f.tickAt(f.wall.Add(24 * time.Hour))
	f.applied(time.Hour)
	f.ackAll()
	eligible := f.wall.Add(admission.HistoryRetention)
	f.tickAt(eligible.Add(-time.Hour))
	f.nextGeneration()
	f.queued()
	// The older history may be retired now, but not enough of it to make
	// room.
	f.adjustStorage(func(s *admission.StorageState) { s.General.Used = general + 5000 })
	for _, short := range []uint64{0, 1000} {
		f.adjustStorage(func(s *admission.StorageState) {
			s.General.Credit = admission.NewStorageState().General.Credit - short*uint64(time.Second)
		})
		wake, ok, err := f.l.NextWake()
		if err != nil || !ok || !wake.Equal(eligible) {
			t.Fatalf("credit %d bytes short: wake = %v %v %v, want %v", short, wake, ok, err, eligible)
		}
	}
}

// Already eligible history must clear an upgrade's excess before the
// scheduler stops counting room for a fresh charge.
func TestAdmissionLedgerScheduleClearsUpgradeExcess(t *testing.T) {
	f := newLedgerFixture(t)
	f.applied(time.Hour)
	f.applied(time.Hour)
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryRetention))
	f.nextGeneration()
	id := f.queued()
	cost := uint64(f.cost(id))
	general, _ := admission.HistoryLanes()
	f.adjustStorage(func(s *admission.StorageState) {
		s.General.Used = general + cost/2
		s.General.Credit = cost * uint64(time.Second)
	})
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("eligible excess wake: %v %v %v", wake, ok, err)
	}
	picks := f.schedule(admission.ScheduleLimits{General: 1, Members: 1})
	if len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("eligible excess picks: %+v", picks)
	}
	if _, _, _, err = f.l.Reserve(id, picks[0].Lane, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// A timer must not sleep past the first byte at which its actual held head
// can proceed, even when that costs less than a full quantum.
func TestAdmissionLedgerNextWakeAtExactHistoryCredit(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	cost := uint64(f.cost(id))
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = (cost-1)*uint64(time.Second) + 1 })
	general, _ := admission.HistoryLanes()
	rate := admission.HistoryRate(general)
	delay := time.Duration((uint64(time.Second) - 1 + rate - 1) / rate)
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall.Add(delay)) {
		t.Fatalf("exact credit wake: %v %v %v; want %v", wake, ok, err, f.wall.Add(delay))
	}
	before := f.snapshot()
	if _, _, err = f.l.NextWake(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("wake changed credit or turns")
	}
	f.tickAt(wake.Add(-time.Nanosecond))
	if picks := f.schedule(admission.ScheduleLimits{General: 1, Members: 1}); len(picks) != 0 {
		t.Fatal("served before enough credit")
	}
	f.tickAt(wake)
	if picks := f.schedule(admission.ScheduleLimits{General: 1, Members: 1}); len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("exact wake did not serve: %+v", picks)
	}
}

func TestAdmissionLedgerScheduleRespectsOutstandingRecovery(t *testing.T) {
	f := newLedgerFixture(t)
	ids := f.fill(3, evidenceSpec{})
	cost := uint64(f.cost(ids[0]))
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, cost+admission.AttemptAuditBytes) })
	picks := f.schedule(admission.ScheduleLimits{General: 3, Members: 3})
	if len(picks) != 1 {
		t.Fatalf("recovery batch overbooked: %+v", picks)
	}
	if _, _, _, err := f.l.Reserve(picks[0].ID, picks[0].Lane, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if picks = f.schedule(admission.ScheduleLimits{General: 3, Members: 3}); len(picks) != 0 {
		t.Fatalf("outstanding recovery ignored: %+v", picks)
	}
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall.Add(admission.QueueAgeLimit)) {
		t.Fatalf("recovery-only wake: %v %v %v", wake, ok, err)
	}
}

func TestAdmissionLedgerSchedulingRefusesMissingHistory(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(admissionHistoryBucket)).Delete([]byte(id)) }); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if _, _, err := f.l.NextWake(); !isCorrupt(err) {
		t.Fatalf("missing history wake: %v", err)
	}
	if _, err := f.l.Schedule(admission.ScheduleLimits{General: 1, Members: 1}); !isCorrupt(err) {
		t.Fatalf("missing history schedule: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("refused schedule changed missing history")
	}
}

// Recovery-bound work is not a ready head that may hold cheaper work's
// turn. The batch budget alone cannot provide this readiness distinction.
func TestAdmissionLedgerRecoveryBlockedHeadDoesNotHold(t *testing.T) {
	f := newLedgerFixture(t)
	f.fillRoots(1, admission.MaxRoots)
	f.tickAt(f.wall.Add(time.Nanosecond))
	id := f.queued()
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, uint64(f.cost(id))+admission.AttemptAuditBytes) })
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("affordable recovery head wake: %v %v %v", wake, ok, err)
	}
	picks := f.schedule(admission.ScheduleLimits{General: 2, Members: 2})
	if len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("unavailable recovery head held service: %+v", picks)
	}
}

// Valid checksums and balanced totals cannot hide broken ownership links.
func TestAdmissionLedgerOpenProvesStorageLinks(t *testing.T) {
	for name, damage := range map[string]func(tx *bolt.Tx, m mixedLedger) error{
		"missing reference": func(tx *bolt.Tx, m mixedLedger) error {
			c, err := loadCandidate(tx, m.queued)
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionRefsBucket)).Delete([]byte(c.Roots[0]))
		},
		"wrong reference count": func(tx *bolt.Tx, m mixedLedger) error {
			c, err := loadCandidate(tx, m.queued)
			if err != nil {
				return err
			}
			return putRefs(tx, c.Roots[0], admission.EvidenceRefs{Refs: 2})
		},
		"undercharged history": func(tx *bolt.Tx, m mixedLedger) error {
			h, _, err := loadHistoryEntry(tx, m.reserved)
			if err != nil {
				return err
			}
			h.General--
			if err = putHistoryEntry(tx, m.reserved, h); err != nil {
				return err
			}
			return adjustStorage(tx, func(s *admission.StorageState) { s.General.Used-- })
		},
		"missing retirement key": func(tx *bolt.Tx, m mixedLedger) error {
			h, _, err := loadHistoryEntry(tx, m.applied)
			if err != nil {
				return err
			}
			keys, err := h.RetireKeys(m.applied)
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionRetireBucket)).Delete(keys[0])
		},
		"foreign retirement key": func(tx *bolt.Tx, m mixedLedger) error {
			h, _, err := loadHistoryEntry(tx, m.applied)
			if err != nil {
				return err
			}
			keys, err := h.RetireKeys(m.queued)
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionRetireBucket)).Put(keys[0], nil)
		},
		"ring names live candidate": func(tx *bolt.Tx, m mixedLedger) error {
			return tx.Bucket([]byte(admissionRingsBucket)).Put(ringKey(ringEnded, 1), []byte(m.queued))
		},
		"loose ring names another root": func(tx *bolt.Tx, m mixedLedger) error {
			c, err := loadCandidate(tx, m.queued)
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionRingsBucket)).Put(ringKey(ringLoose, 1), []byte(c.Roots[0]))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			m := f.mixed()
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(tx, m) }); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("broken storage links opened: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("refused open changed the ledger")
			}
		})
	}
}

func TestAdmissionLedgerNextWakeUnassessedUpgrade(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	f.schemaOne()
	var err error
	f.l, err = OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.l.SetCeiling(fixtureCeiling); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(8 * time.Second))
	before := f.snapshot()
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("unassessed work wake = %v %v %v, want now", wake, ok, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("wake changed the upgraded ledger")
	}
	if picks := f.schedule(oneEach); len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("due upgraded work was not served: %+v", picks)
	}
}

func TestAdmissionLedgerNextWakeClampsExpiredDeadline(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	f.tickAt(f.wall.Add(admission.QueueAgeLimit + time.Second))
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("expired work wake = %v %v %v, want now", wake, ok, err)
	}
	if picks := f.schedule(oneEach); len(picks) != 0 {
		t.Fatalf("expired work served: %+v", picks)
	}
	if wake, ok, err = f.l.NextWake(); err != nil || ok {
		t.Fatalf("ended work still wakes: %v %v %v", wake, ok, err)
	}
}

func TestAdmissionLedgerRetirementWakeAtTimeLimit(t *testing.T) {
	f := newLedgerFixture(t)
	f.applied(time.Hour)
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		q, err := f.l.openQueue(tx, time.Unix(0, 1<<63-1))
		if err != nil {
			return err
		}
		at, ok, err := q.nextRetirable(admission.LaneGeneral)
		if err != nil || ok {
			t.Fatalf("past history woke at the time limit: %v %v %v", at, ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionLedgerNextWakeRecoveryBlockedRetry(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.adjustStorage(func(s *admission.StorageState) { s.Recovery = admission.RecoveryReserveBytes })
	c, err := f.l.Candidate(id)
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.entry(id)
	if err != nil {
		t.Fatal(err)
	}
	want := c.ExpiresAt
	if e.NextChange.Before(want) {
		want = e.NextChange
	}
	before := f.snapshot()
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(want) {
		t.Fatalf("recovery-blocked retry wake = %v %v %v, want deadline %v", wake, ok, err, want)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("wake changed recovery-blocked retry")
	}
}
