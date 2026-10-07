package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var fullSchedule = admission.ScheduleLimits{General: admission.MaxCeiling, Reserved: admission.MaxCeiling, Members: admission.MaxBatchMembers}

// criticalArrivals queues one Critical C2 candidate at each address.
func (f *ledgerFixture) criticalArrivals(addrs ...string) []admission.CandidateID {
	f.t.Helper()
	var out []admission.CandidateID
	for i, addr := range addrs {
		res := f.arrive(f.arrival(evidenceSpec{target: addr, cursor: "defer=" + string(rune('a'+i)), severity: admission.SeverityCritical}))[0]
		if res.Err != nil || !res.Created {
			f.t.Fatalf("arrival %s = %+v", addr, res)
		}
		out = append(out, res.Candidate)
	}
	return out
}

// leaveCeilingCredit sets each lane's saved credit to whole units.
func (f *ledgerFixture) leaveCeilingCredit(general, reserved uint32) {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		s, err := loadCeilingState(tx)
		if err != nil {
			return err
		}
		s.General.Credit = uint64(general) * uint64(time.Hour)
		s.Reserved.Credit = uint64(reserved) * uint64(time.Hour)
		return putCeilingState(tx, s)
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *ledgerFixture) capacityNotices(reason admission.Reason) int {
	f.t.Helper()
	records, err := f.l.PendingNotices()
	if err != nil {
		f.t.Fatal(err)
	}
	n := 0
	for _, r := range records {
		if r.Key.Kind == admission.NoticeCapacity && r.Key.Reason == reason {
			n++
		}
	}
	return n
}

var critC2 = admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityCritical}

func deferredKey(reason admission.Reason, tier admission.Tier) admission.CountKey {
	return admission.CountKey{Event: admission.EventDeferred, Reason: reason, Class: tier.Class, Severity: tier.Severity}
}

// Spec 5.6 and 5.17: ready work a schedule cannot serve because its lane
// has no ceiling budget is deferred for the ceiling in that transaction,
// counted once and announced as capacity exhaustion when it is Critical.
// Scheduling again under the same shortage changes nothing.
func TestAdmissionLedgerScheduleDefersWorkTheCeilingCannotServe(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11", "192.0.2.12")
	f.leaveCeilingCredit(1, 0)
	picks := f.schedule(fullSchedule)
	if len(picks) != 1 {
		t.Fatalf("picks = %+v, want one within the budget", picks)
	}
	deferred := 0
	for _, id := range ids {
		c := f.candidateOf(id)
		switch {
		case id == picks[0].ID && c.Reason != 0:
			t.Fatalf("the pick was deferred: %s", c.Reason)
		case id != picks[0].ID && c.Reason == admission.ReasonCeiling:
			deferred++
		}
	}
	if deferred != 2 || f.count(deferredKey(admission.ReasonCeiling, critC2)) != 2 || f.capacityNotices(admission.ReasonCeiling) != 1 {
		t.Fatalf("deferred %d, counted %d, notices %d", deferred, f.count(deferredKey(admission.ReasonCeiling, critC2)), f.capacityNotices(admission.ReasonCeiling))
	}
	if _, _, granted, err := f.l.Reserve(picks[0].ID, picks[0].Lane, f.wall.Add(time.Hour)); err != nil || !granted {
		t.Fatalf("reserve the pick: %v %v", granted, err)
	}
	transitions := map[admission.CandidateID]uint32{}
	for _, id := range ids {
		transitions[id] = f.candidateOf(id).Transitions
	}
	if again := f.schedule(fullSchedule); len(again) != 0 {
		t.Fatalf("picked without budget: %+v", again)
	}
	for _, id := range ids {
		if got := f.candidateOf(id).Transitions; got != transitions[id] {
			t.Fatalf("%s moved from %d to %d transitions under the same shortage", id, transitions[id], got)
		}
	}
	if n := f.count(deferredKey(admission.ReasonCeiling, critC2)); n != 2 {
		t.Fatalf("deferrals counted again: %d", n)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening deferred work: %v", err)
	}
}

// directArrivals queues one Critical direct-compromise candidate, eligible
// for the reserved lane, at each address.
func (f *ledgerFixture) directArrivals(addrs ...string) []admission.CandidateID {
	f.t.Helper()
	var out []admission.CandidateID
	for i, addr := range addrs {
		res := f.arrive(f.arrival(evidenceSpec{producer: f.mail, check: "mail_takeover", target: addr, cursor: "direct=" + string(rune('a'+i)), severity: admission.SeverityCritical}))[0]
		if res.Err != nil || !res.Created {
			f.t.Fatalf("arrival %s = %+v", addr, res)
		}
		out = append(out, res.Candidate)
	}
	return out
}

// Reserved-lane work is short of nothing while the reserved lane can still
// serve it: with the general lane exhausted, work passed over for the member
// bound waits without a deferral.
func TestAdmissionLedgerScheduleKeepsReservedWorkUndeferred(t *testing.T) {
	for name, exhaust := range map[string]func(f *ledgerFixture){
		"general ceiling": func(f *ledgerFixture) { f.leaveCeilingCredit(0, 50) },
		"general history": func(f *ledgerFixture) {
			f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = 0 })
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			ids := f.directArrivals("192.0.2.10", "192.0.2.11")
			exhaust(f)
			picks := f.schedule(admission.ScheduleLimits{General: admission.MaxCeiling, Reserved: admission.MaxCeiling, Members: 1})
			if len(picks) != 1 || picks[0].Lane != admission.LaneDirect {
				t.Fatalf("picks = %+v", picks)
			}
			for _, id := range ids {
				if c := f.candidateOf(id); c.Reason != 0 {
					t.Fatalf("%s deferred for %s", id, c.Reason)
				}
			}
		})
	}
}

// Ceiling and history must cover the same lane: credit in separate lanes
// cannot admit a response. With ceiling available, a crossed shortage is
// a storage-share wait, not a fair-turn wait or a ceiling wait.
func TestAdmissionLedgerScheduleDefersCrossedLaneBudgets(t *testing.T) {
	for _, generalCeiling := range []bool{false, true} {
		t.Run(map[bool]string{false: "reserved ceiling", true: "general ceiling"}[generalCeiling], func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			id := f.directArrivals("192.0.2.10")[0]
			if generalCeiling {
				f.leaveCeilingCredit(50, 0)
				f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = 0 })
			} else {
				f.leaveCeilingCredit(0, 50)
				f.adjustStorage(func(s *admission.StorageState) { s.Reserved.Credit = 0 })
			}
			if picks := f.schedule(fullSchedule); len(picks) != 0 {
				t.Fatalf("crossed budgets picked %+v", picks)
			}
			tier := admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityCritical}
			c := f.candidateOf(id)
			if c.Reason != admission.ReasonStorageShare || f.count(deferredKey(admission.ReasonStorageShare, tier)) != 1 || f.capacityNotices(admission.ReasonStorageShare) != 1 {
				t.Fatalf("reason %s, counted %d, notices %d", c.Reason, f.count(deferredKey(admission.ReasonStorageShare, tier)), f.capacityNotices(admission.ReasonStorageShare))
			}
			if picks := f.schedule(fullSchedule); len(picks) != 0 || f.candidateOf(id).Transitions != c.Transitions || f.count(deferredKey(admission.ReasonStorageShare, tier)) != 1 {
				t.Fatalf("repeated shortage picked %+v or changed its deferral", picks)
			}
		})
	}
}

// A resolved shortage must not remain on work that now waits only for the
// member bound. Clearing it is one transition, with no new count or notice,
// and another turn under the same budgets changes nothing further.
func TestAdmissionLedgerScheduleClearsAResolvedBudgetReason(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11")
	f.leaveCeilingCredit(0, 0)
	if picks := f.schedule(fullSchedule); len(picks) != 0 {
		t.Fatalf("exhausted ceiling picked %+v", picks)
	}
	before := map[admission.CandidateID]uint32{}
	for _, id := range ids {
		c := f.candidateOf(id)
		if c.Reason != admission.ReasonCeiling {
			t.Fatalf("initial reason = %s", c.Reason)
		}
		before[id] = c.Transitions
	}
	f.leaveCeilingCredit(50, 50)
	lim := fullSchedule
	lim.Members = 1
	picks := f.schedule(lim)
	if len(picks) != 1 {
		t.Fatalf("picks = %+v", picks)
	}
	var waiting admission.CandidateID
	for _, id := range ids {
		if id != picks[0].ID {
			waiting = id
		}
	}
	c := f.candidateOf(waiting)
	if c.Reason != 0 || c.Transitions != before[waiting]+1 || f.count(deferredKey(admission.ReasonCeiling, critC2)) != 2 || f.capacityNotices(admission.ReasonCeiling) != 1 {
		t.Fatalf("resolved reason %s, transitions %d, counted %d, notices %d", c.Reason, c.Transitions, f.count(deferredKey(admission.ReasonCeiling, critC2)), f.capacityNotices(admission.ReasonCeiling))
	}
	if again := f.schedule(lim); len(again) != 1 || f.candidateOf(waiting).Transitions != c.Transitions {
		t.Fatalf("unchanged budgets picked %+v or repeated the clearing", again)
	}
}

// Recovery room the schedule's picks take is gone for the rest: work that
// no longer fits waits for recovery.
func TestAdmissionLedgerScheduleDefersWorkThePicksLeaveNoRecoveryFor(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11")
	need := uint64(f.cost(ids[0])) + admission.AttemptAuditBytes
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, need+need/2) })
	picks := f.schedule(fullSchedule)
	if len(picks) != 1 {
		t.Fatalf("picks = %+v", picks)
	}
	for _, id := range ids {
		if c := f.candidateOf(id); id != picks[0].ID && c.Reason != admission.ReasonPendingRecovery {
			t.Fatalf("the other candidate waits for %s", c.Reason)
		}
	}
}

// A retry in its backoff waits for its time, not for a budget: it is never
// deferred while its wait lasts.
func TestAdmissionLedgerScheduleLeavesARetryInItsBackoff(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if c := f.candidateOf(id); c.State != admission.StateQueued || !f.wall.Before(c.NotBefore) {
		t.Fatalf("retry = %s until %v at %v", c.State, c.NotBefore, f.wall)
	}
	f.leaveCeilingCredit(0, 0)
	if picks := f.schedule(fullSchedule); len(picks) != 0 {
		t.Fatalf("picks = %+v", picks)
	}
	if c := f.candidateOf(id); c.Reason != 0 {
		t.Fatalf("a retry in its backoff was deferred for %s", c.Reason)
	}
}

// Work passed over only for the member bound is not short of anything: it
// waits for its turn without a deferral.
func TestAdmissionLedgerScheduleLeavesWorkPastTheMemberBound(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11")
	if picks := f.schedule(admission.ScheduleLimits{General: admission.MaxCeiling, Reserved: admission.MaxCeiling, Members: 1}); len(picks) != 1 {
		t.Fatalf("picks = %+v", picks)
	}
	for _, id := range ids {
		if c := f.candidateOf(id); c.Reason != 0 {
			t.Fatalf("%s deferred for %s", id, c.Reason)
		}
	}
}

// Ready work with ceiling budget but no history budget waits on its storage
// share; work whose details do not fit the recovery reserve waits for
// recovery (spec 5.4).
func TestAdmissionLedgerScheduleDefersWorkStorageCannotTake(t *testing.T) {
	for name, tc := range map[string]struct {
		adjust func(f *ledgerFixture, id admission.CandidateID) func(*admission.StorageState)
		want   admission.Reason
	}{
		"history share": {func(f *ledgerFixture, _ admission.CandidateID) func(*admission.StorageState) {
			return func(s *admission.StorageState) { s.General.Credit, s.Reserved.Credit = 0, 0 }
		}, admission.ReasonStorageShare},
		"recovery reserve": {func(f *ledgerFixture, id admission.CandidateID) func(*admission.StorageState) {
			need := uint64(f.cost(id)) + admission.AttemptAuditBytes
			return func(s *admission.StorageState) { leaveRecoveryRoom(s, need-1) }
		}, admission.ReasonPendingRecovery},
		"ceiling before history": {func(f *ledgerFixture, _ admission.CandidateID) func(*admission.StorageState) {
			f.leaveCeilingCredit(0, 0)
			return func(s *admission.StorageState) { s.General.Credit, s.Reserved.Credit = 0, 0 }
		}, admission.ReasonCeiling},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			id := f.criticalArrivals("192.0.2.10")[0]
			f.adjustStorage(tc.adjust(f, id))
			if picks := f.schedule(fullSchedule); len(picks) != 0 {
				t.Fatalf("picks = %+v", picks)
			}
			if c := f.candidateOf(id); c.Reason != tc.want || f.count(deferredKey(tc.want, critC2)) != 1 || f.capacityNotices(tc.want) != 1 {
				t.Fatalf("reason %s, counted %d, notices %d", c.Reason, f.count(deferredKey(tc.want, critC2)), f.capacityNotices(tc.want))
			}
		})
	}
}

func challengeWaitingOnBlockCredit(t *testing.T) (*ledgerFixture, admission.CandidateID) {
	t.Helper()
	f := newLedgerFixture(t)
	f.begin()
	f.criticalArrivals("192.0.2.10")
	a := f.arrival(evidenceSpec{target: "192.0.2.10", cursor: "challenge", severity: admission.SeverityCritical})
	a.Request.Kind = admission.KindChallenge
	result := f.arrive(a)[0]
	if result.Err != nil || !result.Created {
		t.Fatalf("challenge: %+v", result)
	}
	f.leaveCeilingCredit(0, 0)
	return f, result.Candidate
}

func TestAdmissionLedgerScheduleChallengeUsesNoBlockCredit(t *testing.T) {
	f, id := challengeWaitingOnBlockCredit(t)
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("free challenge wake: %v %v %v", wake, ok, err)
	}
	picks := f.schedule(fullSchedule)
	if len(picks) != 1 || picks[0].ID != id || picks[0].Cost != 0 || f.candidateOf(id).Reason != 0 {
		t.Fatalf("free challenge picks: %+v", picks)
	}
	before := f.storageState()
	c, _, granted, err := f.l.Observe(id, picks[0].Lane, f.wall.Add(time.Hour))
	if err != nil || !granted || c.State != admission.StateObserved || len(f.charges()) != 0 || f.ceilingState().General.Used != 0 || f.storageState().General.Used <= before.General.Used {
		t.Fatalf("free challenge observe: %s %v %v", c.State, granted, err)
	}
}

func TestAdmissionLedgerScheduleChallengeWaitsForHistoryWithoutBlockCredit(t *testing.T) {
	f, id := challengeWaitingOnBlockCredit(t)
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = 0 })
	if picks := f.schedule(fullSchedule); len(picks) != 0 {
		t.Fatalf("challenge without history: %+v", picks)
	}
	if c := f.candidateOf(id); c.Reason != admission.ReasonStorageShare {
		t.Fatalf("challenge reason: %s", c.Reason)
	}
	general, _ := admission.HistoryLanes()
	rate := admission.HistoryRate(general)
	wait := time.Duration((uint64(f.cost(id))*uint64(time.Second) + rate - 1) / rate)
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(f.wall.Add(wait)) {
		t.Fatalf("challenge history wake: %v %v %v, want %v", wake, ok, err, f.wall.Add(wait))
	}
	f.tickAt(f.wall.Add(wait))
	if picks := f.schedule(fullSchedule); len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("challenge after history credit: %+v", picks)
	}
}

func TestAdmissionLedgerScheduleChallengeKeepsItsBackoff(t *testing.T) {
	f, id := challengeWaitingOnBlockCredit(t)
	_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted {
		t.Fatalf("reserve challenge: %v %v", granted, err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	retry := f.wall.Add(admission.RetryBackoff(1))
	if picks := f.schedule(fullSchedule); len(picks) != 0 || f.candidateOf(id).Reason != 0 {
		t.Fatalf("backoff challenge: %+v %s", picks, f.candidateOf(id).Reason)
	}
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(retry) {
		t.Fatalf("challenge retry wake: %v %v %v, want %v", wake, ok, err, retry)
	}
	f.tickAt(retry)
	if picks := f.schedule(fullSchedule); len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("ready challenge retry: %+v", picks)
	}
}

func TestAdmissionLedgerScheduleClearsBudgetReasonsOnPicks(t *testing.T) {
	for _, reason := range []admission.Reason{admission.ReasonCeiling, admission.ReasonStorageShare, admission.ReasonPendingRecovery} {
		t.Run(reason.String(), func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			id := f.criticalArrivals("192.0.2.10")[0]
			before, err := f.l.Defer(id, reason)
			if err != nil {
				t.Fatal(err)
			}
			notices := f.notices()
			count := f.count(deferredKey(reason, critC2))
			picks := f.schedule(fullSchedule)
			if len(picks) != 1 || picks[0].ID != id {
				t.Fatalf("picks = %+v", picks)
			}
			if c := f.candidateOf(id); c.Reason != 0 || c.Transitions != before.Transitions+1 {
				t.Fatalf("resolved pick reason %s, transitions %d, want %d", c.Reason, c.Transitions, before.Transitions+1)
			}
			if f.count(deferredKey(reason, critC2)) != count || !reflect.DeepEqual(f.notices(), notices) {
				t.Fatal("clearing a reason changed counts or notices")
			}
			f.schedule(fullSchedule)
			if c := f.candidateOf(id); c.Transitions != before.Transitions+1 {
				t.Fatal("unchanged budgets repeated the clearing")
			}
		})
	}
}

func TestAdmissionLedgerScheduleKeepsExternalDeferralReasons(t *testing.T) {
	for _, reason := range []admission.Reason{admission.ReasonSetFull, admission.ReasonEngineUnavailable} {
		t.Run(reason.String(), func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			ids := f.criticalArrivals("192.0.2.10", "192.0.2.11")
			before := make(map[admission.CandidateID]admission.Candidate)
			for _, id := range ids {
				c, err := f.l.Defer(id, reason)
				if err != nil {
					t.Fatal(err)
				}
				before[id] = c
			}
			if picks := f.schedule(oneEach); len(picks) != 1 {
				t.Fatalf("picks = %+v", picks)
			}
			for _, id := range ids {
				if c := f.candidateOf(id); !reflect.DeepEqual(c, before[id]) {
					t.Fatalf("schedule changed an external deferral: reason %s, transitions %d", c.Reason, c.Transitions)
				}
			}
		})
	}
}

func TestAdmissionLedgerNextWakeTracksChargedWorkBesideChallenges(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	id := f.criticalArrivals("192.0.2.10")[0]
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	arrival := f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "challenge", severity: admission.SeverityCritical})
	arrival.Request.Kind = admission.KindChallenge
	if result := f.arrive(arrival)[0]; result.Err != nil || !result.Created {
		t.Fatalf("challenge = %+v", result)
	}
	f.leaveCeilingCredit(0, 0)
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = 0 })
	// The retry already paid its history. One general ceiling unit accrues
	// before the new challenge earns its history credit.
	want := f.wall.Add(2250 * time.Millisecond)
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(want) {
		t.Fatalf("wake = %v %v %v, want %v", wake, ok, err, want)
	}
	f.tickAt(want)
	if picks := f.schedule(fullSchedule); len(picks) != 1 || picks[0].ID != id || picks[0].Bytes != 0 {
		t.Fatalf("charged retry after refill = %+v", picks)
	}
}
