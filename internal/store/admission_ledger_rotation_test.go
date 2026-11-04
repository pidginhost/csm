package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// freshWith queues a block of target, severity and owner's scope through
// ingress, as production arrivals are: its episode row makes it fresh
// until the episode's first verified response (spec 5.2).
func (f *ledgerFixture) freshWith(target string, severity admission.Severity, owner admission.Owner) admission.CandidateID {
	f.t.Helper()
	r := f.arrive(f.arrival(evidenceSpec{target: target, cursor: "fresh-" + target, severity: severity, owner: owner}))[0]
	if r.Err != nil || !r.Created {
		f.t.Fatalf("arrival %+v", r)
	}
	return r.Candidate
}

// testAttemptAction is a well-formed attempt action name.
func testAttemptAction(t *testing.T, n byte) admission.ActionID {
	t.Helper()
	a, err := admission.ParseActionID(fmt.Sprintf("act_%032x", n))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// rotationFixture is a live ledger whose one general slot holds a
// verified High block of alice's scope, with an ingress generation open.
func rotationFixture(t *testing.T) (*ledgerFixture, admission.AttemptRecord) {
	t.Helper()
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	f.begin()
	id := f.freshWith("192.0.2.10", admission.SeverityHigh, f.owner("alice"))
	_, victim, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(victim.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(victim.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	return f, victim
}

// Fresh work of the victim's tier rotates it out only once its 30-minute
// hold passed on both clocks: the reservation claims it as an eviction
// does, raises the capacity notice once, and the ledger reopens with the
// claim and with the eviction (spec 5.6).
func TestAdmissionLedgerRotatesAfterTheHold(t *testing.T) {
	f, victim := rotationFixture(t)
	f.tickAt(f.wall.Add(admission.RotationHold - time.Second))
	early := f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	before := f.snapshot()
	_, _, _, err := f.l.Reserve(early, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "held victim", err, admission.ReasonSetFull)
	if !reflect.DeepEqual(before, f.snapshot()) || f.capacityNotices(admission.ReasonSetFull) != 0 {
		t.Fatal("a refused rotation changed the ledger")
	}
	f.tickAt(f.wall.Add(time.Second))
	original, _ := f.effectOf(victim)
	originalEpisode, found := f.episodeAt("192.0.2.10")
	if !found || originalEpisode.Verified != original.ExpiresAt {
		t.Fatalf("victim episode %+v, found %v", originalEpisode, found)
	}
	originalCandidate := f.candidateOf(victim.Attempt.Candidate)
	charged := f.ceilingState()
	_, a, _, err := f.l.Reserve(early, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	member, _ := f.effectOf(a)
	evicted, _ := f.effectOf(victim)
	if member.Victim != (admission.EffectRef{Action: victim.Attempt.ID, ExpiresAt: victim.ExpiresAt}) || member.Partition != admission.PartitionGeneral || member.Tier != evicted.Tier {
		t.Fatalf("member record %+v", member)
	}
	wantVictim := original
	wantVictim.EvictedBy = a.Attempt.ID
	if evicted != wantVictim {
		t.Fatalf("victim record %+v, want %+v", evicted, wantVictim)
	}
	if got := f.ceilingState(); got.General.Used != charged.General.Used+1 || got.General.Units() != charged.General.Units()-1 || got.Reserved != charged.Reserved {
		t.Fatalf("rotation charge %+v, before %+v", got, charged)
	}
	if n := f.capacityNotices(admission.ReasonSetFull); n != 1 {
		t.Fatalf("capacity notices %d, want 1 for the rotation", n)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("a ledger with a rotation claim: %v", err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
		t.Fatal(err)
	}
	// The victim's record notes when the ledger learned it left: the
	// rotation's verified outcome.
	wantVictim.Evicted, wantVictim.Gone = true, f.wall
	if evicted, _ = f.effectOf(victim); evicted != wantVictim {
		t.Fatalf("rotated victim %+v, want unchanged hold and expiry %+v", evicted, wantVictim)
	}
	if episode, exists := f.episodeAt("192.0.2.10"); !exists || !reflect.DeepEqual(episode, originalEpisode) || !reflect.DeepEqual(f.candidateOf(victim.Attempt.Candidate), originalCandidate) {
		t.Fatal("rotation changed the victim's episode boundary or evidence")
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("a ledger with a rotation: %v", err)
	}
}

// A rotation notice shares the recovery reserve with its new attempt.
// When only the attempt fits, the notice must use the fixed overflow
// record instead of spending the attempt's future unknown-outcome hold.
func TestAdmissionLedgerRotationNoticeKeepsRecoveryRoom(t *testing.T) {
	for _, room := range []uint64{0, admission.NoticeSlotBytes - 1, admission.NoticeSlotBytes} {
		t.Run(fmt.Sprint(room), func(t *testing.T) {
			f, victim := rotationFixture(t)
			f.tickAt(f.wall.Add(admission.RotationHold))
			id := f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
			cost := uint64(f.cost(id))
			f.adjustStorage(func(s *admission.StorageState) {
				leaveRecoveryRoom(s, cost+admission.AttemptRecoveryBytes+room)
			})
			before := f.storageState()
			_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
			if err != nil || !granted {
				t.Fatalf("reserve: granted %v, %v", granted, err)
			}
			if member, found := f.effectOf(a); !found || member.Victim.Action != victim.Attempt.ID {
				t.Fatalf("rotation did not claim its victim: %+v", member)
			}
			after := f.storageState()
			hold := cost + admission.UnknownHoldBytes
			if after.Recovery+after.OutboxBytes()+hold > admission.RecoveryReserveBytes {
				t.Fatal("rotation notice overbooked the recovery reserve")
			}
			notices := f.notices()
			key := sshKey(admission.NoticeCapacity, admission.ReasonSetFull)
			overflow := admission.OverflowKey(admission.NoticeCapacity)
			if room < admission.NoticeSlotBytes {
				if after.NoticeRecords != before.NoticeRecords || notices[key].Count != 0 || notices[overflow].Count != 1 {
					t.Fatal("rotation notice spent its attempt's hold or lost its overflow count")
				}
			} else if after.NoticeRecords != before.NoticeRecords+1 || notices[key].Count != 1 || notices[overflow].Count != 0 {
				t.Fatal("exact room did not fund exactly one rotation notice")
			}
			if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
				t.Fatal(err)
			}
			if settled := f.storageState(); settled.Recovery+settled.OutboxBytes() > admission.RecoveryReserveBytes {
				t.Fatal("the rotation's unknown outcome exceeded the recovery reserve")
			}
		})
	}
}

// Downtime and a degraded reading never complete a hold: a reboot grants
// no elapsed time, and a degraded reading allows no rotation even once
// both clocks passed the hold (spec 5.4).
func TestAdmissionLedgerRotationNeedsTrustedElapsedTime(t *testing.T) {
	f, _ := rotationFixture(t)
	const otherBoot = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d"
	read := func(wall time.Duration, since time.Duration, degraded bool) {
		t.Helper()
		f.wall = f.wall.Add(wall)
		tick, err := f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: otherBoot, SinceBoot: since})
		if err != nil || tick.Degraded != degraded {
			t.Fatalf("reading: %+v %v, want degraded %v", tick, err, degraded)
		}
	}
	read(admission.RotationHold, time.Second, false)
	id := f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "after a reboot", err, admission.ReasonSetFull)
	read(admission.RotationHold+2*time.Minute, time.Second+admission.RotationHold+time.Minute, true)
	_, _, _, err = f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "degraded clock", err, admission.ReasonSetFull)
	before := f.snapshot()
	if wake, ok, wakeErr := f.l.NextWake(nil); wakeErr != nil || !ok || !wake.Equal(f.wall.Add(setRecheck)) {
		t.Fatalf("degraded wake %v %v %v, want the set recheck", wake, ok, wakeErr)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("the wake probe changed the ledger")
	}
	read(time.Minute, time.Second+admission.RotationHold+2*time.Minute, false)
	if _, _, _, err = f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatalf("elapsed hold on a trusted clock: %v", err)
	}
}

// Only a new episode rotates: work queued without an episode row, or
// whose episode already had a verified response, waits (spec 5.2).
func TestAdmissionLedgerOnlyFreshWorkRotates(t *testing.T) {
	f, _ := rotationFixture(t)
	f.tickAt(f.wall.Add(admission.RotationHold))
	legacy := f.queuedBy("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	_, _, _, err := f.l.Reserve(legacy, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "no episode row", err, admission.ReasonSetFull)
	answered := f.freshWith("192.0.2.12", admission.SeverityHigh, f.owner("alice"))
	e, found := f.episodeAt("192.0.2.12")
	if !found {
		t.Fatal("arrival wrote no episode row")
	}
	e.Verified = f.wall.Add(time.Hour)
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisodeRow(tx, f.target("192.0.2.12").Key(), e) }); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = f.l.Reserve(answered, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "verified episode", err, admission.ReasonSetFull)
	other := f.freshWith("192.0.2.14", admission.SeverityHigh, f.owner("alice"))
	if e, found = f.episodeAt("192.0.2.14"); !found {
		t.Fatal("arrival wrote no episode row")
	}
	if e.ID, err = admission.ParseEpisodeID("00000000000000000000000000000009"); err != nil {
		t.Fatal(err)
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisodeRow(tx, f.target("192.0.2.14").Key(), e) }); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = f.l.Reserve(other, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "another episode's row", err, admission.ReasonSetFull)
	if _, _, _, err = f.l.Reserve(f.freshWith("192.0.2.13", admission.SeverityHigh, f.owner("alice")), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatalf("fresh work: %v", err)
	}
}

// Fresh answers as a live schedule decides fresh work, on a ledger that
// never started too: only block_ip work whose episode row names its
// episode and records no verified response (spec 5.2).
func TestAdmissionLedgerFreshReadsTheEpisodeRow(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	fresh := f.freshWith("192.0.2.13", admission.SeverityHigh, f.owner("alice"))
	legacy := f.queuedBy("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	answered := f.freshWith("192.0.2.12", admission.SeverityHigh, f.owner("alice"))
	other := f.freshWith("192.0.2.14", admission.SeverityHigh, f.owner("alice"))
	e, found := f.episodeAt("192.0.2.12")
	if !found {
		t.Fatal("arrival wrote no episode row")
	}
	e.Verified = f.wall
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisodeRow(tx, f.target("192.0.2.12").Key(), e) }); err != nil {
		t.Fatal(err)
	}
	if e, found = f.episodeAt("192.0.2.14"); !found {
		t.Fatal("arrival wrote no episode row")
	}
	var err error
	if e.ID, err = admission.ParseEpisodeID("00000000000000000000000000000009"); err != nil {
		t.Fatal(err)
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisodeRow(tx, f.target("192.0.2.14").Key(), e) }); err != nil {
		t.Fatal(err)
	}
	challenge := f.candidateOf(fresh)
	challenge.Key.Kind = admission.KindChallenge
	for name, tc := range map[string]struct {
		c    admission.Candidate
		want bool
	}{
		"a fresh episode":       {f.candidateOf(fresh), true},
		"no episode row":        {f.candidateOf(legacy), false},
		"a verified episode":    {f.candidateOf(answered), false},
		"another episode's row": {f.candidateOf(other), false},
		"not block_ip work":     {challenge, false},
	} {
		got, err := f.l.Fresh(tc.c)
		if err != nil || got != tc.want {
			t.Errorf("%s: Fresh = %v %v, want %v", name, got, err, tc.want)
		}
	}
}

// A candidate retained through schema 5 upgrade has no episode proof and
// cannot gain rotation privilege from opening the upgraded ledger.
func TestAdmissionLedgerOnlyFreshWorkRotatesAfterUpgrade(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queuedBy("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	f.schemaFive()
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	c := f.candidateOf(id)
	if c.State != admission.StateQueued {
		t.Fatalf("upgrade changed the queued candidate: %+v", c)
	}
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		q, openErr := f.l.openQueue(tx, f.wall)
		if openErr != nil {
			return openErr
		}
		// Isolate the episode proof from the live-start gate.
		q.started = true
		fresh, freshErr := q.fresh(c)
		if freshErr != nil || fresh {
			t.Fatalf("upgraded candidate is fresh: %v %v", fresh, freshErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The pool's holdings count each scope's unexpired, unclaimed records,
// pending ones included, and its records carry their scope and
// application, rotatable only as the hold test says.
func TestAdmissionLedgerPoolCountsUnclaimedHoldings(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 7, Unclaimed: 3})
	kept := f.verifiedBy("192.0.2.10", admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	claimed := f.verifiedBy("192.0.2.11", admission.SeverityHigh, f.owner("alice"), time.Hour)
	expiring := f.verifiedBy("192.0.2.12", admission.SeverityHigh, f.owner("alice"), 2*time.Hour)
	_, member, _, err := f.l.Reserve(f.queuedBy("192.0.2.13", admission.SeverityCritical, f.owner("bob")), admission.LaneGeneral, f.wall.Add(5*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := f.effectOf(claimed); rec.EvictedBy != member.Attempt.ID {
		t.Fatalf("the earliest expiry was not claimed: %+v", rec)
	}
	keptRec, _ := f.effectOf(kept)
	expiringRec, _ := f.effectOf(expiring)
	memberRec, _ := f.effectOf(member)
	for _, at := range []time.Time{f.wall, f.wall.Add(3 * time.Hour)} {
		if err = f.db.bolt.View(func(tx *bolt.Tx) error {
			pool, holding, poolErr := victimPool(tx, at, func(rec admission.EffectRecord) bool { return rec.Action == kept.Attempt.ID }, nil)
			if poolErr != nil {
				return poolErr
			}
			want := map[admission.Partition]map[string]int{admission.PartitionGeneral: {keptRec.Scope: 1, memberRec.Scope: 1}}
			var wantPool []admission.EvictionVictim
			if at.Equal(f.wall) {
				want[admission.PartitionGeneral][keptRec.Scope] = 2
				wantPool = append(wantPool, admission.EvictionVictim{Action: expiringRec.Action, Target: expiringRec.Target, Tier: expiringRec.Tier, Partition: expiringRec.Partition, ExpiresAt: expiringRec.ExpiresAt,
					Scope: expiringRec.Scope, Applied: expiringRec.Applied})
			}
			wantPool = append(wantPool, admission.EvictionVictim{Action: keptRec.Action, Target: keptRec.Target, Tier: keptRec.Tier, Partition: keptRec.Partition, ExpiresAt: keptRec.ExpiresAt,
				Scope: keptRec.Scope, Applied: keptRec.Applied, Rotatable: true})
			if !reflect.DeepEqual(holding, want) {
				t.Fatalf("at %v holding %+v, want %+v", at, holding, want)
			}
			if !reflect.DeepEqual(pool, wantPool) {
				t.Fatalf("at %v pool %+v, want %+v", at, pool, wantPool)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// The schedule funds one rotation per victim and the reservation agrees
// with it; strictly lower work never rotates, and a pick that finds no
// victim stays queued.
func TestAdmissionLedgerScheduleFundsRotation(t *testing.T) {
	f, victim := rotationFixture(t)
	f.tickAt(f.wall.Add(admission.RotationHold))
	first := f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	f.tickAt(f.wall.Add(time.Second))
	second := f.freshWith("192.0.2.12", admission.SeverityHigh, f.owner("alice"))
	lower := f.freshWith("192.0.2.13", admission.SeverityWarning, f.owner("alice"))
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 1 || picks[0].ID != first {
		t.Fatalf("picks %+v %v, want only the oldest rotation", picks, err)
	}
	_, a, _, err := f.l.Reserve(first, picks[0].Lane, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if member, _ := f.effectOf(a); member.Victim.Action != victim.Attempt.ID {
		t.Fatalf("member record %+v", member)
	}
	for _, id := range []admission.CandidateID{second, lower} {
		if c := f.candidateOf(id); c.State != admission.StateQueued {
			t.Fatalf("candidate %s left the queue: %+v", id, c)
		}
	}
}

// A schedule projects complete replacements. The existing occupancy
// tally keeps a pending victim and member together until settlement;
// later picks recheck that pressure, then reserve with transferred shares.
func TestAdmissionLedgerScheduleFundsRotationAfterSettlement(t *testing.T) {
	f := liveLedgerFixture(t)
	f.fillGeneral(4)
	for i := 10; i < 14; i++ {
		f.verifiedBy(fmt.Sprintf("192.0.2.%d", i), admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	}
	f.begin()
	f.tickAt(f.wall.Add(admission.RotationHold))
	first := f.freshWith("192.0.2.20", admission.SeverityHigh, f.owner("bob"))
	f.tickAt(f.wall.Add(time.Second))
	second := f.freshWith("192.0.2.21", admission.SeverityHigh, f.owner("bob"))
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 2 || picks[0].ID != first || picks[1].ID != second {
		t.Fatalf("picks %+v %v, want both fresh claimants in order", picks, err)
	}
	_, a, _, err := f.l.Reserve(first, picks[0].Lane, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claimed, _ := f.effectOf(a)
	before := f.snapshot()
	_, _, _, err = f.l.Reserve(second, picks[1].Lane, f.wall.Add(time.Hour))
	wantLedgerReason(t, "pending replacement", err, admission.ReasonSetFull)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused pending replacement changed the ledger")
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
		t.Fatal(err)
	}
	_, b, _, err := f.l.Reserve(second, picks[1].Lane, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatalf("the second pick after settlement: %v", err)
	}
	member, _ := f.effectOf(b)
	if member.Victim.Action == "" || member.Victim.Action == claimed.Victim.Action {
		t.Fatalf("second pick did not claim a different over-share block: %+v", member)
	}
	if n := f.capacityNotices(admission.ReasonSetFull); n != 1 {
		t.Fatalf("two rotations produced %d notices, want one coalesced notice", n)
	}
}

// The ledger wakes for a rotation only once the hold passed; before it,
// the periodic set recheck bounds the wait.
func TestAdmissionLedgerWakeWaitsForTheHold(t *testing.T) {
	f, _ := rotationFixture(t)
	f.tickAt(f.wall.Add(10 * time.Minute))
	f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall.Add(setRecheck)) {
		t.Fatalf("wake %v %v %v, want the set recheck", wake, ok, err)
	}
	f.tickAt(f.wall.Add(admission.RotationHold))
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("wake %v %v %v, want now", wake, ok, err)
	}
}

// Opening proves an equal-tier claim only inside the block's own lane
// partition, as rotation makes it; a higher victim is never a claim.
func TestEvictionsAgreeOnRotationClaims(t *testing.T) {
	f := liveLedgerFixture(t)
	c3 := admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityHigh}
	victim := admission.EffectRecord{Action: testAttemptAction(t, 1), Target: f.target("192.0.2.10"), Partition: admission.PartitionGeneral, Lane: admission.LaneGeneral,
		Tier: c3, Scope: "host/block", ExpiresAt: f.wall.Add(time.Hour), Applied: f.wall}
	member := admission.EffectRecord{Action: testAttemptAction(t, 2), Target: f.target("192.0.2.11"), Partition: admission.PartitionGeneral, Lane: admission.LaneGeneral,
		Tier: c3, Scope: "host/block", ExpiresAt: f.wall.Add(2 * time.Hour)}
	for name, tc := range map[string]struct {
		lane   admission.Lane
		direct bool
		tier   admission.Tier
		want   bool
	}{
		"equal tier in the lane's partition": {admission.LaneGeneral, false, c3, true},
		"strictly lower victim":              {admission.LaneGeneral, false, admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityHigh}, true},
		"equal tier across partitions":       {admission.LaneDirect, true, c3, false},
		"lower tier across partitions":       {admission.LaneDirect, true, admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityHigh}, true},
		"higher victim":                      {admission.LaneGeneral, false, admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityCritical}, false},
	} {
		v, m := victim, member
		v.Tier, v.EvictedBy = tc.tier, m.Action
		m.Lane, m.Direct, m.Victim = tc.lane, tc.direct, admission.EffectRef{Action: v.Action, ExpiresAt: v.ExpiresAt}
		if err := f.db.bolt.View(func(tx *bolt.Tx) error {
			if got := evictionsAgree(tx, map[admission.ActionID]admission.EffectRecord{v.Action: v, m.Action: m}); got != tc.want {
				t.Errorf("%s: agree = %v, want %v", name, got, tc.want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// More scopes than slots take turns at the remainder: each live schedule
// cycle under pressure moves the persisted cursor, so a scope with no
// share now has one on a later cycle, after a restart too, and the wake
// sees that cycle coming.
func TestAdmissionLedgerShareCursorRotatesTheRemainder(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	bobs := f.verifiedBy("192.0.2.20", admission.SeverityHigh, f.owner("bob"), 4*time.Hour)
	f.begin()
	f.tickAt(f.wall.Add(admission.RotationHold))
	id := f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
		t.Fatalf("first cycle picks %+v %v, want the remainder elsewhere", picks, err)
	}
	moved := f.queueState().SetCursors
	wantMoved := admission.QueueCursors{General: f.candidateOf(id).Scope.Key()}
	if moved != wantMoved {
		t.Fatalf("first cycle cursors %+v, want %+v", moved, wantMoved)
	}
	beforeWake := f.snapshot()
	waiting := f.l.waiting
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("wake %v %v %v, want the next cycle now", wake, ok, err)
	}
	if !reflect.DeepEqual(beforeWake, f.snapshot()) || !reflect.DeepEqual(waiting, f.l.waiting) {
		t.Fatal("wake probe stored a cursor or changed the cycle's waiting scopes")
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	f.tickAt(f.wall.Add(time.Second))
	f.l.SetOccupants(&fullGeneral)
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("second cycle picks %+v %v, want the waiting scope", picks, err)
	}
	bobRecord, _ := f.effectOf(bobs)
	if again := f.queueState().SetCursors; again != (admission.QueueCursors{General: bobRecord.Scope}) {
		t.Fatalf("second cycle cursors %+v, want bob's scope only", again)
	}
	_, a, _, err := f.l.Reserve(id, picks[0].Lane, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if member, _ := f.effectOf(a); member.Victim.Action != bobs.Attempt.ID {
		t.Fatalf("member record %+v, want the over-share block", member)
	}
}

// Waiting work counts its scope in the shares: with a third scope
// waiting, a requester at its smaller share rotates its own block, as the
// schedule planned, instead of reclaiming another scope's.
func TestAdmissionLedgerWaitingScopesShareTheSet(t *testing.T) {
	f := liveLedgerFixture(t)
	f.fillGeneral(3)
	f.verifiedBy("192.0.2.10", admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	f.verifiedBy("192.0.2.11", admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	own := f.verifiedBy("192.0.2.12", admission.SeverityHigh, f.owner("bob"), 4*time.Hour)
	f.begin()
	f.tickAt(f.wall.Add(admission.RotationHold))
	id := f.freshWith("192.0.2.13", admission.SeverityHigh, f.owner("bob"))
	host := f.freshWith("192.0.2.14", admission.SeverityWarning, admission.Owner{})
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("picks %+v %v", picks, err)
	}
	// A later arrival belongs to the next cycle. A wake probe may use it
	// in its simulation but must not change the current picks' shares.
	f.freshWith("192.0.2.15", admission.SeverityHigh, f.owner("alice"))
	wantWaiting := map[admission.Partition][]string{admission.PartitionGeneral: {f.candidateOf(id).Scope.Key(), f.candidateOf(host).Scope.Key()}}
	beforeWake := f.snapshot()
	if _, _, err = f.l.NextWake(nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.l.waiting, wantWaiting) || !reflect.DeepEqual(beforeWake, f.snapshot()) {
		t.Fatalf("wake probe changed the last cycle: waiting %+v, want %+v", f.l.waiting, wantWaiting)
	}
	_, a, _, err := f.l.Reserve(id, picks[0].Lane, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if member, _ := f.effectOf(a); member.Victim.Action != own.Attempt.ID {
		t.Fatalf("member record %+v, want the requester's own block", member)
	}
}

// A preview ledger holds no records, so nothing is shared and its cursors
// never move: preview hosts write nothing new.
func TestAdmissionLedgerPreviewLedgerKeepsNoShareCursor(t *testing.T) {
	f := newLedgerFixture(t)
	f.fillGeneral(1, f.importAt(1, "192.0.2.60", 4*time.Hour))
	f.begin()
	f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	f.freshWith("192.0.2.12", admission.SeverityHigh, f.owner("bob"))
	for range 2 {
		if _, err := f.l.Schedule(allSlots, nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.queueState().SetCursors; got != (admission.QueueCursors{}) {
		t.Fatalf("a preview ledger moved its set cursors: %+v", got)
	}
}

// Queued one-unit block work waits in the general partition, and in the
// reserved one too when a reserved lane may serve it; other work, and a
// scope's repeats, add nothing.
func TestWaitingScopesByPartition(t *testing.T) {
	block := liveCandidate{c: admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}}}
	subnet := liveCandidate{c: admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockSubnet}}}
	direct := admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityHigh}
	items := []admission.ScheduleItem{
		{ID: "a", Scope: "s1", Tier: direct, CeilingCost: 1, Direct: true},
		{ID: "b", Scope: "s2", CeilingCost: 1},
		{ID: "c", Scope: "s2", CeilingCost: 1, Ready: true},
		{ID: "d", Scope: "s3"},
		{ID: "e", Scope: "s4", CeilingCost: 1},
	}
	byID := map[admission.CandidateID]liveCandidate{"a": block, "b": block, "c": block, "d": block, "e": subnet}
	want := map[admission.Partition][]string{admission.PartitionGeneral: {"s1", "s2"}, admission.PartitionReserved: {"s1"}}
	if got := waitingScopes(items, byID); !reflect.DeepEqual(got, want) {
		t.Fatalf("waiting %+v, want %+v", got, want)
	}
}
