package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

var allSlots = admission.ScheduleLimits{General: 10, Reserved: 10, Members: 10}

// queuedAt enqueues a block of target from its own local root.
func (f *ledgerFixture) queuedAt(target string) admission.CandidateID {
	f.t.Helper()
	root := f.published(evidenceSpec{target: target, cursor: "slot-" + target})
	_, id := f.enqueue(f.request(target, root))
	return id
}

// directAt enqueues a block of target from a direct compromise root.
func (f *ledgerFixture) directAt(target string) admission.CandidateID {
	f.t.Helper()
	root := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: target, cursor: "direct-" + target, severity: admission.SeverityCritical})
	_, id := f.enqueue(f.request(target, root))
	return id
}

func pickLanes(picks []admission.Pick) map[admission.CandidateID]admission.Lane {
	out := map[admission.CandidateID]admission.Lane{}
	for _, p := range picks {
		out[p.ID] = p.Lane
	}
	return out
}

// A schedule serves block work only into free slots of the partition its
// lane occupies; the rest waits as set_full. The firewall's entries leave
// the room, the ledger's own records take it, and a raised limit frees it.
func TestAdmissionLedgerScheduleBudgetsTheSetSlots(t *testing.T) {
	f := liveLedgerFixture(t)
	ids := []admission.CandidateID{f.queuedAt("192.0.2.10"), f.queuedAt("192.0.2.11"), f.queuedAt("192.0.2.12")}
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 3 {
		t.Fatalf("without a set every pick fits: %+v %v", picks, err)
	}
	// Five slots, three unclaimed: one general and one reserved slot left.
	// The ledger keeps its own copy of what it was told.
	base := admission.SetOccupancy{Limit: 5, Unclaimed: 3}
	f.l.SetOccupants(&base)
	base.Unclaimed = 0
	if picks, err = f.l.Schedule(allSlots, nil); err != nil || len(picks) != 1 || picks[0].Lane != admission.LaneGeneral {
		t.Fatalf("one general slot: %+v %v", picks, err)
	}
	served := picks[0].ID
	for _, id := range ids {
		if c := f.candidateOf(id); id != served && c.Reason != admission.ReasonSetFull {
			t.Fatalf("%s waits as %s, want set_full", id, c.Reason)
		}
	}
	if _, _, _, err = f.l.Reserve(served, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if picks, err = f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
		t.Fatalf("the reservation holds the general slot: %+v %v", picks, err)
	}
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 6, Unclaimed: 3})
	if picks, err = f.l.Schedule(allSlots, nil); err != nil || len(picks) != 1 {
		t.Fatalf("a raised limit frees one general slot: %+v %v", picks, err)
	}
	if c := f.candidateOf(picks[0].ID); c.Reason != 0 {
		t.Fatalf("a free slot ends the pick's wait: %+v", c)
	}
	still := picks[0].ID
	for _, id := range ids {
		if id != served && id != picks[0].ID {
			still = id
		}
	}
	f.l.SetOccupants(nil)
	if picks, err = f.l.Schedule(allSlots, nil); err != nil || len(picks) != 2 {
		t.Fatalf("without a set again: %+v %v", picks, err)
	}
	// Without a set the ledger cannot judge the wait; the engine ends it.
	if c := f.candidateOf(still); c.Reason != admission.ReasonSetFull {
		t.Fatalf("an unjudged wait cleared: %+v", c)
	}
}

// Reserved work uses the reserved slot first and its general turn after,
// and general work never takes the reserved slot.
func TestAdmissionLedgerScheduleKeepsTheReservedSlot(t *testing.T) {
	f := liveLedgerFixture(t)
	general := f.queuedAt("192.0.2.10")
	first, second := f.directAt("192.0.2.20"), f.directAt("192.0.2.21")
	// Two free slots: one general, one reserved.
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 2})
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := pickLanes(picks)
	lanes := map[admission.Lane]int{got[first]: 1}
	lanes[got[second]]++
	if len(got) != 2 || got[general] != 0 || lanes[admission.LaneDirect] != 1 || lanes[admission.LaneGeneral] != 1 {
		t.Fatalf("picks %+v", got)
	}
	if c := f.candidateOf(general); c.Reason != admission.ReasonSetFull {
		t.Fatalf("general work waits as %s", c.Reason)
	}
}

// Reservation rechecks the slots under the ledger's lock, before anything
// is charged: a pick from an earlier schedule cannot overfill a partition.
func TestAdmissionLedgerReserveRechecksTheSetSlots(t *testing.T) {
	f := liveLedgerFixture(t)
	plain, other := f.queuedAt("192.0.2.10"), f.queuedAt("192.0.2.11")
	direct, again := f.directAt("192.0.2.20"), f.directAt("192.0.2.21")
	// One free slot, and it is the reserve's.
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 2, Unclaimed: 1})
	before := f.snapshot()
	_, _, _, err := f.l.Reserve(plain, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "general work into the reserve", err, admission.ReasonSetFull)
	_, _, _, err = f.l.Observe(other, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "a preview into the reserve", err, admission.ReasonSetFull)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
	if _, _, _, err = f.l.Reserve(direct, admission.LaneDirect, f.wall.Add(time.Hour)); err != nil {
		t.Fatalf("direct work into the reserve: %v", err)
	}
	before = f.snapshot()
	_, _, _, err = f.l.Reserve(again, admission.LaneDirect, f.wall.Add(time.Hour))
	wantLedgerReason(t, "a full reserve", err, admission.ReasonSetFull)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refusal after the last slot changed the ledger")
	}
	if s := f.ceilingState(); s.General.Used != 0 || s.Reserved.Used != 1 {
		t.Fatalf("refusals charged the ceiling: %+v", s)
	}
}

// Work a full set defers wakes when a slot may free: at the first held
// slot's expiry, or after setRecheck for slots the ledger is not told about,
// never at once.
func TestAdmissionLedgerWakesWhenTheSetMayHaveRoom(t *testing.T) {
	f := liveLedgerFixture(t)
	held := f.queuedAt("192.0.2.10")
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 2})
	ends := f.wall.Add(30 * time.Second)
	if _, _, _, err := f.l.Reserve(held, admission.LaneGeneral, ends); err != nil {
		t.Fatal(err)
	}
	waiting := f.queuedAt("192.0.2.11")
	if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 || f.candidateOf(waiting).Reason != admission.ReasonSetFull {
		t.Fatalf("no slot: %+v %v", picks, err)
	}
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(ends) {
		t.Fatalf("wake %v %v %v, want the held slot's expiry %v", wake, ok, err, ends)
	}
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 2, Unclaimed: 1})
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(ends) {
		t.Fatalf("wake %v %v %v, want %v", wake, ok, err, ends)
	}
	f.tickAt(ends)
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall.Add(setRecheck)) {
		t.Fatalf("wake %v %v %v, want a recheck at %v", wake, ok, err, f.wall.Add(setRecheck))
	}
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 2})
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("wake %v %v %v, want now", wake, ok, err)
	}
}

// Once the ledger runs live, any block work a full set defers raises the
// capacity notice; a preview ledger raises it for Critical work only.
func TestAdmissionLedgerFullSetNoticeOnceLive(t *testing.T) {
	for _, live := range []bool{false, true} {
		f := newLedgerFixture(t)
		if live {
			f = liveLedgerFixture(t)
		}
		id := f.queuedAt("192.0.2.10")
		if tier := f.entryTier(id); tier.Severity != admission.SeverityHigh {
			t.Fatalf("fixture tier %+v", tier)
		}
		f.l.SetOccupants(&admission.SetOccupancy{Limit: 1, Unclaimed: 1})
		if _, err := f.l.Schedule(allSlots, nil); err != nil {
			t.Fatal(err)
		}
		records, err := f.l.PendingNotices()
		if err != nil {
			t.Fatal(err)
		}
		var capacity bool
		for _, r := range records {
			capacity = capacity || (r.Key.Kind == admission.NoticeCapacity && r.Key.Reason == admission.ReasonSetFull)
		}
		if capacity != live {
			t.Fatalf("live %v: capacity notice %v in %+v", live, capacity, records)
		}
	}
}

// Each lane's history/ceiling probe respects a full set. Otherwise a
// shorter credit wait wakes a turn that still cannot admit any block.
func TestAdmissionLedgerSlotWakeBudgetsEveryProbe(t *testing.T) {
	for _, direct := range []bool{false, true} {
		for _, short := range []string{"ceiling", "history"} {
			f := liveLedgerFixture(t)
			if direct {
				f.directAt("192.0.2.10")
			} else {
				f.queuedAt("192.0.2.10")
			}
			f.l.SetOccupants(&admission.SetOccupancy{Limit: 2, Unclaimed: 2})
			if short == "ceiling" {
				f.leaveCeilingCredit(0, 0)
			} else {
				f.adjustStorage(func(s *admission.StorageState) { s.General.Credit, s.Reserved.Credit = 0, 0 })
			}
			if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
				t.Fatalf("full set: %+v %v", picks, err)
			}
			before := f.snapshot()
			if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall.Add(setRecheck)) {
				t.Fatalf("direct=%v short=%s: wake %v %v %v, want set recheck", direct, short, wake, ok, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("readiness probe changed the ledger")
			}
		}
	}
}

// A degraded reading may retain an already expired record. That record
// must not request immediate wakes until a trusted sweep can free its slot.
func TestAdmissionLedgerSlotWakeIgnoresUntrustedPastExpiry(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 2})
	expires := f.wall.Add(30 * time.Second)
	if _, _, _, err := f.l.Reserve(f.queuedAt("192.0.2.10"), admission.LaneGeneral, expires); err != nil {
		t.Fatal(err)
	}
	f.queuedAt("192.0.2.11")
	if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
		t.Fatalf("held slot: %+v %v", picks, err)
	}
	at := expires.Add(time.Minute)
	tick, err := f.l.Tick(admission.ClockReading{Wall: at, BootID: ledgerBoot, SinceBoot: f.since})
	if err != nil || !tick.Degraded {
		t.Fatalf("forward step: %+v %v", tick, err)
	}
	if records, _, _ := f.effectRecords(); len(records) != 1 {
		t.Fatal("degraded reading did not retain the slot")
	}
	for range 3 {
		if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(at.Add(setRecheck)) {
			t.Fatalf("untrusted expiry requests wake %v %v %v, want recheck", wake, ok, err)
		}
	}
}

// With no set the engine owns its set_full reason, including when other
// budgets run short. Polling must not replace it and count another wait.
func TestAdmissionLedgerSlotWaitOwnershipWithoutASet(t *testing.T) {
	for _, short := range []string{"none", "ceiling", "history"} {
		f := liveLedgerFixture(t)
		id := f.queuedAt("192.0.2.10")
		if _, err := f.l.Defer(id, admission.ReasonSetFull); err != nil {
			t.Fatal(err)
		}
		before := f.candidateOf(id)
		counts, notices := f.countersSnapshot(), f.notices()
		switch short {
		case "ceiling":
			f.leaveCeilingCredit(0, 0)
		case "history":
			f.adjustStorage(func(s *admission.StorageState) { s.General.Credit, s.Reserved.Credit = 0, 0 })
		}
		for range 3 {
			if _, err := f.l.Schedule(allSlots, nil); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, f.candidateOf(id)) || !reflect.DeepEqual(counts, f.countersSnapshot()) || !reflect.DeepEqual(notices, f.notices()) {
				t.Fatalf("%s shortage changed an engine-owned wait, count or notice", short)
			}
		}
	}
}

// Forecast selection and wake ignore live slots: the shadow model owns
// their capacity. They still preserve an engine-owned set_full wait.
func TestAdmissionLedgerSlotBudgetDoesNotGateForecast(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queuedAt("192.0.2.10")
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 1, Unclaimed: 1})
	if _, err := f.l.Defer(id, admission.ReasonSetFull); err != nil {
		t.Fatal(err)
	}
	before := f.candidateOf(id)
	if picks, err := f.l.SchedulePreview(nil); err != nil || len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("forecast selection: %+v %v", picks, err)
	}
	if wake, ok, err := f.l.PreviewWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("forecast wake: %v %v %v", wake, ok, err)
	}
	if !reflect.DeepEqual(before, f.candidateOf(id)) {
		t.Fatal("forecast changed an engine-owned wait")
	}
}

// Either eligible lane may become usable first: a free slot on a lane
// waiting for credit must not hide the other lane's earlier slot wake.
func TestAdmissionLedgerSlotWakeWithCreditOnTheFullLane(t *testing.T) {
	for _, fullLane := range []admission.Lane{admission.LaneGeneral, admission.LaneDirect} {
		for _, recorded := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recorded=%v", fullLane, recorded), func(t *testing.T) {
				f := liveLedgerFixture(t)
				if err := f.l.SetCeiling(10); err != nil {
					t.Fatal(err)
				}
				base := admission.SetOccupancy{Limit: 2}
				want := f.wall.Add(setRecheck)
				switch {
				case recorded:
					want = f.wall.Add(30 * time.Second)
					if _, _, _, err := f.l.Reserve(f.directAt("192.0.2.10"), fullLane, want); err != nil {
						t.Fatal(err)
					}
				case fullLane == admission.LaneGeneral:
					base.General = 1
				default:
					base.Reserved = 1
				}
				f.l.SetOccupants(&base)
				if fullLane == admission.LaneGeneral {
					f.leaveCeilingCredit(1, 0)
				} else {
					f.leaveCeilingCredit(0, 1)
				}
				id := f.directAt("192.0.2.11")
				if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
					t.Fatalf("split shortages: %+v %v", picks, err)
				}
				if c := f.candidateOf(id); c.Reason != admission.ReasonSetFull {
					t.Fatalf("waiting reason %s, want set_full", c.Reason)
				}
				before := f.snapshot()
				if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(want) {
					t.Fatalf("wake %v %v %v, want %v", wake, ok, err, want)
				}
				if !reflect.DeepEqual(before, f.snapshot()) {
					t.Fatal("wake probe changed the ledger")
				}
				f.tickAt(want)
				if !recorded {
					f.l.SetOccupants(&admission.SetOccupancy{Limit: 2})
				}
				if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 1 || picks[0].ID != id || picks[0].Lane != fullLane {
					t.Fatalf("freed slot: %+v %v", picks, err)
				}
			})
		}
	}
}

// A retained past expiry must neither spin the timer nor hide the next
// future expiry that can free a slot before the periodic recheck.
func TestAdmissionLedgerSlotWakePastExpiryKeepsFutureExpiry(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 3})
	past := f.wall.Add(30 * time.Second)
	future := f.wall.Add(2 * time.Minute)
	for i, expires := range []time.Time{past, future} {
		id := f.queuedAt(fmt.Sprintf("192.0.2.%d", 10+i))
		if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, expires); err != nil {
			t.Fatal(err)
		}
	}
	id := f.queuedAt("192.0.2.12")
	if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
		t.Fatalf("held slots: %+v %v", picks, err)
	}
	at := past.Add(time.Minute)
	tick, err := f.l.Tick(admission.ClockReading{Wall: at, BootID: ledgerBoot, SinceBoot: f.since})
	if err != nil || !tick.Degraded {
		t.Fatalf("forward step: %+v %v", tick, err)
	}
	if records, _, _ := f.effectRecords(); len(records) != 2 {
		t.Fatalf("degraded reading retained %d slots, want 2", len(records))
	}
	before := f.snapshot()
	for range 3 {
		if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(future) {
			t.Fatalf("wake %v %v %v, want future expiry %v", wake, ok, err, future)
		}
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("wake probe changed the ledger")
	}
	f.wall = at
	f.tickAt(future)
	if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("freed slots: %+v %v", picks, err)
	}
}

// A refused pick spends no slots when selection restarts. The final
// picks alone consume the bounded or unbounded budget used for deferrals.
func TestAdmissionLedgerSlotBudgetAfterRefusedPick(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(fmt.Sprintf("bounded=%v", bounded), func(t *testing.T) {
			f, raise := newFloorLedger(t)
			highRoot := f.published(evidenceSpec{owner: f.owner("alice"), cursor: "high"})
			_, refused := f.enqueue(f.request("192.0.2.10", highRoot))
			var valid []admission.CandidateID
			for i := range 3 {
				target := fmt.Sprintf("192.0.2.%d", 11+i)
				root := f.published(evidenceSpec{owner: f.owner("bob"), target: target, cursor: target, severity: admission.SeverityCritical})
				_, id := f.enqueue(f.request(target, root))
				valid = append(valid, id)
			}
			f.schedule(admission.ScheduleLimits{Members: 1})
			raise(admission.SeverityCritical)
			lim := allSlots
			wantReason := admission.ReasonCeiling
			if bounded {
				f.l.SetOccupants(&admission.SetOccupancy{Limit: 3})
				wantReason = admission.ReasonSetFull
			} else {
				lim.General = 2
			}
			picks := f.schedule(lim)
			if len(picks) != 2 {
				t.Fatalf("picks after refusal: %+v, want two", picks)
			}
			if c := f.candidateOf(refused); c.State != admission.StateRefused || c.Reason != admission.ReasonPolicy {
				t.Fatalf("invalid pick survived revalidation: %+v", c)
			}
			lanes := pickLanes(picks)
			waiting := 0
			for _, id := range valid {
				want := wantReason
				if lane, picked := lanes[id]; picked {
					if lane != admission.LaneGeneral {
						t.Fatalf("pick used lane %s, want general", lane)
					}
					want = 0
				} else {
					waiting++
				}
				if c := f.candidateOf(id); c.Reason != want {
					t.Fatalf("candidate %s reason %s, want %s", id, c.Reason, want)
				}
			}
			if waiting != 1 {
				t.Fatalf("waiting candidates %d, want one", waiting)
			}
		})
	}
}
