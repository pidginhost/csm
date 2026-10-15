package store

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) preview(pending map[admission.CandidateID]admission.Answer) []admission.Pick {
	f.t.Helper()
	picks, err := f.l.SchedulePreview(pending)
	if err != nil {
		f.t.Fatal(err)
	}
	return picks
}

// Selecting for a dry-run forecast is not admission: with the live
// ceiling and history budgets spent it still selects every ready pick,
// records no deferral, count or notice for that shortage, and charges and
// reserves nothing. Picks stay queued for the forecast to end.
func TestAdmissionLedgerPreviewIgnoresLiveBudgets(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11", "192.0.2.12")
	f.leaveCeilingCredit(0, 0)
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit, s.Reserved.Credit = 0, 0 })
	if picks := f.schedule(fullSchedule); len(picks) != 0 {
		t.Fatalf("fixture: live budgets still serve %+v", picks)
	}
	// The live schedule deferred them. A selection clears those stale
	// reasons with no count or notice.
	counters, ceiling, storage := f.countersSnapshot(), f.ceilingState(), f.storageState()
	notices, err := f.l.PendingNotices()
	if err != nil {
		t.Fatal(err)
	}
	picks := f.preview(nil)
	if got := pickIDs(picks); len(got) != 3 || !slices.Contains(got, ids[0]) || !slices.Contains(got, ids[1]) || !slices.Contains(got, ids[2]) {
		t.Fatalf("preview picks = %v, want %v", got, ids)
	}
	for _, p := range picks {
		if c := f.candidateOf(p.ID); c.State != admission.StateQueued || c.Attempts != 0 || p.Lane != admission.LaneGeneral || p.Cost != 1 || p.Bytes != 0 {
			t.Fatalf("pick %+v of %+v", p, c)
		}
	}
	again, err := f.l.PendingNotices()
	if err != nil || !reflect.DeepEqual(again, notices) || !reflect.DeepEqual(f.countersSnapshot(), counters) ||
		!reflect.DeepEqual(f.ceilingState(), ceiling) || !reflect.DeepEqual(f.storageState(), storage) {
		t.Fatalf("selection changed capacity, counts or notices: %v", err)
	}
}

// Real safety state still gates a selection: revalidation ends a pick
// below a raised policy floor and an aged-out one, a retry waits out its
// backoff, an unresolved attempt holds its target (deferred as pending
// recovery once its backoff is over, as a schedule records it) and pending
// work is passed over without a transition.
func TestAdmissionLedgerPreviewKeepsSafetyGates(t *testing.T) {
	f, raise := newFloorLedger(t)
	failedRetry := func(target string) admission.CandidateID {
		f.nextGeneration()
		root := f.published(evidenceSpec{target: target, cursor: "retry=" + target, severity: admission.SeverityCritical})
		_, id := f.enqueue(f.request(target, root))
		_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
			t.Fatal(err)
		}
		return id
	}
	highRoot := f.published(evidenceSpec{owner: f.owner("alice"), cursor: "high"})
	_, high := f.enqueue(f.request("192.0.2.10", highRoot))
	critical := f.published(evidenceSpec{owner: f.owner("bob"), target: "192.0.2.11", cursor: "critical", severity: admission.SeverityCritical})
	_, kept := f.enqueue(f.request("192.0.2.11", critical))
	retry := failedRetry("192.0.2.12")
	held := failedRetry("192.0.2.13")
	f.nextGeneration()
	unknownRoot := f.published(evidenceSpec{target: "192.0.2.13", cursor: "unknown", severity: admission.SeverityCritical})
	_, unknown := f.enqueue(f.request("192.0.2.13", unknownRoot))
	_, u, _, err := f.l.Reserve(unknown, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(u.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(u.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	waitingRoot := f.published(evidenceSpec{target: "192.0.2.14", cursor: "waiting", severity: admission.SeverityCritical})
	_, waiting := f.enqueue(f.request("192.0.2.14", waitingRoot))
	pending := pendingSet(waiting)
	if got := pickIDs(f.preview(pending)); len(got) != 2 || !slices.Contains(got, high) || !slices.Contains(got, kept) {
		t.Fatalf("first selection = %v, want the two fresh picks %s and %s", got, high, kept)
	}
	if c := f.candidateOf(held); c.Reason != 0 {
		t.Fatalf("a held retry in its backoff was deferred: %+v", c)
	}
	// The selections above checked every queued candidate, so the next one
	// must refuse the raised floor at its pick.
	raise(admission.SeverityCritical)
	if got := pickIDs(f.preview(pending)); !reflect.DeepEqual(got, []admission.CandidateID{kept}) {
		t.Fatalf("picks after the policy change = %v, want only %s", got, kept)
	}
	if c := f.candidateOf(high); c.State != admission.StateRefused || c.Reason != admission.ReasonPolicy {
		t.Fatalf("pick below the new floor = %+v", c)
	}
	f.tickAt(f.candidateOf(held).NotBefore.Add(time.Second))
	got := pickIDs(f.preview(pending))
	if len(got) != 2 || !slices.Contains(got, kept) || !slices.Contains(got, retry) {
		t.Fatalf("after the backoff = %v", got)
	}
	deferredHeld := f.candidateOf(held)
	if deferredHeld.State != admission.StateQueued || deferredHeld.Reason != admission.ReasonPendingRecovery {
		t.Fatalf("held pick = %+v, want a pending_recovery deferral", deferredHeld)
	}
	f.preview(pending)
	if c := f.candidateOf(held); c.Transitions != deferredHeld.Transitions || f.count(deferredKey(admission.ReasonPendingRecovery, f.entryTier(held))) != 1 {
		t.Fatalf("the same hold was deferred again: %+v", c)
	}
	if c := f.candidateOf(waiting); c.State != admission.StateQueued || c.Reason != 0 || c.Transitions != 1 {
		t.Fatalf("pending pick = %+v", c)
	}
	f.tickAt(ledgerT0.Add(admission.QueueAgeLimit))
	if got = pickIDs(f.preview(nil)); len(got) != 0 {
		t.Fatalf("aged-out work was selected: %v", got)
	}
	if c := f.candidateOf(kept); c.State != admission.StateDropped || c.Reason != admission.ReasonStale {
		t.Fatalf("aged-out pick = %+v", c)
	}
}

// A selection judges no live budget, so a live ceiling or storage-share
// wait on work it passes over is stale. It clears as a schedule clears a
// resolved budget reason, on a pick and on a retry in its backoff: one
// transition, no count and no notice. Pending work and outside reasons
// keep theirs.
func TestAdmissionLedgerPreviewClearsLiveBudgetReasons(t *testing.T) {
	for _, reason := range []admission.Reason{admission.ReasonCeiling, admission.ReasonStorageShare} {
		t.Run(reason.String(), func(t *testing.T) {
			f := newLedgerFixture(t)
			retry, a := f.admitted(time.Hour)
			if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
				t.Fatal(err)
			}
			f.begin()
			ids := f.criticalArrivals("192.0.2.20", "192.0.2.21", "192.0.2.22")
			picked, pending, external := ids[0], ids[1], ids[2]
			before := map[admission.CandidateID]admission.Candidate{}
			for _, id := range []admission.CandidateID{retry, picked, pending} {
				c, err := f.l.Defer(id, reason)
				if err != nil {
					t.Fatal(err)
				}
				before[id] = c
			}
			if _, err := f.l.Defer(external, admission.ReasonSetFull); err != nil {
				t.Fatal(err)
			}
			counters, notices := f.countersSnapshot(), f.notices()
			if got := pickIDs(f.preview(pendingSet(pending))); len(got) != 2 || !slices.Contains(got, picked) || !slices.Contains(got, external) {
				t.Fatalf("picks = %v", got)
			}
			for _, id := range []admission.CandidateID{retry, picked} {
				if c := f.candidateOf(id); c.Reason != 0 || c.Transitions != before[id].Transitions+1 {
					t.Fatalf("%s kept reason %s, transitions %d, want %d", id, c.Reason, c.Transitions, before[id].Transitions+1)
				}
			}
			if c := f.candidateOf(pending); c.Reason != reason || c.Transitions != before[pending].Transitions {
				t.Fatalf("pending work = %+v", c)
			}
			if c := f.candidateOf(external); c.Reason != admission.ReasonSetFull {
				t.Fatalf("outside reason = %s", c.Reason)
			}
			if !reflect.DeepEqual(f.countersSnapshot(), counters) || !reflect.DeepEqual(f.notices(), notices) {
				t.Fatal("clearing a reason changed counts or notices")
			}
			f.preview(pendingSet(pending))
			for _, id := range []admission.CandidateID{retry, picked} {
				if c := f.candidateOf(id); c.Transitions != before[id].Transitions+1 {
					t.Fatalf("%s cleared again", id)
				}
			}
		})
	}
}

// The first selection of a reopened ledger checks every queued candidate,
// not only its picks: one waiting on the panel ends below a raised floor.
func TestAdmissionLedgerPreviewRevalidatesAfterReopen(t *testing.T) {
	f, raise := newFloorLedger(t)
	root := f.published(evidenceSpec{cursor: "high"})
	_, waiting := f.enqueue(f.request("192.0.2.10", root))
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	f.tickAt(f.wall)
	raise(admission.SeverityCritical)
	if got := f.preview(pendingSet(waiting)); len(got) != 0 {
		t.Fatalf("picks = %v", got)
	}
	if c := f.candidateOf(waiting); c.State != admission.StateRefused || c.Reason != admission.ReasonPolicy {
		t.Fatalf("pending work below the new floor = %+v", c)
	}
}

// A damaged queue refuses a selection and changes nothing.
func TestAdmissionLedgerPreviewRefusesDamage(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueBucket)).Put([]byte(id), []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if _, err := f.l.SchedulePreview(nil); !isCorrupt(err) {
		t.Fatalf("damaged queue: %v, want a corrupt record", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused selection changed the ledger")
	}
}

// Ignoring live budgets must not bypass the storage checks a live schedule
// performs, including the paid history of retries and in-flight attempts.
func TestAdmissionLedgerPreviewRefusesStorageDamage(t *testing.T) {
	for _, state := range []admission.State{admission.StateQueued, admission.StateReserved, admission.StateExecuting} {
		for _, damage := range []string{"ceiling", "storage", "history", "missing history"} {
			t.Run(state.String()+"/"+damage, func(t *testing.T) {
				f := newLedgerFixture(t)
				id, a := f.admitted(time.Hour)
				switch state {
				case admission.StateQueued:
					if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
						t.Fatal(err)
					}
					f.tickAt(f.candidateOf(id).NotBefore)
				case admission.StateExecuting:
					if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
					switch damage {
					case "ceiling":
						return tx.Bucket([]byte(admissionQueueStateBucket)).Put(ceilingStateKey, []byte("{}"))
					case "storage":
						return tx.Bucket([]byte(admissionQueueStateBucket)).Put(storageStateKey, []byte("{}"))
					case "history":
						return tx.Bucket([]byte(admissionHistoryBucket)).Put([]byte(id), []byte("{}"))
					default:
						return tx.Bucket([]byte(admissionHistoryBucket)).Delete([]byte(id))
					}
				}); err != nil {
					t.Fatal(err)
				}
				before := f.snapshot()
				if _, err := f.l.Schedule(fullSchedule, nil); !isCorrupt(err) {
					t.Fatalf("live schedule accepted damaged %s: %v", damage, err)
				}
				if _, _, err := f.l.PreviewWake(nil); !isCorrupt(err) {
					t.Errorf("preview wake accepted damaged %s: %v", damage, err)
				}
				if picks, err := f.l.SchedulePreview(nil); !isCorrupt(err) || len(picks) != 0 {
					t.Errorf("preview accepted damaged %s: picks %v, error %v", damage, picks, err)
				}
				if !reflect.DeepEqual(before, f.snapshot()) {
					t.Fatal("a refused selection changed the ledger")
				}
			})
		}
	}
}

// A selection takes at most 64 picks and advances the shared fair
// position once: scopes rotate across selections as they do across
// schedules, every candidate weighing one unit whatever it asks for.
func TestAdmissionLedgerPreviewBoundsAndRotates(t *testing.T) {
	f := newLedgerFixture(t)
	f.fill(30, evidenceSpec{owner: f.owner("alice")})
	f.fill(30, evidenceSpec{owner: f.owner("bob")})
	f.fill(30, evidenceSpec{})
	first := f.preview(nil)
	if len(first) != admission.MaxBatchMembers {
		t.Fatalf("first selection = %d picks", len(first))
	}
	scopes := map[string]int{}
	for _, p := range first {
		scopes[f.scopeOf(p.ID)]++
	}
	if len(scopes) != 3 {
		t.Fatalf("scopes = %v", scopes)
	}
	for scope, n := range scopes {
		if n != 21 && n != 22 {
			t.Fatalf("scope %s took %d of 64 turns", scope, n)
		}
	}
	// Nothing ends the picks here, so the next selection resumes after the
	// stored position: 64 turns over three scopes end on the first scope,
	// and the second selection starts on the next.
	second := f.preview(nil)
	if len(second) != admission.MaxBatchMembers || f.scopeOf(second[0].ID) == f.scopeOf(first[0].ID) {
		t.Fatalf("second selection restarted the rotation: both start with %s", f.scopeOf(first[0].ID))
	}
	req := f.request("192.0.2.99", f.published(evidenceSpec{target: "192.0.2.99", cursor: "challenge"}))
	req.Kind = admission.KindChallenge
	_, challenge := f.enqueue(req)
	found := false
	for _, p := range f.preview(nil) {
		if p.Cost != 1 {
			t.Fatalf("pick %+v weighs %d", p, p.Cost)
		}
		found = found || p.ID == challenge
	}
	if !found {
		t.Fatal("the challenge was not selected")
	}
}

// Dry-run and live selection share one stored fair position: each resumes
// the scope rotation where the other one stopped.
func TestAdmissionLedgerPreviewSharesTheFairPosition(t *testing.T) {
	f := newLedgerFixture(t)
	f.fill(30, evidenceSpec{owner: f.owner("alice")})
	f.fill(30, evidenceSpec{owner: f.owner("bob")})
	f.fill(30, evidenceSpec{})
	first := f.preview(nil)
	order := []string{f.scopeOf(first[0].ID), f.scopeOf(first[1].ID), f.scopeOf(first[2].ID)}
	after := func(picks []admission.Pick) string {
		i := slices.Index(order, f.scopeOf(picks[len(picks)-1].ID))
		return order[(i+1)%len(order)]
	}
	live := f.schedule(admission.ScheduleLimits{General: 5, Members: admission.MaxBatchMembers})
	if len(live) != 5 || f.scopeOf(live[0].ID) != after(first) {
		t.Fatalf("live schedule after a selection starts with %s, want %s", f.scopeOf(live[0].ID), after(first))
	}
	if again := f.preview(nil); f.scopeOf(again[0].ID) != after(live) {
		t.Fatalf("selection after a live schedule starts with %s, want %s", f.scopeOf(again[0].ID), after(live))
	}
}

// Direct and corroborated work alternates in the reserved lane for at most
// 13 of a selection's members; the general lane serves the rest by class
// and severity, where reserved-eligible work competes as well. A general
// pick never takes a reserved lane.
func TestAdmissionLedgerPreviewBoundsTheReservedLane(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	var directIDs []admission.CandidateID
	for i := range 40 {
		res := f.arrive(f.arrival(evidenceSpec{producer: f.mail, check: "mail_takeover", target: fmt.Sprintf("198.51.100.%d", i+1), cursor: fmt.Sprintf("direct=%d", i), severity: admission.SeverityCritical}))[0]
		if res.Err != nil || !res.Created {
			t.Fatalf("arrival %d = %+v", i, res)
		}
		directIDs = append(directIDs, res.Candidate)
	}
	f.fill(30, evidenceSpec{owner: f.owner("bob")})
	picks := f.preview(nil)
	if len(picks) != admission.MaxBatchMembers {
		t.Fatalf("picks = %d", len(picks))
	}
	isDirect := map[admission.CandidateID]bool{}
	for _, id := range directIDs {
		isDirect[id] = true
	}
	var reserved, generalPicks, directInGeneral int
	for i, p := range picks {
		switch p.Lane {
		case admission.LaneDirect, admission.LaneCorroborated:
			if i >= 13 || !isDirect[p.ID] {
				t.Fatalf("reserved pick %d = %+v", i, p)
			}
			reserved++
		case admission.LaneGeneral:
			if isDirect[p.ID] {
				directInGeneral++
			} else {
				generalPicks++
			}
		}
	}
	if reserved != 13 || directInGeneral == 0 || generalPicks == 0 {
		t.Fatalf("reserved %d, direct in general %d, general %d", reserved, directInGeneral, generalPicks)
	}
	// Live scheduling keeps its own lane budgets.
	live := f.schedule(admission.ScheduleLimits{Reserved: 2, Members: admission.MaxBatchMembers})
	if len(live) != 2 || live[0].Lane == admission.LaneGeneral || live[1].Lane == admission.LaneGeneral {
		t.Fatalf("live reserved picks = %+v", live)
	}
}

// Spec 3.2 amendment: a challenge's comparison preview spends live history,
// so a selection skips one the live history budget cannot serve, the check
// a live schedule makes. Without that the forecast reselects it every
// second: the wake says now, the selection picks it and its preview fails
// again. A skipped challenge records no wait and takes no fair turn, block
// work beside it is still selected, and the wake is when the budget can pay
// for it, so a budget change brings it back without new input.
func TestAdmissionLedgerPreviewSkipsChallengesHistoryCannotServe(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	req := f.request("192.0.2.99", f.published(evidenceSpec{target: "192.0.2.99", cursor: "challenge"}))
	req.Kind = admission.KindChallenge
	_, challenge := f.enqueue(req)
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit, s.Reserved.Credit = 0, 0 })
	if picks := f.schedule(fullSchedule); len(picks) != 0 {
		t.Fatalf("fixture: live history still serves the challenge: %+v", picks)
	}
	// The first selection clears the live schedule's wait, as it clears
	// every live budget wait; then nothing changes.
	if picks := f.preview(nil); len(picks) != 0 {
		t.Fatalf("the selection picked a challenge history cannot serve: %+v", picks)
	}
	before, counters, notices := f.candidateOf(challenge), f.countersSnapshot(), f.notices()
	readPosition := func() admission.ScheduleState {
		var st admission.ScheduleState
		if err := f.db.bolt.View(func(tx *bolt.Tx) (err error) { st, err = loadScheduleState(tx); return err }); err != nil {
			t.Fatal(err)
		}
		return st
	}
	position := readPosition()
	for range 3 {
		if picks := f.preview(nil); len(picks) != 0 {
			t.Fatalf("the selection picked a challenge history cannot serve: %+v", picks)
		}
	}
	if c := f.candidateOf(challenge); !reflect.DeepEqual(c, before) {
		t.Fatalf("a skipped challenge changed: %+v, before %+v", c, before)
	}
	if !reflect.DeepEqual(readPosition(), position) || !reflect.DeepEqual(f.countersSnapshot(), counters) || !reflect.DeepEqual(f.notices(), notices) {
		t.Fatal("a skipped challenge took a fair turn, a count or a notice")
	}
	need, ok := f.storageState().UntilHistoryCost(admission.LaneGeneral, f.cost(challenge))
	if !ok || need <= 0 {
		t.Fatalf("fixture: no history wait for the challenge: %v %v", need, ok)
	}
	wake, ok, err := f.l.PreviewWake(nil)
	if err != nil || !ok || !wake.Equal(f.wall.Add(need)) {
		t.Fatalf("wake = %v %v %v, want when the history credit pays for the challenge, %v", wake, ok, err, f.wall.Add(need))
	}
	block := f.criticalArrivals("192.0.2.10")[0]
	if got := pickIDs(f.preview(nil)); !reflect.DeepEqual(got, []admission.CandidateID{block}) {
		t.Fatalf("picks beside the skipped challenge = %v, want only the block %s", got, block)
	}
	f.tickAt(wake)
	if got := pickIDs(f.preview(nil)); !slices.Contains(got, challenge) {
		t.Fatalf("picks once the budget can pay = %v, want the challenge", got)
	}
}

// Challenge previews share the same live history budget within a turn.
// Individually affordable challenges must not collectively overspend it.
func TestAdmissionLedgerPreviewBoundsCombinedChallengeHistory(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	var challenges []admission.CandidateID
	for i := range 2 {
		ip := fmt.Sprintf("192.0.2.%d", 90+i)
		req := f.request(ip, f.published(evidenceSpec{target: ip, cursor: ip}))
		req.Kind = admission.KindChallenge
		_, id := f.enqueue(req)
		challenges = append(challenges, id)
	}
	need := max(f.cost(challenges[0]), f.cost(challenges[1]))
	f.adjustStorage(func(s *admission.StorageState) {
		s.General.Credit = uint64(need) * uint64(time.Second)
		s.Reserved.Credit = 0
	})
	block := f.criticalArrivals("192.0.2.10")[0]
	picks := f.preview(nil)
	if len(picks) != 2 || !slices.Contains(pickIDs(picks), block) {
		t.Fatalf("picks = %+v, want one challenge and the block", picks)
	}
	for _, id := range challenges {
		if c := f.candidateOf(id); c.Reason != 0 || c.Transitions != 1 {
			t.Fatalf("challenge changed during selection: %+v", c)
		}
	}
}

// A reserved-eligible challenge is selected only on a lane whose live
// history can pay for its preview: the reserved lane while only it can,
// even when the reserved lane's selection bound left it to the general
// lane, the general lane while only it can, and neither once both are
// spent.
func TestAdmissionLedgerPreviewServesAChallengeOnALaneThatCanPay(t *testing.T) {
	const keep = ^uint64(0)
	for _, tc := range []struct {
		name    string
		credit  [2]uint64
		crowded bool
		want    admission.Lane
	}{
		{name: "reserved only", credit: [2]uint64{0, keep}, want: admission.LaneDirect},
		{name: "reserved only, reserved bound spent", credit: [2]uint64{0, keep}, crowded: true, want: admission.LaneDirect},
		{name: "general only", credit: [2]uint64{keep, 0}, want: admission.LaneGeneral},
		{name: "neither", credit: [2]uint64{0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			var crowd []admission.CandidateID
			if tc.crowded {
				// Thirteen reserved scopes sort before the challenge's and
				// take every reserved slot of the selection.
				var accounts []string
				for i := range previewReservedMembers {
					accounts = append(accounts, fmt.Sprintf("a%02d", i))
				}
				f.refresh(accounts, nil)
				for i, account := range accounts {
					res := f.arrive(f.arrival(evidenceSpec{producer: f.mail, check: "mail_takeover", owner: f.owner(account), target: fmt.Sprintf("198.51.100.%d", i+1), cursor: "crowd=" + account, severity: admission.SeverityCritical}))[0]
					if res.Err != nil || !res.Created {
						t.Fatalf("arrival %s = %+v", account, res)
					}
					crowd = append(crowd, res.Candidate)
				}
			}
			root := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.99", cursor: "challenge", severity: admission.SeverityCritical})
			req := f.request("192.0.2.99", root)
			req.Kind = admission.KindChallenge
			_, challenge := f.enqueue(req)
			if e, err := f.entry(challenge); err != nil || !e.Direct {
				t.Fatalf("fixture: challenge entry %+v %v is not reserved-eligible", e, err)
			}
			f.adjustStorage(func(s *admission.StorageState) {
				s.General.Credit = min(s.General.Credit, tc.credit[0])
				s.Reserved.Credit = min(s.Reserved.Credit, tc.credit[1])
			})
			var got *admission.Pick
			reserved := 0
			for _, p := range f.preview(nil) {
				if p.ID == challenge {
					got = &p
				} else if p.Lane != admission.LaneGeneral {
					reserved++
				}
			}
			switch {
			case tc.want == 0 && got != nil:
				t.Fatalf("picked %+v, want no pick", *got)
			case tc.want != 0 && (got == nil || got.Lane != tc.want):
				t.Fatalf("challenge pick = %+v, want lane %s", got, tc.want)
			case tc.crowded && reserved != previewReservedMembers:
				t.Fatalf("fixture: %d of %d crowd picks took the reserved lane", reserved, len(crowd))
			}
		})
	}
}

// Without reserved work the general lane takes all 64 members.
func TestAdmissionLedgerPreviewLendsReservedMembers(t *testing.T) {
	f := newLedgerFixture(t)
	f.fill(70, evidenceSpec{owner: f.owner("bob")})
	if picks := f.preview(nil); len(picks) != admission.MaxBatchMembers {
		t.Fatalf("picks = %d", len(picks))
	}
}

// A forecast wakes for selectable work whatever the live budgets, waits
// out a retry's backoff and an age-out, and skips pending work.
func TestAdmissionLedgerPreviewWake(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10")
	f.leaveCeilingCredit(0, 0)
	if wake, ok, err := f.l.NextWake(nil); err != nil || (ok && !wake.After(f.wall)) {
		t.Fatalf("fixture: live wake %v %v %v is not after now", wake, ok, err)
	}
	if wake, ok, err := f.l.PreviewWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("preview wake = %v %v %v, want now", wake, ok, err)
	}
	if wake, ok, err := f.l.PreviewWake(pendingSet(ids...)); err != nil || !ok || !wake.Equal(f.candidateOf(ids[0]).AgeOut) {
		t.Fatalf("pending wake = %v %v %v, want its age-out", wake, ok, err)
	}
	g := newLedgerFixture(t)
	id, a := g.admitted(time.Hour)
	if _, _, err := g.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if wake, ok, err := g.l.PreviewWake(nil); err != nil || !ok || !wake.Equal(g.candidateOf(id).NotBefore) {
		t.Fatalf("retry wake = %v %v %v, want its backoff end", wake, ok, err)
	}
	// A held target waits for recovery, not a turn.
	k := newLedgerFixture(t)
	_, u := k.admitted(time.Hour)
	if _, _, _, err := k.l.Execute(u.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.l.Finish(u.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	k.nextGeneration()
	held := k.queued()
	if wake, ok, err := k.l.PreviewWake(nil); err != nil || !ok || !wake.Equal(k.candidateOf(held).AgeOut) {
		t.Fatalf("held wake = %v %v %v, want its age-out", wake, ok, err)
	}
	// A deadline that passed before a sweep is due now.
	g.tickAt(g.candidateOf(id).ExpiresAt.Add(time.Second))
	if wake, ok, err := g.l.PreviewWake(pendingSet(id)); err != nil || !ok || !wake.Equal(g.wall) {
		t.Fatalf("overdue wake = %v %v %v, want now", wake, ok, err)
	}
	h := newLedgerFixture(t)
	if _, ok, err := h.l.PreviewWake(nil); err != nil || ok {
		t.Fatalf("empty queue wake = %v %v", ok, err)
	}
}
