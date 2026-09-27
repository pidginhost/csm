package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) entry(id admission.CandidateID) (e admission.QueueEntry, err error) {
	err = f.db.bolt.View(func(tx *bolt.Tx) error {
		e, err = loadQueueEntry(tx, id)
		return err
	})
	return e, err
}

func (f *ledgerFixture) queueState() admission.QueueState {
	f.t.Helper()
	var s admission.QueueState
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		s, err = loadQueueState(tx)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *ledgerFixture) count(k admission.CountKey) uint64 {
	f.t.Helper()
	var q admission.QueueCounters
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		q, err = loadQueueCounters(tx)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return q.Count(k)
}

// fill queues n candidates in one transaction, each from its own fresh root
// shaped by spec and aimed at its own documentation address.
func (f *ledgerFixture) fill(n int, spec evidenceSpec) []admission.CandidateID {
	f.t.Helper()
	var ids []admission.CandidateID
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	if err := f.l.update("fill", func(tx *bolt.Tx) error {
		q, err := f.l.openQueue(tx, f.l.now)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			f.fills++
			s := spec
			s.target, s.cursor = fmt.Sprintf("2001:db8::%x", f.fills), fmt.Sprintf("fill=%d", f.fills)
			e := f.mint(s)
			data, err := e.MarshalBinary()
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(e.ID()), data); err != nil {
				return err
			}
			req := f.request(s.target, e.ID())
			key := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: req.Episode, Generation: req.Generation}
			id, err := key.ID()
			if err != nil {
				return err
			}
			if _, _, err = f.l.enqueueTx(q, req, key, id, []admission.EvidenceID{e.ID()}); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return q.flush()
	}); err != nil {
		f.t.Fatal(err)
	}
	return ids
}

// newest is the candidate a scope loses first among candidates of one tier
// queued at the same instant: the greatest ID.
func newest(ids []admission.CandidateID) admission.CandidateID {
	out := ids[0]
	for _, id := range ids[1:] {
		if id > out {
			out = id
		}
	}
	return out
}

func ended(reason admission.Reason, tier admission.Tier) admission.CountKey {
	return admission.CountKey{Event: admission.EventEnded, Reason: reason, Class: tier.Class, Severity: tier.Severity}
}

var sshHigh = admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityHigh}

// Every live candidate holds one entry: its partition and last assessment.
// Leaving the queue for good deletes it; a retry keeps it.
func TestAdmissionLedgerQueueEntries(t *testing.T) {
	f := newLedgerFixture(t)
	local := f.published(evidenceSpec{})
	_, id := f.enqueue(f.request("192.0.2.10", local))
	e, err := f.entry(id)
	if err != nil || e.Partition != admission.PartitionGeneral || e.Tier != sshHigh || e.Eligible() || !e.NextChange.Equal(ledgerT0.Add(admission.RootFreshness)) {
		t.Fatalf("local candidate entry = %+v, %v", e, err)
	}
	if next := f.queueState().NextSweep; !next.Equal(ledgerT0.Add(admission.QueueAgeLimit)) {
		t.Fatalf("next sweep = %v", next)
	}
	support := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "pass=1"})
	if _, _, err = f.l.Enqueue(f.request("192.0.2.10", local, support)); err != nil {
		t.Fatal(err)
	}
	if e, err = f.entry(id); err != nil || e.Partition != admission.PartitionReserved || !e.Corroborated || e.Tier.Class != admission.ClassC3 {
		t.Fatalf("corroboration did not move the candidate to a reserved position: %+v, %v", e, err)
	}
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, directID := f.enqueue(f.request("192.0.2.11", direct))
	if e, err = f.entry(directID); err != nil || e.Partition != admission.PartitionReserved || !e.Direct {
		t.Fatalf("direct compromise entry = %+v, %v", e, err)
	}
	if _, err = f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	c3h := admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityHigh}
	if n := f.count(admission.CountKey{Event: admission.EventDeferred, Reason: admission.ReasonCeiling, Class: admission.ClassC3, Severity: admission.SeverityHigh}); n != 1 {
		t.Fatalf("deferral count = %d", n)
	}
	if _, err = f.l.Terminate(id, admission.ReasonProtected); err != nil {
		t.Fatal(err)
	}
	if _, err = f.entry(id); !isCorrupt(err) || f.count(ended(admission.ReasonProtected, c3h)) != 1 {
		t.Fatalf("ended candidate kept its entry or was not counted: %v", err)
	}
	_, a, _, err := f.l.Reserve(directID, admission.LaneGeneral, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if _, err = f.entry(directID); err != nil {
		t.Fatalf("a retry lost its entry: %v", err)
	}
	f.tickAt(ledgerT0.Add(admission.RetryBackoff(1)))
	if _, a, _, err = f.l.Reserve(directID, admission.LaneGeneral, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	if _, err = f.entry(directID); !isCorrupt(err) {
		t.Fatalf("an applied candidate kept its entry: %v", err)
	}
}

// A full general partition refuses an arrival of a scope at its share when
// the arrival would be the newest of its lowest tier. A scope below its
// share reclaims one position from the scope over it, and the displaced
// candidate ends as queue overflow in the same transaction. Reserved
// positions stay open for direct compromise.
func TestAdmissionLedgerQueueOverflowDisplaces(t *testing.T) {
	f := newLedgerFixture(t)
	alice, bob := f.owner("alice"), f.owner("bob")
	flood := f.fill(admission.PartitionGeneral.DurableCapacity(), evidenceSpec{owner: alice})
	own := f.published(evidenceSpec{owner: alice, target: "192.0.2.20", cursor: "own"})
	before := f.snapshot()
	_, _, err := f.l.Enqueue(f.request("192.0.2.20", own))
	wantLedgerReason(t, "own scope at its share", err, admission.ReasonQueueOverflow)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused arrival changed records")
	}
	other := f.published(evidenceSpec{owner: bob, target: "192.0.2.21", cursor: "other"})
	before = f.snapshot()
	f.failNext("enqueue")
	if _, _, err = f.l.Enqueue(f.request("192.0.2.21", other)); err == nil {
		t.Fatal("injected failure did not fail the enqueue")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed displacing enqueue changed records")
	}
	c, otherID := f.enqueue(f.request("192.0.2.21", other))
	if e, err := f.entry(otherID); err != nil || e.Partition != admission.PartitionGeneral || c.Scope.Owner != bob {
		t.Fatalf("reclaiming arrival = %+v %+v, %v", c, e, err)
	}
	if got, err := f.l.Candidate(newest(flood)); err != nil || got.State != admission.StateDropped || got.Reason != admission.ReasonQueueOverflow {
		t.Fatalf("newest flood candidate = %+v, %v", got, err)
	}
	if n := f.count(ended(admission.ReasonQueueOverflow, sshHigh)); n != 1 {
		t.Fatalf("displacements counted = %d", n)
	}
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", owner: alice, target: "192.0.2.22", cursor: "direct", severity: admission.SeverityCritical})
	_, directID := f.enqueue(f.request("192.0.2.22", direct))
	if e, err := f.entry(directID); err != nil || e.Partition != admission.PartitionReserved {
		t.Fatalf("direct compromise with a full general partition: %+v, %v", e, err)
	}
}

// Coalescing never adds a position: a repeat that rescopes the candidate
// moves its one position to the new scope, and a repeat of an in-flight
// candidate leaves its position as it is.
func TestAdmissionLedgerCoalescingKeepsOnePosition(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.published(evidenceSpec{owner: f.owner("alice")})
	req := f.request("192.0.2.10", a)
	_, id := f.enqueue(req)
	req.Support = []admission.EvidenceID{f.published(evidenceSpec{cursor: "offset=2"})}
	for range 2 {
		if _, _, err := f.l.Enqueue(req); err != nil {
			t.Fatal(err)
		}
	}
	positions := func() (n int, scope string) {
		if err := f.db.bolt.View(func(tx *bolt.Tx) error {
			q, err := openQueueWith(tx, f.reg, f.l.Inventory(), f.wall)
			if err != nil {
				return err
			}
			v, err := q.queueView()
			if err != nil {
				return err
			}
			it, _ := v.Item(string(id))
			n, scope = v.Len(), it.Scope
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n, scope
	}
	if n, scope := positions(); n != 1 || scope != "host/address" {
		t.Fatalf("after rescoping: %d positions, scope %q", n, scope)
	}
	if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, ledgerT0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req.Support = nil
	if _, _, err := f.l.Enqueue(req); err != nil {
		t.Fatal(err)
	}
	if n, _ := positions(); n != 1 {
		t.Fatalf("in-flight repeat: %d positions", n)
	}
}

// A new candidate first frees the positions of queued candidates whose
// deadlines passed: an age-out, or an effect expiry during a retry wait.
// Neither deadline moves.
func TestAdmissionLedgerSweepAgesOut(t *testing.T) {
	f := newLedgerFixture(t)
	old := f.queued()
	f.nextGeneration()
	retry := f.queued()
	_, a, _, err := f.l.Reserve(retry, admission.LaneGeneral, ledgerT0.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(ledgerT0.Add(30 * time.Minute))
	fresh := f.published(evidenceSpec{target: "192.0.2.30", cursor: "fresh"})
	f.enqueue(f.request("192.0.2.30", fresh))
	if got, _ := f.l.Candidate(retry); got.State != admission.StateDropped || got.Reason != admission.ReasonStale || !got.ExpiresAt.Equal(ledgerT0.Add(30*time.Minute)) {
		t.Fatalf("expired retry wait = %+v", got)
	}
	if got, _ := f.l.Candidate(old); got.State != admission.StateQueued {
		t.Fatalf("a candidate before its age-out was swept: %+v", got)
	}
	f.tickAt(ledgerT0.Add(admission.QueueAgeLimit))
	later := f.published(evidenceSpec{target: "192.0.2.31", cursor: "later"})
	f.enqueue(f.request("192.0.2.31", later))
	got, _ := f.l.Candidate(old)
	if got.State != admission.StateDropped || got.Reason != admission.ReasonStale || !got.AgeOut.Equal(ledgerT0.Add(admission.QueueAgeLimit)) {
		t.Fatalf("aged-out candidate = %+v", got)
	}
	if n := f.count(ended(admission.ReasonStale, sshHigh)); n != 2 {
		t.Fatalf("stale endings counted = %d", n)
	}
}

// A candidate whose corroboration lapses leaves its reserved position at
// its next change. With the general partition full it reclaims a general
// position like any arrival below its share; ranking below its own scope's
// work there, it ends as queue overflow.
func TestAdmissionLedgerSweepMovesLapsedCorroboration(t *testing.T) {
	for _, crowded := range []bool{false, true} {
		t.Run(fmt.Sprintf("own scope crowded %v", crowded), func(t *testing.T) {
			f := newLedgerFixture(t)
			alice, bob := f.owner("alice"), f.owner("bob")
			local := f.published(evidenceSpec{owner: alice, cursor: "local"})
			support := f.published(evidenceSpec{producer: f.rep, check: "reputation", owner: alice, cursor: "pass=1", age: 23 * time.Hour})
			_, id := f.enqueue(f.request("192.0.2.10", local, support))
			if e, _ := f.entry(id); e.Partition != admission.PartitionReserved || !e.NextChange.Equal(ledgerT0.Add(time.Hour)) {
				t.Fatalf("corroborated entry = %+v", e)
			}
			floodOwner := bob
			if crowded {
				floodOwner = alice
			}
			flood := f.fill(admission.PartitionGeneral.DurableCapacity(), evidenceSpec{owner: floodOwner, severity: admission.SeverityCritical})
			f.tickAt(ledgerT0.Add(time.Hour))
			trigger := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.40", cursor: "trigger", severity: admission.SeverityCritical})
			_, triggerID := f.enqueue(f.request("192.0.2.40", trigger))
			if e, err := f.entry(triggerID); err != nil || e.Partition != admission.PartitionReserved {
				t.Fatalf("trigger = %+v, %v", e, err)
			}
			got, _ := f.l.Candidate(id)
			if crowded {
				if got.State != admission.StateDropped || got.Reason != admission.ReasonQueueOverflow || f.count(ended(admission.ReasonQueueOverflow, sshHigh)) != 1 {
					t.Fatalf("lapsed candidate ranking lowest in its scope = %+v", got)
				}
				return
			}
			if e, err := f.entry(id); got.State != admission.StateQueued || err != nil || e.Partition != admission.PartitionGeneral || e.Corroborated || e.Tier != sshHigh {
				t.Fatalf("lapsed candidate = %+v %+v, %v", got, e, err)
			}
			if dropped, _ := f.l.Candidate(newest(flood)); dropped.State != admission.StateDropped {
				t.Fatalf("reclaim did not displace the newest flood candidate: %+v", dropped)
			}
		})
	}
}

// An inventory change that retires an account ends the queued candidates
// whose roots name it, in the refresh transaction. In-flight work keeps its
// frozen roots.
func TestAdmissionLedgerInventoryRefreshEndsStaleOwners(t *testing.T) {
	f := newLedgerFixture(t)
	alice := f.owner("alice")
	queuedRoot := f.published(evidenceSpec{owner: alice, cursor: "queued"})
	_, queued := f.enqueue(f.request("192.0.2.10", queuedRoot))
	flightRoot := f.published(evidenceSpec{owner: alice, target: "192.0.2.11", cursor: "flight"})
	_, flight := f.enqueue(f.request("192.0.2.11", flightRoot))
	if _, _, _, err := f.l.Reserve(flight, admission.LaneGeneral, ledgerT0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	f.failNext("inventory")
	if err := f.l.RefreshInventory(admission.InventoryObservation{Accounts: []string{"bob"}}); err == nil {
		t.Fatal("injected failure did not fail the refresh")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed refresh changed records")
	}
	f.refresh([]string{"bob"}, nil)
	got, _ := f.l.Candidate(queued)
	if got.State != admission.StateRefused || got.Reason != admission.ReasonStaleIdentity {
		t.Fatalf("queued candidate of a retired account = %+v", got)
	}
	if _, err := f.entry(queued); !isCorrupt(err) || f.count(ended(admission.ReasonStaleIdentity, sshHigh)) != 1 {
		t.Fatalf("ended candidate kept its entry or was not counted: %v", err)
	}
	if got, _ = f.l.Candidate(flight); got.State != admission.StateReserved {
		t.Fatalf("in-flight candidate = %+v", got)
	}
}

// The queue index and the candidates agree: a live candidate without an
// entry, or an entry of an ended candidate, is a damaged ledger that
// refuses mutation.
func TestAdmissionLedgerQueueIndexIsConsistent(t *testing.T) {
	for _, op := range []string{"reserve", "defer", "terminate", "coalesce", "finish"} {
		t.Run(op, func(t *testing.T) {
			f := newLedgerFixture(t)
			root := f.published(evidenceSpec{})
			req := f.request("192.0.2.10", root)
			_, id := f.enqueue(req)
			var action admission.ActionID
			if op == "finish" {
				_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, ledgerT0.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				action = a.Attempt.ID
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(admissionQueueBucket)).Delete([]byte(id))
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			var err error
			switch op {
			case "reserve":
				_, _, _, err = f.l.Reserve(id, admission.LaneGeneral, ledgerT0.Add(time.Hour))
			case "defer":
				_, err = f.l.Defer(id, admission.ReasonCeiling)
			case "terminate":
				_, err = f.l.Terminate(id, admission.ReasonProtected)
			case "coalesce":
				req.Support = []admission.EvidenceID{f.published(evidenceSpec{cursor: "offset=2"})}
				before = f.snapshot()
				_, _, err = f.l.Enqueue(req)
			case "finish":
				_, _, err = f.l.Finish(action, admission.DispositionApplied)
			}
			if !isCorrupt(err) {
				t.Fatalf("missing entry: err = %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("refused call changed records")
			}
		})
	}
	f := newLedgerFixture(t)
	id := f.queued()
	if _, err := f.l.Terminate(id, admission.ReasonProtected); err != nil {
		t.Fatal(err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return putQueueEntry(tx, id, admission.QueueEntry{Partition: admission.PartitionGeneral})
	}); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	other := f.published(evidenceSpec{target: "192.0.2.11", cursor: "other"})
	if _, _, err := f.l.Enqueue(f.request("192.0.2.11", other)); !isCorrupt(err) {
		t.Fatalf("entry of an ended candidate: %v", err)
	}
}

// Revalidation after a policy change ends the queued candidates whose roots
// fall below the new policy; the others keep their positions.
func TestAdmissionLedgerRevalidateAfterPolicyChange(t *testing.T) {
	f, raise := newFloorLedger(t)
	high := f.queued()
	f.nextGeneration()
	critical := f.published(evidenceSpec{target: "192.0.2.11", cursor: "critical", severity: admission.SeverityCritical})
	_, kept := f.enqueue(f.request("192.0.2.11", critical))
	raise(admission.SeverityCritical)
	before := f.snapshot()
	f.failNext("revalidate")
	if err := f.l.Revalidate(); err == nil {
		t.Fatal("injected failure did not fail the revalidation")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed revalidation changed records")
	}
	if err := f.l.Revalidate(); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.l.Candidate(high); got.State != admission.StateRefused || got.Reason != admission.ReasonPolicy {
		t.Fatalf("candidate below the new floor = %+v", got)
	}
	if got, _ := f.l.Candidate(kept); got.State != admission.StateQueued {
		t.Fatalf("candidate above the new floor = %+v", got)
	}
	if n := f.count(ended(admission.ReasonPolicy, sshHigh)); n != 1 {
		t.Fatalf("policy endings counted = %d", n)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	wantLedgerReason(t, "revalidate without a current reading", reopened.Revalidate(), admission.ReasonEngineUnavailable)
	// Evidence is never removed: a queued candidate whose root is gone is
	// a damaged ledger, not a refusal.
	root, _ := f.l.Candidate(kept)
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionEvidenceBucket)).Delete([]byte(root.Roots[0]))
	}); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	if err = f.l.Revalidate(); !isCorrupt(err) {
		t.Fatalf("missing root: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused revalidation changed records")
	}
}

// After an upgrade, revalidation assesses and places every candidate the
// upgrade could only mark: an eligible one takes a reserved position.
func TestAdmissionLedgerRevalidatePlacesUpgradedCandidates(t *testing.T) {
	f := newLedgerFixture(t)
	local := f.published(evidenceSpec{})
	support := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "pass=1"})
	_, corroborated := f.enqueue(f.request("192.0.2.10", local, support))
	f.nextGeneration()
	plain := f.queued()
	f.schemaOne()
	db := f.copyDatabase()
	l, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.db, f.l = db, l
	f.tickAt(f.wall)
	if err = f.l.Revalidate(); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[admission.CandidateID]admission.Partition{corroborated: admission.PartitionReserved, plain: admission.PartitionGeneral} {
		if e, err := f.entry(id); err != nil || !e.Assessed() || e.Partition != want {
			t.Fatalf("upgraded candidate entry = %+v, %v; want %s", e, err, want)
		}
	}
	if next := f.queueState().NextSweep; next.IsZero() {
		t.Fatal("revalidation left no sweep deadline")
	}
}

// An entry under a key that names no candidate is damage, whatever the
// key's shape.
func TestAdmissionLedgerQueueEntryKeysAreCandidates(t *testing.T) {
	for _, key := range []string{"cand_ffffffffffffffffffffffffffffffff", "not-a-candidate"} {
		f := newLedgerFixture(t)
		f.queued()
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueBucket)).Put([]byte(key), mustEntry(t))
		}); err != nil {
			t.Fatal(err)
		}
		f.nextGeneration()
		other := f.published(evidenceSpec{target: "192.0.2.11", cursor: "other"})
		if _, _, err := f.l.Enqueue(f.request("192.0.2.11", other)); !isCorrupt(err) {
			t.Fatalf("%s: err = %v, want a corrupt record", key, err)
		}
	}
}

func mustEntry(t *testing.T) []byte {
	t.Helper()
	data, err := admission.QueueEntry{Partition: admission.PartitionGeneral}.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A sweep must release expired work before it decides whether a candidate
// that lost reserved eligibility fits in the general partition.
func TestAdmissionLedgerSweepReleasesBeforePlacement(t *testing.T) {
	f := newLedgerFixture(t)
	alice := f.owner("alice")
	local := f.published(evidenceSpec{owner: alice})
	support := f.published(evidenceSpec{producer: f.rep, check: "reputation", owner: alice, cursor: "support", age: 23 * time.Hour})
	_, id := f.enqueue(f.request("192.0.2.10", local, support))
	f.tickAt(ledgerT0.Add(time.Second))
	expired := f.fill(admission.PartitionGeneral.DurableCapacity(), evidenceSpec{owner: alice, severity: admission.SeverityCritical, age: 90 * time.Minute})
	f.tickAt(ledgerT0.Add(time.Hour))
	before := f.snapshot()
	f.failNext("revalidate")
	if err := f.l.Revalidate(); err == nil {
		t.Fatal("injected failure did not abort revalidation")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed sweep changed records")
	}
	if err := f.l.Revalidate(); err != nil {
		t.Fatal(err)
	}
	c, err := f.l.Candidate(id)
	e, entryErr := f.entry(id)
	if err != nil || entryErr != nil || c.State != admission.StateQueued || e.Partition != admission.PartitionGeneral || e.Tier != sshHigh {
		t.Fatalf("valid candidate lost to expired occupancy: %+v %+v %v %v", c, e, err, entryErr)
	}
	for _, old := range expired {
		c, err := f.l.Candidate(old)
		if err != nil || c.Reason != admission.ReasonStale {
			t.Fatalf("expired candidate: %+v %v", c, err)
		}
	}
	critical := admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityCritical}
	if n := f.count(ended(admission.ReasonStale, critical)); n != uint64(len(expired)) {
		t.Fatalf("stale count = %d", n)
	}
	if n := f.count(ended(admission.ReasonQueueOverflow, sshHigh)); n != 0 {
		t.Fatalf("spurious overflow count = %d", n)
	}
}

// A newer general candidate can lose severity before an older reserved
// candidate needs its position. Victim selection must use both new tiers.
func TestAdmissionLedgerSweepRefreshesVictimTiers(t *testing.T) {
	f := newLedgerFixture(t)
	alice := f.owner("alice")
	local := f.published(evidenceSpec{owner: alice})
	support := f.published(evidenceSpec{producer: f.rep, check: "reputation", owner: alice, cursor: "support", age: 23 * time.Hour})
	_, older := f.enqueue(f.request("192.0.2.10", local, support))
	f.tickAt(ledgerT0.Add(time.Second))
	general := f.fill(admission.PartitionGeneral.DurableCapacity()-1, evidenceSpec{owner: alice, severity: admission.SeverityCritical})
	high := f.published(evidenceSpec{owner: alice, target: "192.0.2.11", cursor: "high"})
	critical := f.published(evidenceSpec{owner: alice, target: "192.0.2.11", cursor: "critical", severity: admission.SeverityCritical, age: 90 * time.Minute})
	_, victim := f.enqueue(f.request("192.0.2.11", high, critical))
	f.tickAt(ledgerT0.Add(time.Hour))
	if err := f.l.Revalidate(); err != nil {
		t.Fatal(err)
	}
	if c, err := f.l.Candidate(older); err != nil || c.State != admission.StateQueued {
		t.Fatalf("older equal-tier candidate: %+v %v", c, err)
	}
	if c, err := f.l.Candidate(victim); err != nil || c.Reason != admission.ReasonQueueOverflow {
		t.Fatalf("newer lower-tier victim: %+v %v", c, err)
	}
	for _, id := range general {
		if c, err := f.l.Candidate(id); err != nil || c.State != admission.StateQueued {
			t.Fatalf("higher-tier candidate: %+v %v", c, err)
		}
	}
	if n := f.count(ended(admission.ReasonQueueOverflow, sshHigh)); n != 1 {
		t.Fatalf("overflow count = %d", n)
	}
}

// Maintenance observes the same predecessor-chain invariant as explicit
// candidate transitions, including when a retry's expiry has passed.
func TestAdmissionLedgerMaintenanceRejectsBrokenHistory(t *testing.T) {
	for _, op := range []string{"revalidate", "sweep", "inventory"} {
		t.Run(op, func(t *testing.T) {
			f := newLedgerFixture(t)
			root := f.published(evidenceSpec{owner: f.owner("alice")})
			_, id := f.enqueue(f.request("192.0.2.10", root))
			_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, ledgerT0.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			_, a, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
			if err != nil {
				t.Fatal(err)
			}
			a.State, a.Disposition = admission.StateUnknown, admission.DispositionUnknown
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putAttempt(tx, a) }); err != nil {
				t.Fatal(err)
			}
			f.tickAt(ledgerT0.Add(time.Minute))
			next := f.published(evidenceSpec{target: "192.0.2.11", cursor: "next"})
			before := f.snapshot()
			switch op {
			case "revalidate":
				err = f.l.Revalidate()
			case "sweep":
				_, _, err = f.l.Enqueue(f.request("192.0.2.11", next))
			case "inventory":
				err = f.l.RefreshInventory(admission.InventoryObservation{Accounts: []string{"bob"}})
			}
			if !isCorrupt(err) {
				t.Fatalf("maintenance accepted broken history: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("damaged history changed records")
			}
			if got := f.l.Inventory().Resolve(admission.Claim{Kind: admission.ClaimAccount, Value: "alice"}); got.IsHost() {
				t.Fatal("failed maintenance published inventory")
			}
		})
	}
}

// Executing an attempt still requires its durable position. The grant must
// not authorize work that is invisible to queue capacity.
func TestAdmissionLedgerExecuteRequiresQueueEntry(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(admissionQueueBucket)).Delete([]byte(id)) }); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	_, _, granted, err := f.l.Execute(a.Attempt.ID)
	if !isCorrupt(err) || granted {
		t.Fatalf("execute without a position: granted %v, %v", granted, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("refused execution changed records")
	}
}

// Missing evidence is corruption even when time has also expired. A sweep
// must not erase the candidate and disguise damage as an ordinary age-out.
func TestAdmissionLedgerExpiredCandidateRequiresRoots(t *testing.T) {
	for _, damage := range []string{"missing", "damaged"} {
		t.Run(damage, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			c, err := f.l.Candidate(id)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(admissionEvidenceBucket))
				if damage == "missing" {
					return b.Delete([]byte(c.Roots[0]))
				}
				raw := append([]byte(nil), b.Get([]byte(c.Roots[0]))...)
				raw[5] ^= 1
				return b.Put([]byte(c.Roots[0]), raw)
			}); err != nil {
				t.Fatal(err)
			}
			f.tickAt(c.AgeOut)
			before := f.snapshot()
			if err = f.l.Revalidate(); !isCorrupt(err) {
				t.Fatalf("expired candidate hid %s evidence: %v", damage, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("damaged candidate was changed")
			}
		})
	}
}

// Coalescing can also move a candidate out of reserve. The merged roots
// must be assessed alongside other due work before choosing its position.
func TestAdmissionLedgerCoalescingSweepsBeforePlacement(t *testing.T) {
	f := newLedgerFixture(t)
	alice := f.owner("alice")
	local := f.published(evidenceSpec{owner: alice})
	support := f.published(evidenceSpec{producer: f.rep, check: "reputation", owner: alice, cursor: "support", age: 23 * time.Hour})
	original, id := f.enqueue(f.request("192.0.2.10", local, support))
	f.tickAt(ledgerT0.Add(time.Second))
	f.fill(admission.PartitionGeneral.DurableCapacity(), evidenceSpec{owner: alice, severity: admission.SeverityCritical, age: 90 * time.Minute})
	f.tickAt(ledgerT0.Add(time.Hour))
	fresh := f.published(evidenceSpec{owner: alice, cursor: "fresh"})
	req := f.request("192.0.2.10", fresh)
	before := f.snapshot()
	f.failNext("enqueue")
	if _, _, err := f.l.Enqueue(req); err == nil {
		t.Fatal("injected failure did not abort coalescing")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed coalescing changed records")
	}
	c, created, err := f.l.Enqueue(req)
	e, entryErr := f.entry(id)
	if err != nil || entryErr != nil || created || c.State != admission.StateQueued || e.Partition != admission.PartitionGeneral || e.Tier != sshHigh {
		t.Fatalf("coalesced candidate lost to expired occupancy: %+v %+v %v %v", c, e, err, entryErr)
	}
	if c.Transitions != original.Transitions+1 || len(c.Roots) != 3 || c.AgeOut != original.AgeOut || c.FirstQueued != original.FirstQueued {
		t.Fatalf("coalescing changed history: %+v", c)
	}
	if n := f.count(ended(admission.ReasonQueueOverflow, sshHigh)); n != 0 {
		t.Fatalf("spurious overflow count = %d", n)
	}
}

// New support must be visible to victim selection in the same sweep. The
// promoted candidate cannot be displaced using its previous general tier.
func TestAdmissionLedgerCoalescingAssessesBeforeDisplacement(t *testing.T) {
	f := newLedgerFixture(t)
	alice := f.owner("alice")
	local := f.published(evidenceSpec{owner: alice})
	support := f.published(evidenceSpec{producer: f.rep, check: "reputation", owner: alice, cursor: "support", age: 23 * time.Hour})
	_, demoting := f.enqueue(f.request("192.0.2.10", local, support))
	f.tickAt(ledgerT0.Add(time.Second))
	f.fill(admission.PartitionGeneral.DurableCapacity()-1, evidenceSpec{owner: alice, severity: admission.SeverityCritical})
	root := f.published(evidenceSpec{owner: alice, target: "192.0.2.11", cursor: "root"})
	_, promoting := f.enqueue(f.request("192.0.2.11", root))
	f.tickAt(ledgerT0.Add(time.Hour))
	fresh := f.published(evidenceSpec{producer: f.rep, check: "reputation", owner: alice, target: "192.0.2.11", cursor: "fresh"})
	c, created, err := f.l.Enqueue(f.request("192.0.2.11", root, fresh))
	if err != nil || created || c.State != admission.StateQueued {
		t.Fatalf("promoting candidate displaced: %+v %v", c, err)
	}
	for id, partition := range map[admission.CandidateID]admission.Partition{demoting: admission.PartitionGeneral, promoting: admission.PartitionReserved} {
		e, err := f.entry(id)
		if err != nil || e.Partition != partition {
			t.Fatalf("candidate %s: entry %+v, %v; want %s", id, e, err, partition)
		}
	}
	if n := f.count(ended(admission.ReasonQueueOverflow, sshHigh)); n != 0 {
		t.Fatalf("unnecessary displacement count = %d", n)
	}
}
