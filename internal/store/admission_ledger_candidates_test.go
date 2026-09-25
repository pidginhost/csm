package store

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) candidateCount() (n int) {
	_ = f.db.bolt.View(func(tx *bolt.Tx) error {
		n = tx.Bucket([]byte(admissionCandidatesBucket)).Stats().KeyN
		return nil
	})
	return n
}

// A queued candidate takes its entry, check and finding link from its
// primary root, and ages out at the earlier of two hours or the moment its
// last fresh root goes stale.
func TestAdmissionLedgerEnqueueBuildsFromEvidence(t *testing.T) {
	f := newLedgerFixture(t)
	primary := f.published(evidenceSpec{age: 90 * time.Minute, finding: "00000000000000aa"})
	c, created, err := f.l.Enqueue(f.request("192.0.2.10", primary))
	if err != nil || !created {
		t.Fatalf("enqueue: %v, %v", created, err)
	}
	if c.Entry != admission.EntryScan || c.Check != "ssh_brute" || c.FindingID != "00000000000000aa" {
		t.Fatalf("candidate fields = %+v", c)
	}
	if !c.FirstQueued.Equal(ledgerT0) || !c.AgeOut.Equal(ledgerT0.Add(30*time.Minute)) {
		t.Fatalf("queue times = %v, %v", c.FirstQueued, c.AgeOut)
	}
	fresh := f.published(evidenceSpec{cursor: "offset=2", target: "192.0.2.11"})
	c2, _ := f.enqueue(f.request("192.0.2.11", fresh))
	if !c2.AgeOut.Equal(ledgerT0.Add(admission.QueueAgeLimit)) {
		t.Fatalf("fresh root age-out = %v", c2.AgeOut)
	}
	id, _ := c.ID()
	if got, err := f.l.Candidate(id); err != nil || got.Transitions != 1 || got.State != admission.StateQueued {
		t.Fatalf("stored candidate = %+v, %v", got, err)
	}
}

func TestAdmissionLedgerEnqueueRefusals(t *testing.T) {
	f := newLedgerFixture(t)
	stale := f.published(evidenceSpec{age: 3 * time.Hour})
	_, _, err := f.l.Enqueue(f.request("192.0.2.10", stale))
	wantLedgerReason(t, "stale root", err, admission.ReasonStale)
	_, _, err = f.l.Enqueue(f.request("192.0.2.10", "ev_00000000000000000000000000000001"))
	wantLedgerReason(t, "unpublished root", err, admission.ReasonInvalid)
	other := f.published(evidenceSpec{target: "198.51.100.7", cursor: "offset=9"})
	_, _, err = f.l.Enqueue(f.request("192.0.2.10", other))
	wantLedgerReason(t, "root for another target", err, admission.ReasonInvalid)
	var many []admission.EvidenceID
	for i := 0; i <= admission.MaxRoots; i++ {
		many = append(many, f.published(evidenceSpec{cursor: "offset=" + string(rune('a'+i))}))
	}
	_, _, err = f.l.Enqueue(f.request("192.0.2.10", many[0], many[1:]...))
	wantLedgerReason(t, "too many roots", err, admission.ReasonInvalid)
	// An oversized request is refused before any record is read, so a
	// request carrying thousands of IDs cannot make one call read them all.
	var unread []admission.EvidenceID
	for i := 0; i <= admission.MaxRoots; i++ {
		unread = append(unread, admission.EvidenceID(fmt.Sprintf("ev_%032x", i+1)))
	}
	_, _, err = f.l.Enqueue(f.request("192.0.2.10", unread[0], unread[1:]...))
	var refused *admission.Error
	if !errors.As(err, &refused) || refused.Detail != "candidate has too many roots" {
		t.Errorf("oversized request reached storage: %v", err)
	}
	if n := f.candidateCount(); n != 0 {
		t.Fatalf("refused requests stored %d candidates", n)
	}
}

// A repeated request coalesces into the queued candidate. It never refreshes
// queue age or the age-out, even after time has passed.
func TestAdmissionLedgerEnqueueCoalescesWithoutRefreshing(t *testing.T) {
	f := newLedgerFixture(t)
	primary := f.published(evidenceSpec{})
	first, _ := f.enqueue(f.request("192.0.2.10", primary))
	f.tickAt(ledgerT0.Add(20 * time.Minute))
	same, created, err := f.l.Enqueue(f.request("192.0.2.10", primary))
	if err != nil || created || same.Transitions != first.Transitions {
		t.Fatalf("repeat: created %v transitions %d, %v", created, same.Transitions, err)
	}
	support := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "pass=2"})
	merged, created, err := f.l.Enqueue(f.request("192.0.2.10", primary, support))
	if err != nil || created {
		t.Fatalf("coalesce: %v, %v", created, err)
	}
	if !slices.Contains(merged.Roots, support) || len(merged.Roots) != 2 || merged.Transitions != first.Transitions+1 {
		t.Fatalf("coalesced roots = %v, transitions %d", merged.Roots, merged.Transitions)
	}
	if !merged.FirstQueued.Equal(first.FirstQueued) || !merged.AgeOut.Equal(first.AgeOut) {
		t.Fatal("coalescing refreshed queue age or age-out")
	}
}

// The fairness scope is an account only when every root names that account
// and it is current; mixed or unknown ownership uses the host scope,
// and an account that has changed generation refuses.
func TestAdmissionLedgerEnqueueScope(t *testing.T) {
	f := newLedgerFixture(t)
	alice, bob := f.owner("alice"), f.owner("bob")
	a := f.published(evidenceSpec{owner: alice, cursor: "offset=1"})
	rep := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "pass=1", owner: alice})
	c, _ := f.enqueue(f.request("192.0.2.10", a, rep))
	if c.Scope.Owner != alice || c.Scope.Effect != admission.EffectAddress {
		t.Fatalf("alice scope = %s", c.Scope.Key())
	}
	b := f.published(evidenceSpec{owner: bob, target: "192.0.2.20", cursor: "offset=2"})
	a2 := f.published(evidenceSpec{owner: alice, target: "192.0.2.20", cursor: "offset=3"})
	c2, _ := f.enqueue(f.request("192.0.2.20", b, a2))
	if !c2.Scope.Owner.IsHost() {
		t.Fatalf("two accounts scope = %s", c2.Scope.Key())
	}
	f.refresh([]string{"bob"}, nil)
	f.refresh([]string{"alice", "bob"}, nil)
	stale := f.published(evidenceSpec{owner: alice, target: "192.0.2.30", cursor: "offset=4"})
	_, _, err := f.l.Enqueue(f.request("192.0.2.30", stale))
	wantLedgerReason(t, "recreated account", err, admission.ReasonStaleIdentity)
}

func TestAdmissionLedgerEnqueueIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	primary := f.published(evidenceSpec{})
	f.failNext("enqueue")
	if _, _, err := f.l.Enqueue(f.request("192.0.2.10", primary)); err == nil {
		t.Fatal("injected failure did not fail the enqueue")
	}
	if n := f.candidateCount(); n != 0 {
		t.Fatalf("failed enqueue stored %d candidates", n)
	}
}

// Roots are revalidated when a candidate is queued: evidence below its
// check's current severity floor cannot queue one.
func TestAdmissionLedgerEnqueueRevalidatesRoots(t *testing.T) {
	f, raise := newFloorLedger(t)
	id := f.published(evidenceSpec{})
	raise(admission.SeverityCritical)
	_, _, err := f.l.Enqueue(f.request("192.0.2.10", id))
	wantLedgerReason(t, "enqueue below the new floor", err, admission.ReasonPolicy)
	if n := f.candidateCount(); n != 0 {
		t.Fatalf("refused request stored %d candidates", n)
	}
}

func TestAdmissionLedgerCoalescingRevalidatesAndRescopes(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.published(evidenceSpec{owner: f.owner("alice")})
	req := f.request("192.0.2.10", a)
	first, id := f.enqueue(req)
	host := f.published(evidenceSpec{cursor: "offset=2"})
	req.Support = []admission.EvidenceID{host}
	before := f.snapshot()
	f.failNext("enqueue")
	if _, _, err := f.l.Enqueue(req); err == nil {
		t.Fatal("merge did not fail")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed merge changed records")
	}
	c, created, err := f.l.Enqueue(req)
	if err != nil || created || !c.Scope.Owner.IsHost() || c.Transitions != first.Transitions+1 || len(c.Roots) != 2 {
		t.Fatalf("coalesced scope: %+v %v", c, err)
	}
	if !c.FirstQueued.Equal(first.FirstQueued) || !c.AgeOut.Equal(first.AgeOut) {
		t.Fatal("merge moved deadlines")
	}
	f.refresh([]string{"bob"}, nil)
	_, _, err = f.l.Enqueue(req)
	wantLedgerReason(t, "duplicate stale owner", err, admission.ReasonStaleIdentity)
	if stored, err := f.l.Candidate(id); err != nil || stored.Transitions != c.Transitions {
		t.Fatalf("refusal changed candidate: %+v %v", stored, err)
	}
}

func TestAdmissionLedgerCoalescingRevalidatesPolicy(t *testing.T) {
	f, raise := newFloorLedger(t)
	root := f.published(evidenceSpec{})
	req := f.request("192.0.2.10", root)
	f.enqueue(req)
	raise(admission.SeverityCritical)
	_, _, err := f.l.Enqueue(req)
	wantLedgerReason(t, "duplicate policy", err, admission.ReasonPolicy)
}

func TestAdmissionLedgerBoundsRawRootRequests(t *testing.T) {
	f := newLedgerFixture(t)
	root := f.published(evidenceSpec{})
	req := f.request("192.0.2.10", root)
	req.Support = make([]admission.EvidenceID, admission.MaxRoots)
	for i := range req.Support {
		req.Support[i] = root
	}
	_, _, err := f.l.Enqueue(req)
	wantLedgerReason(t, "duplicate oversized input", err, admission.ReasonInvalid)
	if f.candidateCount() != 0 {
		t.Fatal("oversized request queued")
	}
}
