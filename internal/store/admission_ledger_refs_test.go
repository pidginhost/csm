package store

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) storageState() admission.StorageState {
	f.t.Helper()
	s, err := f.l.Storage()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// Published evidence waits in the loose ring until a candidate names it.
// Each candidate that names it adds a reference, and a named record leaves
// the ring.
func TestAdmissionLedgerEvidenceReferences(t *testing.T) {
	f := newLedgerFixture(t)
	root := f.published(evidenceSpec{})
	if r, found := refsIn(t, f.db, root); !found || r != (admission.EvidenceRefs{Loose: 1}) {
		t.Fatalf("published evidence refs = %+v (found %t)", r, found)
	}
	if s := f.storageState(); s.Loose != (admission.RingState{Count: 1, Last: 1}) {
		t.Fatalf("loose ring = %+v", s.Loose)
	}
	again := f.published(evidenceSpec{})
	if again != root || f.storageState().Loose != (admission.RingState{Count: 1, Last: 1}) {
		t.Fatal("publishing the same record again took another position")
	}
	_, id := f.enqueue(f.request("192.0.2.10", root))
	if r, _ := refsIn(t, f.db, root); r != (admission.EvidenceRefs{Refs: 1}) {
		t.Fatalf("named evidence refs = %+v", r)
	}
	if s := f.storageState(); s.Loose != (admission.RingState{Count: 0, Last: 1}) || len(ringIn(t, f.db, ringLoose)) != 0 {
		t.Fatalf("named evidence stayed in the loose ring: %+v", s.Loose)
	}
	support := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "intel"})
	if _, created, err := f.l.Enqueue(f.request("192.0.2.10", root, support)); err != nil || created {
		t.Fatalf("coalesce: %v %v", created, err)
	}
	if c, _ := f.l.Candidate(id); len(c.Roots) != 2 {
		t.Fatalf("coalesced roots = %v", c.Roots)
	}
	if r, _ := refsIn(t, f.db, support); r != (admission.EvidenceRefs{Refs: 1}) {
		t.Fatalf("coalesced root refs = %+v", r)
	}
	f.nextGeneration()
	f.enqueue(f.request("192.0.2.10", root))
	if r, _ := refsIn(t, f.db, root); r != (admission.EvidenceRefs{Refs: 2}) {
		t.Fatalf("a second candidate's root refs = %+v", r)
	}
	// Coalescing roots a candidate already holds adds no reference.
	if _, _, err := f.l.Enqueue(f.request("192.0.2.10", root)); err != nil {
		t.Fatal(err)
	}
	if r, _ := refsIn(t, f.db, root); r != (admission.EvidenceRefs{Refs: 2}) {
		t.Fatalf("a repeated request counted again: %+v", r)
	}
}

// publishLoose publishes n records aimed at 192.0.2.12 in one transaction,
// oldest first, then names the first of them in a new candidate, before the
// transaction ends.
func (f *ledgerFixture) publishLoose(n int, nameFirst bool) []admission.EvidenceID {
	f.t.Helper()
	var ids []admission.EvidenceID
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	if err := f.l.update("fill", func(tx *bolt.Tx) error {
		q, err := f.l.openQueue(tx, f.l.now)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			e := f.mint(evidenceSpec{target: "192.0.2.12", cursor: fmt.Sprintf("loose=%d", i)})
			if _, err = publishTx(q, f.reg, e); err != nil {
				return err
			}
			ids = append(ids, e.ID())
		}
		if nameFirst {
			req := f.request("192.0.2.12", ids[0])
			key := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: req.Episode, Generation: req.Generation}
			id, err := key.ID()
			if err != nil {
				return err
			}
			if _, _, err = f.l.enqueueTx(q, req, key, id, []admission.EvidenceID{ids[0]}); err != nil {
				return err
			}
		}
		return q.flush()
	}); err != nil {
		f.t.Fatal(err)
	}
	return ids
}

// The loose ring keeps its newest records. The oldest leave with their
// report links when the transaction ends, so a record named later in the
// same transaction is kept.
func TestAdmissionLedgerLooseRingKeepsTheNewest(t *testing.T) {
	f := newLedgerFixture(t)
	first := f.published(evidenceSpec{target: "192.0.2.12", cursor: "first"})
	if err := f.l.LinkReport(first, "fedcba9876543210"); err != nil {
		t.Fatal(err)
	}
	ids := f.publishLoose(admission.MaxLooseEvidence+2, true)
	s := f.storageState()
	if s.Loose.Count != admission.MaxLooseEvidence || s.Loose.Last != admission.MaxLooseEvidence+3 {
		t.Fatalf("loose ring = %+v", s.Loose)
	}
	// The earlier record and the second of the batch were the oldest loose
	// records; the first of the batch was named before the end.
	for _, gone := range []admission.EvidenceID{first, ids[1]} {
		if _, err := f.l.LoadEvidence(gone); err != admission.ErrEvidenceUnpublished {
			t.Errorf("%s: %v", gone, err)
		}
		if _, found := refsIn(t, f.db, gone); found {
			t.Errorf("%s kept its reference count", gone)
		}
	}
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(admissionReportsBucket)).Get([]byte(first)) != nil {
			t.Error("evicted evidence kept its report links")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r, _ := refsIn(t, f.db, ids[0]); r != (admission.EvidenceRefs{Refs: 1}) {
		t.Fatalf("named record refs = %+v", r)
	}
	ring := ringIn(t, f.db, ringLoose)
	if len(ring) != admission.MaxLooseEvidence || ring[4] != string(ids[2]) || ring[admission.MaxLooseEvidence+3] != string(ids[len(ids)-1]) {
		t.Fatalf("loose ring holds %d records, oldest %s", len(ring), ring[4])
	}
	for pos, id := range ring {
		if r, _ := refsIn(t, f.db, admission.EvidenceID(id)); r != (admission.EvidenceRefs{Loose: pos}) {
			t.Fatalf("%s at %d has refs %+v", id, pos, r)
		}
	}
}

// Evidence whose arrival is refused waits in the loose ring: rejected
// traffic takes a bounded position, not a row of its own forever.
func TestAdmissionLedgerRefusedArrivalLeavesLooseEvidence(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	a := f.arrival(evidenceSpec{cursor: "refused"})
	a.Request.Primary = f.published(evidenceSpec{cursor: "other"})
	results, _, err := f.l.EnqueueGroup([]admission.Arrival{a}, nil)
	if err != nil || len(results) != 1 {
		t.Fatalf("group: %v %v", results, err)
	}
	wantLedgerReason(t, "request naming other evidence", results[0].Err, admission.ReasonInvalid)
	if r, found := refsIn(t, f.db, a.Evidence.ID()); !found || r.Loose == 0 {
		t.Fatalf("refused arrival's evidence refs = %+v (found %t)", r, found)
	}
}

// Report links are metadata about stored evidence. A later policy raise
// refuses the evidence as a root but leaves its links readable and
// linkable.
func TestAdmissionLedgerReportsSurviveAPolicyRaise(t *testing.T) {
	f, raise := newFloorLedger(t)
	id := f.published(evidenceSpec{})
	if err := f.l.LinkReport(id, "fedcba9876543210"); err != nil {
		t.Fatal(err)
	}
	raise(admission.SeverityCritical)
	if _, err := f.l.LoadEvidence(id); err == nil {
		t.Fatal("evidence below the new floor still loads as a root")
	}
	if err := f.l.LinkReport(id, "fedcba9876543211"); err != nil {
		t.Fatalf("link after a policy raise: %v", err)
	}
	links, dropped, err := f.l.Reports(id)
	if err != nil || dropped != 0 || !reflect.DeepEqual(links, []string{"fedcba9876543210", "fedcba9876543211"}) {
		t.Fatalf("reports after a policy raise: %v %d %v", links, dropped, err)
	}
	if _, _, err = f.l.Reports("ev_ffffffffffffffffffffffffffffffff"); err != admission.ErrEvidenceUnpublished {
		t.Fatalf("reports of unknown evidence: %v", err)
	}
}

// Damaged reference bookkeeping refuses the change and leaves the ledger
// as it was.
func TestAdmissionLedgerRefusesDamagedReferences(t *testing.T) {
	for name, damage := range map[string]func(tx *bolt.Tx, root admission.EvidenceID) error{
		"missing count": func(tx *bolt.Tx, root admission.EvidenceID) error {
			return tx.Bucket([]byte(admissionRefsBucket)).Delete([]byte(root))
		},
		"damaged count": func(tx *bolt.Tx, root admission.EvidenceID) error {
			return tx.Bucket([]byte(admissionRefsBucket)).Put([]byte(root), []byte("damaged"))
		},
		"ring position of other evidence": func(tx *bolt.Tx, _ admission.EvidenceID) error {
			return tx.Bucket([]byte(admissionRingsBucket)).Put(ringKey(ringLoose, 1), []byte("ev_ffffffffffffffffffffffffffffffff"))
		},
		"missing ring position": func(tx *bolt.Tx, _ admission.EvidenceID) error {
			return tx.Bucket([]byte(admissionRingsBucket)).Delete(ringKey(ringLoose, 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			root := f.published(evidenceSpec{})
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(tx, root) }); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, _, err := f.l.Enqueue(f.request("192.0.2.10", root)); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("a refused enqueue changed the ledger")
			}
		})
	}
}
