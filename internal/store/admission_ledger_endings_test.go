package store

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// endMany queues and ends n candidates in one transaction, each from its
// own fresh root aimed at its own documentation address.
func (f *ledgerFixture) endMany(n int) []admission.CandidateID {
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
			target := fmt.Sprintf("2001:db8::%x", f.fills)
			e := f.mint(evidenceSpec{target: target, cursor: fmt.Sprintf("fill=%d", f.fills)})
			if _, err = publishTx(q, f.reg, e); err != nil {
				return err
			}
			req := f.request(target, e.ID())
			key := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: req.Episode, Generation: req.Generation}
			id, err := key.ID()
			if err != nil {
				return err
			}
			c, _, err := f.l.enqueueTx(q, req, key, id, []admission.EvidenceID{e.ID()})
			if err != nil {
				return err
			}
			entry, err := loadQueueEntry(tx, id)
			if err != nil {
				return err
			}
			if err = q.end(liveCandidate{id: id, c: c, entry: entry}, admission.ReasonProtected); err != nil {
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

// A candidate that ends before any attempt takes the next ended position,
// whichever path ends it, and stays readable while it is kept.
func TestAdmissionLedgerEndingsJoinTheEndedRing(t *testing.T) {
	f := newLedgerFixture(t)
	terminated := f.queued()
	if _, err := f.l.Terminate(terminated, admission.ReasonProtected); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Terminate(terminated, admission.ReasonProtected); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	stale := f.queued()
	f.tickAt(f.wall.Add(admission.QueueAgeLimit))
	if err := f.l.Revalidate(); err != nil {
		t.Fatal(err)
	}
	if c, err := f.l.Candidate(stale); err != nil || c.State != admission.StateDropped {
		t.Fatalf("stale candidate: %+v, %v", c, err)
	}
	want := map[uint64]string{1: string(terminated), 2: string(stale)}
	if got := ringIn(t, f.db, ringEnded); !reflect.DeepEqual(got, want) {
		t.Fatalf("ended ring = %v, want %v", got, want)
	}
	if s := f.storageState(); s.Ended != (admission.RingState{Count: 2, Last: 2}) {
		t.Fatalf("ended ring state = %+v", s.Ended)
	}
	f.generation = 0
	if _, _, err := f.l.Enqueue(f.request("192.0.2.10", f.published(evidenceSpec{cursor: "late"}))); err != admission.ErrCandidateTerminal {
		t.Fatalf("a kept ending was revived: %v", err)
	}
}

// The ended ring keeps its newest candidates. An older one is removed when
// the transaction ends; its root keeps a loose position while it could
// still support a candidate, and is removed once it cannot.
func TestAdmissionLedgerEndedRingKeepsTheNewest(t *testing.T) {
	f := newLedgerFixture(t)
	ids := f.endMany(admission.MaxEndedCandidates)
	if s := f.storageState(); s.Ended.Count != admission.MaxEndedCandidates {
		t.Fatalf("ended ring = %+v", s.Ended)
	}
	first, err := f.l.Candidate(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.l.Candidate(ids[1])
	if err != nil {
		t.Fatal(err)
	}
	f.endMany(1)
	if _, err = f.l.Candidate(ids[0]); err != errCandidateMissing {
		t.Fatalf("oldest ending: %v", err)
	}
	if r, found := refsIn(t, f.db, first.Roots[0]); !found || r.Loose == 0 {
		t.Fatalf("a fresh root of a removed ending = %+v (found %t)", r, found)
	}
	f.tickAt(f.wall.Add(admission.SupportLookback))
	f.endMany(1)
	if _, err = f.l.Candidate(ids[1]); err != errCandidateMissing {
		t.Fatalf("second ending: %v", err)
	}
	if _, err = f.l.LoadEvidence(second.Roots[0]); err != admission.ErrEvidenceUnpublished {
		t.Fatalf("a root too old to support anything: %v", err)
	}
	if _, found := refsIn(t, f.db, second.Roots[0]); found {
		t.Fatal("a removed root kept its reference count")
	}
	if s := f.storageState(); s.Ended != (admission.RingState{Count: admission.MaxEndedCandidates, Last: admission.MaxEndedCandidates + 2}) {
		t.Fatalf("ended ring = %+v", s.Ended)
	}
	if c, err := f.l.Candidate(ids[2]); err != nil || c.State != admission.StateRefused {
		t.Fatalf("third ending: %+v, %v", c, err)
	}
}

// A removed ending releases only its own reference: a root another stored
// candidate names stays named.
func TestAdmissionLedgerRemovedEndingKeepsASharedRoot(t *testing.T) {
	f := newLedgerFixture(t)
	ids := f.endMany(admission.MaxEndedCandidates)
	first, err := f.l.Candidate(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	ep, err := admission.ParseEpisodeID("00000000000000000000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Enqueue(admission.CandidateRequest{Kind: admission.KindBlockIP, Target: first.Key.Target, Episode: ep, Generation: 1, Primary: first.Roots[0]}); err != nil {
		t.Fatal(err)
	}
	f.endMany(1)
	if _, err = f.l.Candidate(ids[0]); err != errCandidateMissing {
		t.Fatalf("oldest ending: %v", err)
	}
	if r, found := refsIn(t, f.db, first.Roots[0]); !found || r != (admission.EvidenceRefs{Refs: 1}) {
		t.Fatalf("a root another candidate names = %+v (found %t)", r, found)
	}
}

// An ended position must name a candidate that ended before any attempt.
func TestAdmissionLedgerRefusesDamagedEndings(t *testing.T) {
	for name, damage := range map[string]func(tx *bolt.Tx, oldest admission.CandidateID, live admission.CandidateID) error{
		"missing candidate": func(tx *bolt.Tx, oldest, _ admission.CandidateID) error {
			return tx.Bucket([]byte(admissionCandidatesBucket)).Delete([]byte(oldest))
		},
		"live candidate": func(tx *bolt.Tx, _, live admission.CandidateID) error {
			return tx.Bucket([]byte(admissionRingsBucket)).Put(ringKey(ringEnded, 1), []byte(live))
		},
		"damaged root count": func(tx *bolt.Tx, oldest, _ admission.CandidateID) error {
			c, err := loadCandidate(tx, oldest)
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionRefsBucket)).Put([]byte(c.Roots[0]), []byte("damaged"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			ids := f.endMany(admission.MaxEndedCandidates)
			live := f.queued()
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(tx, ids[0], live) }); err != nil {
				t.Fatal(err)
			}
			f.nextGeneration()
			id := f.queued()
			before := f.snapshot()
			_, err := f.l.Terminate(id, admission.ReasonProtected)
			if !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("a refused ending changed the ledger")
			}
		})
	}
}

// The ended ring's removals are part of the transaction that ends a
// candidate: a failure leaves every record as it was.
func TestAdmissionLedgerEndedRingRollsBack(t *testing.T) {
	f := newLedgerFixture(t)
	f.endMany(admission.MaxEndedCandidates)
	id := f.queued()
	before := f.snapshot()
	f.failNext("terminate")
	if _, err := f.l.Terminate(id, admission.ReasonProtected); err == nil {
		t.Fatal("injected failure did not abort the ending")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed ending changed the ledger")
	}
}
