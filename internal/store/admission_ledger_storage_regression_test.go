package store

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Migration must release a pruned ending's last reference just as eviction
// does: expired roots and their reports go, recent and shared roots stay.
func TestAdmissionLedgerUpgradePrunesExpiredRoots(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			f := newLedgerFixture(t)
			expired := f.published(evidenceSpec{cursor: "expired"})
			shared := f.published(evidenceSpec{cursor: "shared"})
			_, oldID := f.enqueue(f.request("192.0.2.10", expired))
			old, err := f.l.Terminate(oldID, admission.ReasonProtected)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.l.LinkReport(expired, "fedcba9876543210"); err != nil {
				t.Fatal(err)
			}
			f.tickAt(f.wall.Add(time.Nanosecond))
			recent := f.published(evidenceSpec{cursor: "recent"})
			f.tickAt(old.FirstQueued.Add(admission.SupportLookback))
			switch schema {
			case 1:
				f.schemaOne()
			case 2:
				f.schemaTwo()
			case 3:
				f.schemaThree()
			}
			var recentID admission.CandidateID
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				for i := 1; i <= admission.MaxEndedCandidates+2; i++ {
					c := old
					c.Key.Generation += uint32(i)
					c.FirstQueued = c.FirstQueued.Add(time.Duration(i) * time.Nanosecond)
					c.AgeOut = c.FirstQueued.Add(admission.QueueAgeLimit)
					c.Roots = []admission.EvidenceID{shared}
					if i == 1 {
						c.Roots = []admission.EvidenceID{recent}
						recentID, _ = c.ID()
					}
					if putErr := putCandidate(tx, c); putErr != nil {
						return putErr
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			l, err := OpenAdmissionLedger(f.db, f.reg)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []admission.CandidateID{oldID, recentID} {
				if _, err = l.Candidate(id); err != errCandidateMissing {
					t.Errorf("pruned candidate still present: %v", err)
				}
			}
			if _, err = l.LoadEvidence(expired); err != admission.ErrEvidenceUnpublished {
				t.Errorf("expired unshared root was retained: %v", err)
			}
			if r, found := refsIn(t, f.db, expired); found {
				t.Errorf("expired root kept references: %+v", r)
			}
			if err = f.db.bolt.View(func(tx *bolt.Tx) error {
				if tx.Bucket([]byte(admissionReportsBucket)).Get([]byte(expired)) != nil {
					t.Error("expired root kept its reports")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if r, found := refsIn(t, f.db, recent); !found || r != (admission.EvidenceRefs{Loose: 1}) {
				t.Errorf("recent root lost its loose position: %+v, %t", r, found)
			}
			if r, found := refsIn(t, f.db, shared); !found || r != (admission.EvidenceRefs{Refs: admission.MaxEndedCandidates}) {
				t.Errorf("shared root lost references: %+v, %t", r, found)
			}
			s, err := l.Storage()
			if err != nil || s.Loose != (admission.RingState{Count: 1, Last: 1}) {
				t.Errorf("loose ring after upgrade: %+v, %v", s.Loose, err)
			}
		})
	}
}

// Publishing cannot turn an existing reference into a new loose record or
// acknowledge evidence whose required reference record has disappeared.
func TestAdmissionLedgerPublishRefusesBrokenReferences(t *testing.T) {
	for _, damage := range []string{"missing evidence", "missing references", "damaged references"} {
		t.Run(damage, func(t *testing.T) {
			f := newLedgerFixture(t)
			e := f.mint(evidenceSpec{})
			if _, err := f.l.PublishEvidence(e); err != nil {
				t.Fatal(err)
			}
			f.enqueue(f.request("192.0.2.10", e.ID()))
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				switch damage {
				case "missing evidence":
					return tx.Bucket([]byte(admissionEvidenceBucket)).Delete([]byte(e.ID()))
				case "missing references":
					return tx.Bucket([]byte(admissionRefsBucket)).Delete([]byte(e.ID()))
				default:
					return tx.Bucket([]byte(admissionRefsBucket)).Put([]byte(e.ID()), []byte("damaged"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if published, err := f.l.PublishEvidence(e); published || !isCorrupt(err) {
				t.Errorf("publish accepted damaged references: %t, %v", published, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Error("refused publish changed the ledger")
			}
		})
	}
}

// Eviction must detect damaged rows before deleting them, rather than hide
// damage behind a successful write. A malformed ring key must not panic.
func TestAdmissionLedgerLooseEvictionRefusesDamage(t *testing.T) {
	for _, damage := range []string{"short key", "long key", "named root at zero", "missing evidence", "damaged evidence", "damaged reports"} {
		t.Run(damage, func(t *testing.T) {
			f := newLedgerFixture(t)
			ids := f.publishLoose(admission.MaxLooseEvidence, false)
			if damage == "named root at zero" {
				f.enqueue(f.request("192.0.2.12", ids[0]))
				f.published(evidenceSpec{cursor: "fill-vacancy"})
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				switch damage {
				case "named root at zero":
					b := tx.Bucket([]byte(admissionRingsBucket))
					if err := b.Delete(ringKey(ringLoose, 2)); err != nil {
						return err
					}
					return b.Put(ringKey(ringLoose, 0), []byte(ids[0]))
				case "short key", "long key":
					b := tx.Bucket([]byte(admissionRingsBucket))
					key := []byte{ringLoose}
					if damage == "long key" {
						key = append(ringKey(ringLoose, 1), 0)
					}
					if err := b.Delete(ringKey(ringLoose, 1)); err != nil {
						return err
					}
					return b.Put(key, []byte(ids[0]))
				case "missing evidence":
					return tx.Bucket([]byte(admissionEvidenceBucket)).Delete([]byte(ids[0]))
				case "damaged evidence":
					return tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(ids[0]), []byte("damaged"))
				default:
					return tx.Bucket([]byte(admissionReportsBucket)).Put([]byte(ids[0]), []byte("damaged"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("eviction panicked instead of refusing damage: %v", p)
				}
			}()
			if _, err := f.l.PublishEvidence(f.mint(evidenceSpec{cursor: "overflow"})); !isCorrupt(err) {
				t.Errorf("eviction accepted damage: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Error("refused eviction changed the ledger")
			}
		})
	}
}

func TestAdmissionLedgerEndedEvictionRefusesMalformedKey(t *testing.T) {
	for name, key := range map[string][]byte{"short": {ringEnded}, "zero": ringKey(ringEnded, 0)} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			ids := f.endMany(admission.MaxEndedCandidates)
			live := f.queued()
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(admissionRingsBucket))
				if err := b.Delete(ringKey(ringEnded, 1)); err != nil {
					return err
				}
				return b.Put(key, []byte(ids[0]))
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := f.l.Terminate(live, admission.ReasonProtected); !isCorrupt(err) {
				t.Errorf("ending accepted malformed ring key: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Error("refused ending changed the ledger")
			}
		})
	}
}

// A nested bucket is not a ring record, even when its key and the stored
// count agree. Refusal must preserve the entire database file.
func TestAdmissionLedgerOpenRefusesNestedRing(t *testing.T) {
	for _, kind := range []byte{ringEnded, ringLoose} {
		t.Run(string(kind), func(t *testing.T) {
			f := newLedgerFixture(t)
			if kind == ringEnded {
				id := f.queued()
				if _, err := f.l.Terminate(id, admission.ReasonProtected); err != nil {
					t.Fatal(err)
				}
			} else {
				f.published(evidenceSpec{})
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(admissionRingsBucket))
				key := ringKey(kind, 1)
				if err := b.Delete(key); err != nil {
					return err
				}
				_, err := b.CreateBucket(key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(f.db.Path()) // #nosec G304 -- test database under t.TempDir
			if err != nil {
				t.Fatal(err)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Errorf("nested bucket counted as a ring record: %v", err)
			}
			after, err := os.ReadFile(f.db.Path()) // #nosec G304 -- test database under t.TempDir
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("refused open changed the database file: %v", err)
			}
		})
	}
}

// A nested bucket that took the oldest ring position after open is damage,
// not an entry to evict: the call refuses it as corrupt and changes nothing.
func TestAdmissionLedgerEvictionRefusesNestedRingEntry(t *testing.T) {
	for _, kind := range []byte{ringEnded, ringLoose} {
		t.Run(string(kind), func(t *testing.T) {
			f := newLedgerFixture(t)
			var live admission.CandidateID
			if kind == ringEnded {
				f.endMany(admission.MaxEndedCandidates)
				live = f.queued()
			} else {
				f.publishLoose(admission.MaxLooseEvidence, false)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(admissionRingsBucket))
				if err := b.Delete(ringKey(kind, 1)); err != nil {
					return err
				}
				_, err := b.CreateBucket(ringKey(kind, 1))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			var err error
			if kind == ringEnded {
				_, err = f.l.Terminate(live, admission.ReasonProtected)
			} else {
				_, err = f.l.PublishEvidence(f.mint(evidenceSpec{cursor: "overflow"}))
			}
			if !isCorrupt(err) {
				t.Errorf("eviction of a nested ring entry: %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Error("refused eviction changed the ledger")
			}
		})
	}
}
