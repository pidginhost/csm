package store

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// schemaOne rewrites the fixture's database into the schema 1 layout: the
// same records without the queue buckets.
func (f *ledgerFixture) schemaOne() {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		for _, name := range admissionQueueBuckets {
			if err := tx.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{1})
	}); err != nil {
		f.t.Fatal(err)
	}
}

// copyDatabase closes the fixture's database and returns a copy of its file
// opened in a new directory, so a test can open, upgrade or damage the copy
// while the original stays as it was.
func (f *ledgerFixture) copyDatabase() *DB {
	f.t.Helper()
	path := f.db.Path()
	if err := f.db.Close(); err != nil {
		f.t.Fatal(err)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test database under t.TempDir
	if err != nil {
		f.t.Fatal(err)
	}
	dir := f.t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, filepath.Base(path)), raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
	db, err := Open(dir)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = db.Close() })
	return db
}

func dbSnapshot(t *testing.T, db *DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		for _, name := range admissionBuckets {
			b := tx.Bucket([]byte(name))
			if b == nil {
				continue
			}
			out[name] = ""
			if err := b.ForEach(func(k, v []byte) error {
				out[name+":"+string(k)] = string(v)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// A new ledger starts at schema 2 with empty queue bookkeeping.
func TestAdmissionLedgerSchemaTwoLayout(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		if schema := tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey); !bytes.Equal(schema, []byte{2}) {
			t.Errorf("schema = %v", schema)
		}
		state, err := loadQueueState(tx)
		if err != nil || state != (admission.QueueState{}) {
			t.Errorf("queue state = %+v, %v", state, err)
		}
		if _, err = loadQueueCounters(tx); err != nil {
			t.Error(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A schema 1 ledger is upgraded once, in the opening transaction: live
// candidates get an unassessed general entry, ended ones get none, and every
// schema 1 record stays byte for byte. Opening again changes nothing.
func TestAdmissionLedgerUpgradesSchemaOne(t *testing.T) {
	f := newLedgerFixture(t)
	queued := f.queued()
	f.nextGeneration()
	reserved := f.queued()
	if _, _, _, err := f.l.Reserve(reserved, ledgerT0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	ended := f.queued()
	if _, err := f.l.Terminate(ended, admission.ReasonProtected); err != nil {
		t.Fatal(err)
	}
	f.schemaOne()
	before := dbSnapshot(t, f.db)
	db := f.copyDatabase()
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	after := dbSnapshot(t, db)
	schemaKey := admissionMetaBucket + ":" + string(admissionSchemaKey)
	for k, v := range before {
		if after[k] != v && k != schemaKey {
			t.Fatalf("upgrade changed schema 1 record %s", k)
		}
	}
	if after[schemaKey] != string([]byte{admissionSchemaVersion}) {
		t.Fatalf("upgraded schema = %q", after[schemaKey])
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		if n := tx.Bucket([]byte(admissionQueueBucket)).Stats().KeyN; n != 2 {
			t.Errorf("queue entries = %d, want 2", n)
		}
		for _, id := range []admission.CandidateID{queued, reserved} {
			q, err := loadQueueEntry(tx, id)
			if err != nil || q != (admission.QueueEntry{Partition: admission.PartitionGeneral}) {
				t.Errorf("%s entry = %+v, %v", id, q, err)
			}
		}
		if raw := tx.Bucket([]byte(admissionQueueBucket)).Get([]byte(ended)); raw != nil {
			t.Error("an ended candidate got an entry")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	if again := dbSnapshot(t, db); !reflect.DeepEqual(again, after) {
		t.Fatal("a second open changed the upgraded ledger")
	}
}

// An upgrade that fails part way leaves the schema 1 ledger exactly as it
// was: a damaged candidate after live ones rolls back their entries too.
func TestAdmissionLedgerUpgradeRollsBack(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	f.schemaOne()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionCandidatesBucket)).Put([]byte("cand_ffffffffffffffffffffffffffffffff"), []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	db := f.copyDatabase()
	before := dbSnapshot(t, db)
	if _, err := OpenAdmissionLedger(db, f.reg); !isCorrupt(err) {
		t.Fatalf("upgrade over a damaged candidate: %v", err)
	}
	if after := dbSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatal("a failed upgrade changed the ledger")
	}
}

// Only a complete schema 1 layout is upgraded. Queue buckets beside schema
// 1, a missing schema 1 bucket or damaged queue bookkeeping refuse to open.
func TestAdmissionLedgerRefusesPartialSchemas(t *testing.T) {
	for name, damage := range map[string]func(tx *bolt.Tx) error{
		"schema 1 with a queue bucket": func(tx *bolt.Tx) error {
			if err := tx.DeleteBucket([]byte(admissionQueueStateBucket)); err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{1})
		},
		"schema 1 without attempts": func(tx *bolt.Tx) error {
			for _, name := range append([]string{admissionAttemptsBucket}, admissionQueueBuckets...) {
				if err := tx.DeleteBucket([]byte(name)); err != nil {
					return err
				}
			}
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{1})
		},
		"missing queue state": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(queueStateKey)
		},
		"damaged queue state": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Put(queueStateKey, []byte("{}"))
		},
		"missing counters": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(queueCountersKey)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			if err := f.db.bolt.Update(damage); err != nil {
				t.Fatal(err)
			}
			before := dbSnapshot(t, f.db)
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
				t.Fatal("a refused open changed the ledger")
			}
		})
	}
}

// An upgrade cannot assume reserved eligibility before a current reading.
// Oversized legacy queues remain schema 1, with no partial queue buckets.
func TestAdmissionLedgerUpgradeRefusesExcessLiveWork(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	c, err := f.l.Candidate(id)
	if err != nil {
		t.Fatal(err)
	}
	f.schemaOne()
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		for i := 0; i < admission.PartitionGeneral.DurableCapacity(); i++ {
			c.Key.Generation++
			if putErr := putCandidate(tx, c); putErr != nil {
				return putErr
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	db := f.copyDatabase()
	before := dbSnapshot(t, db)
	_, err = OpenAdmissionLedger(db, f.reg)
	wantLedgerReason(t, "oversized legacy queue", err, admission.ReasonQueueOverflow)
	if !reflect.DeepEqual(before, dbSnapshot(t, db)) {
		t.Fatal("refused upgrade changed the legacy ledger")
	}
}

// The first new arrival after an upgrade must run due maintenance even
// without a prior explicit revalidation; unassessed entries need a sweep.
func TestAdmissionLedgerUpgradeSweepsBeforeEnqueue(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	f.schemaOne()
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = l
	f.tickAt(ledgerT0.Add(admission.QueueAgeLimit))
	root := f.published(evidenceSpec{target: "192.0.2.11", cursor: "fresh"})
	before := f.snapshot()
	f.failNext("enqueue")
	if _, _, err = f.l.Enqueue(f.request("192.0.2.11", root)); err == nil {
		t.Fatal("injected failure did not abort enqueue")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed enqueue changed the upgraded queue")
	}
	f.enqueue(f.request("192.0.2.11", root))
	if c, err := f.l.Candidate(id); err != nil || c.State != admission.StateDropped || c.Reason != admission.ReasonStale {
		t.Fatalf("upgraded candidate was not swept: %+v %v", c, err)
	}
}
