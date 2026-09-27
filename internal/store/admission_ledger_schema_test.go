package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// schemaTwo rewrites the fixture's database into the schema 2 layout: the
// same records without the ceiling.
func (f *ledgerFixture) schemaTwo() {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(admissionChargesBucket)); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(admissionQueueStateBucket)).Delete(ceilingStateKey); err != nil {
			return err
		}
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{2})
	}); err != nil {
		f.t.Fatal(err)
	}
}

// schemaOne rewrites the fixture's database into the schema 1 layout: the
// same records without the ceiling and the queue buckets.
func (f *ledgerFixture) schemaOne() {
	f.t.Helper()
	f.schemaTwo()
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

// A new ledger starts at schema 3 with empty queue bookkeeping, no charges
// and a ceiling waiting for its first limit to fill its buckets.
func TestAdmissionLedgerSchemaThreeLayout(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	reg, _, _, _ := newLedgerRegistry(t)
	if _, err = OpenAdmissionLedger(db, reg); err != nil {
		t.Fatal(err)
	}
	if err = db.bolt.View(func(tx *bolt.Tx) error {
		if schema := tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey); !bytes.Equal(schema, []byte{3}) {
			t.Errorf("schema = %v", schema)
		}
		state, stateErr := loadQueueState(tx)
		if stateErr != nil || state != (admission.QueueState{}) {
			t.Errorf("queue state = %+v, %v", state, stateErr)
		}
		if _, stateErr = loadQueueCounters(tx); stateErr != nil {
			t.Error(stateErr)
		}
		if n := tx.Bucket([]byte(admissionChargesBucket)).Stats().KeyN; n != 0 {
			t.Errorf("charges = %d", n)
		}
		if got, stateErr := loadCeiling(tx); stateErr != nil || got != (admission.CeilingState{Fill: true}) {
			t.Errorf("new ceiling = %+v, %v", got, stateErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A schema 2 ledger is upgraded once, in the opening transaction: every
// schema 2 record stays byte for byte, and the ceiling starts empty and
// unset because the ledger's recent spend is unknown. Opening again
// changes nothing.
func TestAdmissionLedgerUpgradesSchemaTwo(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	f.nextGeneration()
	reserved := f.queued()
	if _, _, _, err := f.l.Reserve(reserved, ledgerT0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.schemaTwo()
	before := dbSnapshot(t, f.db)
	db := f.copyDatabase()
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	after := dbSnapshot(t, db)
	schemaKey := admissionMetaBucket + ":" + string(admissionSchemaKey)
	for k, v := range before {
		if after[k] != v && k != schemaKey {
			t.Fatalf("upgrade changed schema 2 record %s", k)
		}
	}
	if after[schemaKey] != string([]byte{3}) {
		t.Fatalf("upgraded schema = %q", after[schemaKey])
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		s, err := loadCeiling(tx)
		if err != nil || s != (admission.CeilingState{}) {
			t.Errorf("upgraded ceiling = %+v, %v", s, err)
		}
		if n := tx.Bucket([]byte(admissionChargesBucket)).Stats().KeyN; n != 0 {
			t.Errorf("upgrade invented %d charges", n)
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

// A schema 2 upgrade commits with the rest of the opening checks: damaged
// queue bookkeeping refuses the open and leaves schema 2 exactly as it was.
func TestAdmissionLedgerUpgradeFromTwoRollsBack(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	f.schemaTwo()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueStateBucket)).Put(queueCountersKey, []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	db := f.copyDatabase()
	before := dbSnapshot(t, db)
	if _, err := OpenAdmissionLedger(db, f.reg); !isCorrupt(err) {
		t.Fatalf("upgrade over damaged counters: %v", err)
	}
	if after := dbSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatal("a failed upgrade changed the schema 2 ledger")
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
		if s, err := loadCeiling(tx); err != nil || s != (admission.CeilingState{}) {
			t.Errorf("upgraded ceiling = %+v, %v", s, err)
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

// A live candidate's attempt history is part of what the queue reads, so
// damaged or missing attempts refuse the upgrade and leave schema 1 intact.
func TestAdmissionLedgerUpgradeRefusesDamagedAttempts(t *testing.T) {
	for _, shape := range []string{"damaged", "missing"} {
		t.Run(shape, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.queued()
			f.nextGeneration()
			reserved := f.queued()
			if _, _, _, err := f.l.Reserve(reserved, ledgerT0.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			f.schemaOne()
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(admissionAttemptsBucket))
				var keys [][]byte
				if err := b.ForEach(func(k, _ []byte) error {
					keys = append(keys, append([]byte(nil), k...))
					return nil
				}); err != nil {
					return err
				}
				if len(keys) == 0 {
					return errors.New("no attempt records to damage")
				}
				for _, k := range keys {
					if shape == "missing" {
						if err := b.Delete(k); err != nil {
							return err
						}
					} else if err := b.Put(k, []byte("damaged")); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			db := f.copyDatabase()
			before := dbSnapshot(t, db)
			if _, err := OpenAdmissionLedger(db, f.reg); !isCorrupt(err) {
				t.Fatalf("upgrade over %s attempts: %v", shape, err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, db)) {
				t.Fatal("a refused upgrade changed the schema 1 ledger")
			}
		})
	}
}

// Only a complete schema 1 layout is upgraded. Queue buckets beside schema
// 1, a missing schema 1 bucket or damaged queue bookkeeping refuse to open.
func TestAdmissionLedgerRefusesPartialSchemas(t *testing.T) {
	for name, damage := range map[string]func(tx *bolt.Tx) error{
		"schema 1 with a queue bucket": func(tx *bolt.Tx) error {
			for _, name := range []string{admissionQueueStateBucket, admissionChargesBucket} {
				if err := tx.DeleteBucket([]byte(name)); err != nil {
					return err
				}
			}
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{1})
		},
		"schema 1 without attempts": func(tx *bolt.Tx) error {
			for _, name := range append([]string{admissionAttemptsBucket, admissionChargesBucket}, admissionQueueBuckets...) {
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
		"schema 2 with the charges bucket": func(tx *bolt.Tx) error {
			if err := tx.Bucket([]byte(admissionQueueStateBucket)).Delete(ceilingStateKey); err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{2})
		},
		"schema 2 without the queue state": func(tx *bolt.Tx) error {
			for _, name := range []string{admissionChargesBucket, admissionQueueStateBucket} {
				if err := tx.DeleteBucket([]byte(name)); err != nil {
					return err
				}
			}
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{2})
		},
		"schema 3 without charges": func(tx *bolt.Tx) error {
			return tx.DeleteBucket([]byte(admissionChargesBucket))
		},
		"missing ceiling": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(ceilingStateKey)
		},
		"damaged ceiling": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Put(ceilingStateKey, []byte("{}"))
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
