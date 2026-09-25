package store

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// The ledger is inert until something opens it: a state database opened by
// the daemon today gains no admission buckets.
func TestAdmissionLedgerCreatesItsBucketsOnlyWhenOpened(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	hasBuckets := func() (n int) {
		_ = db.bolt.View(func(tx *bolt.Tx) error {
			for _, name := range admissionBuckets {
				if tx.Bucket([]byte(name)) != nil {
					n++
				}
			}
			return nil
		})
		return n
	}
	if n := hasBuckets(); n != 0 {
		t.Fatalf("plain Open created %d admission buckets", n)
	}
	reg, _, _, _ := newLedgerRegistry(t)
	if _, err := OpenAdmissionLedger(db, reg); err != nil {
		t.Fatal(err)
	}
	if n := hasBuckets(); n != len(admissionBuckets) {
		t.Fatalf("ledger created %d of %d buckets", n, len(admissionBuckets))
	}
}

func TestAdmissionLedgerRefusesUnsealedRegistryAndUnknownSchema(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	open, err := admission.NewRegistry(ledgerLookup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(db, open); err == nil {
		t.Fatal("unsealed registry accepted")
	}
	reg, _, _, _ := newLedgerRegistry(t)
	if _, err := OpenAdmissionLedger(nil, reg); err == nil {
		t.Fatal("nil database accepted")
	}
	if _, err := OpenAdmissionLedger(db, reg); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(meta *bolt.Bucket) error{
		"future schema": func(meta *bolt.Bucket) error { return meta.Put(admissionSchemaKey, []byte{2}) },
		"missing schema with data": func(meta *bolt.Bucket) error {
			if err := meta.Delete(admissionSchemaKey); err != nil {
				return err
			}
			return meta.Put([]byte("stray"), []byte{1})
		},
	} {
		if err := db.bolt.Update(func(tx *bolt.Tx) error { return mutate(tx.Bucket([]byte(admissionMetaBucket))) }); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenAdmissionLedger(db, reg); err != ErrAdmissionSchema {
			t.Errorf("%s: err = %v, want ErrAdmissionSchema", name, err)
		}
		_ = db.bolt.Update(func(tx *bolt.Tx) error {
			meta := tx.Bucket([]byte(admissionMetaBucket))
			_ = meta.Delete([]byte("stray"))
			return meta.Put(admissionSchemaKey, []byte{admissionSchemaVersion})
		})
	}
}

// The high-water mark survives a restart: a ledger reopened after a clock
// rollback keeps the later time and reports degraded coverage.
func TestAdmissionLedgerClockSurvivesRestart(t *testing.T) {
	f := newLedgerFixture(t)
	f.tickAt(ledgerT0.Add(time.Hour))
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.now.Equal(ledgerT0.Add(time.Hour)) {
		t.Fatalf("reopened now = %v", reopened.now)
	}
	tick, err := reopened.Tick(admission.ClockReading{Wall: ledgerT0, BootID: ledgerBoot, SinceBoot: f.since + time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !tick.Degraded || !tick.Now.Equal(ledgerT0.Add(time.Hour)) {
		t.Fatalf("rollback after restart: %+v", tick)
	}
}

// A failed transaction publishes nothing: the stored clock and the time the
// ledger uses stay where they were.
func TestAdmissionLedgerTickIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	f.failNext("tick")
	if _, err := f.l.Tick(admission.ClockReading{Wall: ledgerT0.Add(time.Hour), BootID: ledgerBoot, SinceBoot: f.since + time.Hour}); err == nil {
		t.Fatal("injected failure did not fail the tick")
	}
	if !f.l.now.Equal(ledgerT0) {
		t.Fatalf("failed tick moved now to %v", f.l.now)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil || !reopened.now.Equal(ledgerT0) {
		t.Fatalf("stored clock after failed tick: %v, %v", reopened.now, err)
	}
}

// A damaged meta record refuses to open the ledger instead of starting from
// a guessed clock or inventory.
func TestAdmissionLedgerRefusesCorruptMeta(t *testing.T) {
	for name, damage := range map[string]func(meta *bolt.Bucket) error{
		"clock":                 func(meta *bolt.Bucket) error { return meta.Put(admissionClockKey, []byte("{}")) },
		"inventory":             func(meta *bolt.Bucket) error { return meta.Put(admissionInventoryKey, []byte("{}")) },
		"negative ambiguity":    func(meta *bolt.Bucket) error { return meta.Put(admissionAmbiguousKey, []byte("-1")) },
		"padded ambiguity":      func(meta *bolt.Bucket) error { return meta.Put(admissionAmbiguousKey, []byte("007")) },
		"non-numeric ambiguity": func(meta *bolt.Bucket) error { return meta.Put(admissionAmbiguousKey, []byte("x")) },
		"missing ambiguity":     func(meta *bolt.Bucket) error { return meta.Delete(admissionAmbiguousKey) },
	} {
		f := newLedgerFixture(t)
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(tx.Bucket([]byte(admissionMetaBucket))) }); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
			t.Errorf("%s: err = %v, want a corrupt record", name, err)
		}
	}
}

// Generations persist: an account keeps its generation across refreshes and
// restarts, and one that disappears and returns gets a new one.
func TestAdmissionLedgerInventoryGenerations(t *testing.T) {
	f := newLedgerFixture(t)
	alice := f.owner("alice")
	f.refresh([]string{"alice", "bob", "carol"}, map[string]string{"shop.example": "carol"})
	if f.owner("alice") != alice {
		t.Fatal("alice changed generation while present")
	}
	if err := f.l.RefreshInventory(admission.InventoryObservation{Accounts: []string{"bob"}, AmbiguousDomains: 2}); err != nil {
		t.Fatal(err)
	}
	if f.l.AmbiguousDomains() != 2 {
		t.Fatalf("ambiguous = %d", f.l.AmbiguousDomains())
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.AmbiguousDomains() != 2 || reopened.Inventory().Current(alice) {
		t.Fatal("reopened ledger lost the committed inventory")
	}
	f.l = reopened
	f.refresh([]string{"alice", "bob"}, nil)
	if back := f.owner("alice"); back == alice || back.Generation() <= alice.Generation() {
		t.Fatalf("returning alice reused generation %d", back.Generation())
	}
}

// A malformed observation or a failed transaction keeps the previous
// inventory, in memory and on disk.
func TestAdmissionLedgerInventoryRefreshIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	alice := f.owner("alice")
	for name, obs := range map[string]admission.InventoryObservation{
		"unlisted domain owner": {Accounts: []string{"bob"}, Domains: map[string]string{"alice.example": "alice"}},
		"invalid account":       {Accounts: []string{"bob", "../etc"}},
		"negative ambiguity":    {Accounts: []string{"bob"}, AmbiguousDomains: -1},
	} {
		wantLedgerReason(t, name, f.l.RefreshInventory(obs), admission.ReasonInvalid)
	}
	f.failNext("inventory")
	if err := f.l.RefreshInventory(admission.InventoryObservation{Accounts: []string{"bob"}}); err == nil {
		t.Fatal("injected failure did not fail the refresh")
	}
	if !f.l.Inventory().Current(alice) {
		t.Fatal("failed refresh changed the published inventory")
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil || !reopened.Inventory().Current(alice) {
		t.Fatalf("failed refresh reached disk: %v", err)
	}
}

func TestAdmissionLedgerFreshInventoryAndMissingMeta(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	reg, _, _, _ := newLedgerRegistry(t)
	l, err := OpenAdmissionLedger(db, reg)
	if err != nil {
		t.Fatal(err)
	}
	if l.Inventory() == nil || !l.Inventory().Current(admission.HostOwner()) || l.AmbiguousDomains() != 0 {
		t.Fatal("fresh ledger has no empty inventory")
	}
	for _, key := range [][]byte{admissionClockKey, admissionTrackerKey, admissionInventoryKey} {
		f := newLedgerFixture(t)
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(admissionMetaBucket)).Delete(key) }); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
			t.Errorf("missing %s: %v", key, err)
		}
	}
}

func TestAdmissionLedgerValidatesInventoryPair(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		f := newLedgerFixture(t)
		raw := []byte("damaged")
		if mismatch {
			g := admission.NewGenerations()
			if _, err := g.Observe([]string{"carol"}); err != nil {
				t.Fatal(err)
			}
			var err error
			raw, err = g.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionTrackerKey, raw) }); err != nil {
			t.Fatal(err)
		}
		before := f.snapshot()
		if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
			t.Fatalf("open accepted tracker: %v", err)
		}
		if err := f.l.RefreshInventory(admission.InventoryObservation{Accounts: []string{"alice", "bob"}}); !isCorrupt(err) {
			t.Fatalf("refresh accepted tracker: %v", err)
		}
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatal("invalid tracker was overwritten")
		}
	}
}

func TestAdmissionLedgerMissingBucketRefusesAtomically(t *testing.T) {
	for _, name := range admissionBuckets {
		f := newLedgerFixture(t)
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte(name)) }); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenAdmissionLedger(f.db, f.reg); err == nil {
			t.Fatalf("missing %s was recreated", name)
		}
		if err := f.db.bolt.View(func(tx *bolt.Tx) error {
			if tx.Bucket([]byte(name)) != nil {
				t.Errorf("failed open recreated %s", name)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdmissionLedgerClockReopensDatabase(t *testing.T) {
	f := newLedgerFixture(t)
	path := f.db.Path()
	f.tickAt(ledgerT0.Add(time.Minute))
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	l, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	tick, err := l.Tick(admission.ClockReading{Wall: ledgerT0.Add(2 * time.Minute), BootID: ledgerBoot, SinceBoot: time.Hour + 2*time.Minute})
	if err != nil || tick.Elapsed != time.Minute || tick.Degraded {
		t.Fatalf("same boot: %+v %v", tick, err)
	}
	tick, err = l.Tick(admission.ClockReading{Wall: ledgerT0.Add(3 * time.Minute), BootID: "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d", SinceBoot: time.Second})
	if err != nil || tick.Elapsed != 0 {
		t.Fatalf("new boot: %+v %v", tick, err)
	}
}
