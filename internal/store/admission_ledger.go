package store

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

const (
	admissionMetaBucket       = "adm:meta"
	admissionEvidenceBucket   = "adm:evidence"
	admissionReportsBucket    = "adm:reports"
	admissionCandidatesBucket = "adm:candidates"
	admissionAttemptsBucket   = "adm:attempts"
	admissionSchemaVersion    = 1
)

var (
	admissionBuckets         = []string{admissionMetaBucket, admissionEvidenceBucket, admissionReportsBucket, admissionCandidatesBucket, admissionAttemptsBucket}
	admissionSchemaKey       = []byte("schema")
	admissionClockKey        = []byte("clock")
	admissionClockPendingKey = []byte("clock_pending")
	admissionTrackerKey      = []byte("generations")
	admissionInventoryKey    = []byte("inventory")
	admissionAmbiguousKey    = []byte("ambiguous_domains")
)

// ErrAdmissionSchema reports admission buckets this build cannot read: an
// unknown schema, or data without a schema marker.
var ErrAdmissionSchema = errors.New("admission ledger schema is not supported")

// AdmissionLedger is the durable admission state of spec 5.4, kept in the
// daemon's state database. The engine is its only owner: mutating calls
// serialize on one mutex and each runs in one write transaction, so an error
// leaves the ledger unchanged. Nothing constructs it in production yet.
type AdmissionLedger struct {
	db  *DB
	reg *admission.Registry

	mu  sync.Mutex
	now time.Time

	inv atomic.Pointer[ledgerInventory]

	// failBeforeCommit lets a test fail a write transaction after all of
	// its writes, to prove that nothing is published.
	failBeforeCommit func(op string) error
}

type ledgerInventory struct {
	inv       *admission.Inventory
	ambiguous int
}

func corruptRecord(err error) error {
	if errors.Is(err, admission.ErrCorruptRecord) {
		return err
	}
	return fmt.Errorf("%w: %v", admission.ErrCorruptRecord, err)
}

func refusal(r admission.Reason, detail string) error {
	return &admission.Error{Reason: r, Detail: detail}
}

// OpenAdmissionLedger opens the ledger on db, creating its buckets on first
// use. The registry must be sealed: the set of producers cannot change
// under a running ledger.
func OpenAdmissionLedger(db *DB, reg *admission.Registry) (*AdmissionLedger, error) {
	if db == nil || reg == nil || !reg.Sealed() {
		return nil, errors.New("admission ledger needs a database and a sealed producer registry")
	}
	l := &AdmissionLedger{db: db, reg: reg}
	published := ledgerInventory{}
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		existing := 0
		for _, name := range admissionBuckets {
			if tx.Bucket([]byte(name)) != nil {
				existing++
			}
		}
		if existing != 0 && existing != len(admissionBuckets) {
			return admission.ErrCorruptRecord
		}
		fresh := existing == 0
		if fresh {
			for _, name := range admissionBuckets {
				if _, err := tx.CreateBucket([]byte(name)); err != nil {
					return err
				}
			}
		}
		meta := tx.Bucket([]byte(admissionMetaBucket))
		if fresh {
			if err := initializeLedgerMeta(meta); err != nil {
				return err
			}
		} else if schema := meta.Get(admissionSchemaKey); len(schema) != 1 || schema[0] != admissionSchemaVersion {
			return ErrAdmissionSchema
		}
		c, err := loadLedgerClock(meta)
		if err != nil {
			return err
		}
		l.now = c.Now()
		published, err = loadLedgerInventory(meta)
		return err
	})
	if err != nil {
		return nil, err
	}
	l.inv.Store(&published)
	return l, nil
}

func initializeLedgerMeta(meta *bolt.Bucket) error {
	inv, err := admission.NewInventory(nil, nil)
	if err != nil {
		return err
	}
	snapshot, err := inv.MarshalBinary()
	if err != nil {
		return err
	}
	tracker, err := admission.NewGenerations().MarshalBinary()
	if err != nil {
		return err
	}
	for _, entry := range []struct{ key, value []byte }{
		{admissionSchemaKey, []byte{admissionSchemaVersion}},
		{admissionClockPendingKey, []byte{1}},
		{admissionTrackerKey, tracker},
		{admissionInventoryKey, snapshot},
		{admissionAmbiguousKey, []byte("0")},
	} {
		if err := meta.Put(entry.key, entry.value); err != nil {
			return err
		}
	}
	return nil
}

// A separate marker distinguishes a fresh clock from a lost checkpoint.
// The first tick removes it in the same transaction that writes the clock.
func loadLedgerClock(meta *bolt.Bucket) (admission.Clock, error) {
	raw, pending := meta.Get(admissionClockKey), meta.Get(admissionClockPendingKey)
	if raw == nil && len(pending) == 1 && pending[0] == 1 {
		return admission.Clock{}, nil
	}
	if raw == nil || pending != nil {
		return admission.Clock{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalClock(raw)
}

func loadLedgerTracker(meta *bolt.Bucket) (*admission.Generations, error) {
	g := admission.NewGenerations()
	if err := g.UnmarshalBinary(meta.Get(admissionTrackerKey)); err != nil {
		return nil, corruptRecord(err)
	}
	return g, nil
}

func loadLedgerInventory(meta *bolt.Bucket) (ledgerInventory, error) {
	raw := meta.Get(admissionInventoryKey)
	inv, err := admission.UnmarshalInventory(raw)
	if err != nil {
		return ledgerInventory{}, err
	}
	g, err := loadLedgerTracker(meta)
	if err != nil {
		return ledgerInventory{}, err
	}
	if !inv.MatchesGenerations(g) {
		return ledgerInventory{}, admission.ErrCorruptRecord
	}
	amb := string(meta.Get(admissionAmbiguousKey))
	n, err := strconv.Atoi(amb)
	if err != nil || n < 0 || strconv.Itoa(n) != amb {
		return ledgerInventory{}, admission.ErrCorruptRecord
	}
	return ledgerInventory{inv: inv, ambiguous: n}, nil
}

func (l *AdmissionLedger) update(op string, fn func(tx *bolt.Tx) error) error {
	return l.db.bolt.Update(func(tx *bolt.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if l.failBeforeCommit != nil {
			return l.failBeforeCommit(op)
		}
		return nil
	})
}

// Tick records a clock reading. The high-water mark it persists is the only
// time the other calls use.
func (l *AdmissionLedger) Tick(r admission.ClockReading) (admission.ClockTick, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var tick admission.ClockTick
	err := l.update("tick", func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte(admissionMetaBucket))
		c, err := loadLedgerClock(meta)
		if err != nil {
			return err
		}
		next, t, err := c.Advance(r)
		if err != nil {
			return err
		}
		data, err := next.MarshalBinary()
		if err != nil {
			return err
		}
		tick = t
		if err := meta.Delete(admissionClockPendingKey); err != nil {
			return err
		}
		return meta.Put(admissionClockKey, data)
	})
	if err != nil {
		return admission.ClockTick{}, err
	}
	l.now = tick.Now
	return tick, nil
}

func (l *AdmissionLedger) clock() (time.Time, error) {
	if l.now.IsZero() {
		return time.Time{}, refusal(admission.ReasonEngineUnavailable, "admission clock has no reading")
	}
	return l.now, nil
}

// RefreshInventory folds one complete observation into the persisted
// generation tracker and publishes the new inventory only after the
// transaction commits. A failed read or transaction keeps the old one.
func (l *AdmissionLedger) RefreshInventory(obs admission.InventoryObservation) error {
	if obs.AmbiguousDomains < 0 {
		return refusal(admission.ReasonInvalid, "ambiguous domain count is negative")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var next ledgerInventory
	err := l.update("inventory", func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte(admissionMetaBucket))
		if _, err := loadLedgerInventory(meta); err != nil {
			return err
		}
		g, err := loadLedgerTracker(meta)
		if err != nil {
			return err
		}
		gens, err := g.Observe(obs.Accounts)
		if err != nil {
			return refusal(admission.ReasonInvalid, "inventory observation is malformed")
		}
		inv, err := admission.NewInventory(gens, obs.Domains)
		if err != nil {
			return refusal(admission.ReasonInvalid, "inventory observation is malformed")
		}
		tracker, err := g.MarshalBinary()
		if err != nil {
			return err
		}
		snapshot, err := inv.MarshalBinary()
		if err != nil {
			return err
		}
		if err := meta.Put(admissionTrackerKey, tracker); err != nil {
			return err
		}
		if err := meta.Put(admissionInventoryKey, snapshot); err != nil {
			return err
		}
		next = ledgerInventory{inv: inv, ambiguous: obs.AmbiguousDomains}
		return meta.Put(admissionAmbiguousKey, strconv.AppendInt(nil, int64(obs.AmbiguousDomains), 10))
	})
	if err != nil {
		return err
	}
	l.inv.Store(&next)
	return nil
}

// Inventory is the last committed inventory.
func (l *AdmissionLedger) Inventory() *admission.Inventory { return l.inv.Load().inv }

// AmbiguousDomains is the count from the last committed observation.
func (l *AdmissionLedger) AmbiguousDomains() int { return l.inv.Load().ambiguous }
