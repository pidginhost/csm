package store

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
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
	admissionQueueBucket      = "adm:queue"
	admissionQueueStateBucket = "adm:qstate"
	admissionChargesBucket    = "adm:charges"
	admissionHistoryBucket    = "adm:history"
	admissionRetireBucket     = "adm:retire"
	admissionRefsBucket       = "adm:evrefs"
	admissionRingsBucket      = "adm:rings"
	admissionOutboxBucket     = "adm:outbox"
	admissionWindowsBucket    = "adm:windows"
	admissionEpisodesBucket   = "adm:episodes"
	admissionSchemaVersion    = 6
)

var (
	// admissionSchemaOneBuckets are the buckets of the schema 1 layout.
	// Schema 2 adds the queue buckets, schema 3 the charges bucket, schema
	// 4 the storage buckets, schema 5 the outbox and outcome buckets and
	// schema 6 the episode bucket.
	admissionSchemaOneBuckets   = []string{admissionMetaBucket, admissionEvidenceBucket, admissionReportsBucket, admissionCandidatesBucket, admissionAttemptsBucket}
	admissionQueueBuckets       = []string{admissionQueueBucket, admissionQueueStateBucket}
	admissionSchemaTwoBuckets   = append(append([]string(nil), admissionSchemaOneBuckets...), admissionQueueBuckets...)
	admissionSchemaThreeBuckets = append(append([]string(nil), admissionSchemaTwoBuckets...), admissionChargesBucket)
	admissionStorageBuckets     = []string{admissionHistoryBucket, admissionRetireBucket, admissionRefsBucket, admissionRingsBucket}
	admissionSchemaFourBuckets  = append(append([]string(nil), admissionSchemaThreeBuckets...), admissionStorageBuckets...)
	admissionOutboxBuckets      = []string{admissionOutboxBucket, admissionWindowsBucket}
	admissionSchemaFiveBuckets  = append(append([]string(nil), admissionSchemaFourBuckets...), admissionOutboxBuckets...)
	admissionBuckets            = append(append([]string(nil), admissionSchemaFiveBuckets...), admissionEpisodesBucket)
	admissionSchemaKey          = []byte("schema")
	admissionClockKey           = []byte("clock")
	admissionClockPendingKey    = []byte("clock_pending")
	admissionTrackerKey         = []byte("generations")
	admissionInventoryKey       = []byte("inventory")
	admissionAmbiguousKey       = []byte("ambiguous_domains")
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
	// current is set only by a reading this handle recorded. A reopened
	// handle, or one whose last reading was refused, keeps the stored
	// high-water mark but admits nothing new: after a restart that mark can
	// be hours old, and old evidence would read as fresh.
	current bool

	// revalidated is set once this handle has checked every queued
	// candidate at a current reading. A reopened ledger cannot know what
	// changed while it was closed, so its first schedule checks them all.
	revalidated bool

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
// use and upgrading a schema 1 to 5 ledger in the same transaction. The
// registry must be sealed: the set of producers cannot change under a
// running ledger.
func OpenAdmissionLedger(db *DB, reg *admission.Registry) (*AdmissionLedger, error) {
	if db == nil || reg == nil || !reg.Sealed() {
		return nil, errors.New("admission ledger needs a database and a sealed producer registry")
	}
	l := &AdmissionLedger{db: db, reg: reg}
	published := ledgerInventory{}
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		present := func(names []string) (n int) {
			for _, name := range names {
				if tx.Bucket([]byte(name)) != nil {
					n++
				}
			}
			return n
		}
		if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if strings.HasPrefix(string(name), "adm:") && !slices.Contains(admissionBuckets, string(name)) {
				return admission.ErrCorruptRecord
			}
			return nil
		}); err != nil {
			return err
		}
		existing := present(admissionBuckets)
		if existing == 0 {
			for _, name := range admissionBuckets {
				if _, err := tx.CreateBucket([]byte(name)); err != nil {
					return err
				}
			}
			if err := initializeLedgerMeta(tx.Bucket([]byte(admissionMetaBucket))); err != nil {
				return err
			}
			if err := initializeQueueState(tx.Bucket([]byte(admissionQueueStateBucket))); err != nil {
				return err
			}
			if err := putCeilingState(tx, admission.CeilingState{Fill: true}); err != nil {
				return err
			}
			if err := putStorageState(tx, admission.NewStorageState()); err != nil {
				return err
			}
			if err := putFixedNotices(tx); err != nil {
				return err
			}
			if err := startEpisodeSequence(tx); err != nil {
				return err
			}
		} else {
			meta := tx.Bucket([]byte(admissionMetaBucket))
			if meta == nil {
				return admission.ErrCorruptRecord
			}
			switch schema := meta.Get(admissionSchemaKey); {
			case len(schema) == 1 && schema[0] == 1:
				if existing != len(admissionSchemaOneBuckets) || present(admissionSchemaOneBuckets) != existing {
					return admission.ErrCorruptRecord
				}
				if err := upgradeLedgerToSchemaTwo(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaThree(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaFour(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaFive(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaSix(tx); err != nil {
					return err
				}
			case len(schema) == 1 && schema[0] == 2:
				if existing != len(admissionSchemaTwoBuckets) || present(admissionSchemaTwoBuckets) != existing {
					return admission.ErrCorruptRecord
				}
				if err := upgradeLedgerToSchemaThree(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaFour(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaFive(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaSix(tx); err != nil {
					return err
				}
			case len(schema) == 1 && schema[0] == 3:
				if existing != len(admissionSchemaThreeBuckets) || present(admissionSchemaThreeBuckets) != existing {
					return admission.ErrCorruptRecord
				}
				if err := upgradeLedgerToSchemaFour(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaFive(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaSix(tx); err != nil {
					return err
				}
			case len(schema) == 1 && schema[0] == 4:
				if existing != len(admissionSchemaFourBuckets) || present(admissionSchemaFourBuckets) != existing {
					return admission.ErrCorruptRecord
				}
				if err := upgradeLedgerToSchemaFive(tx); err != nil {
					return err
				}
				if err := upgradeLedgerToSchemaSix(tx); err != nil {
					return err
				}
			case len(schema) == 1 && schema[0] == 5:
				if existing != len(admissionSchemaFiveBuckets) || present(admissionSchemaFiveBuckets) != existing {
					return admission.ErrCorruptRecord
				}
				if err := upgradeLedgerToSchemaSix(tx); err != nil {
					return err
				}
			case len(schema) == 1 && schema[0] == admissionSchemaVersion:
				if existing != len(admissionBuckets) {
					return admission.ErrCorruptRecord
				}
			default:
				return ErrAdmissionSchema
			}
		}
		if err := validateStateKeys(tx); err != nil {
			return err
		}
		if _, err := loadQueueState(tx); err != nil {
			return err
		}
		if _, err := loadQueueCounters(tx); err != nil {
			return err
		}
		if _, err := loadScheduleState(tx); err != nil {
			return err
		}
		if _, err := loadIngressState(tx); err != nil {
			return err
		}
		if _, err := loadCeiling(tx); err != nil {
			return err
		}
		if _, err := loadStorage(tx); err != nil {
			return err
		}
		if err := proveEpisodes(tx); err != nil {
			return err
		}
		meta := tx.Bucket([]byte(admissionMetaBucket))
		c, err := loadLedgerClock(meta)
		if err != nil {
			return err
		}
		if err = proveOutcomes(tx, c.Now()); err != nil {
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
// time the other calls use. The same transaction meters the ceiling and the
// history allowances, retires history at its target and drops the outcome
// buckets that have left their windows, so a crash can neither lose nor
// repeat the elapsed time it credits.
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
		if err := meta.Put(admissionClockKey, data); err != nil {
			return err
		}
		if err := meterCeiling(tx, t); err != nil {
			return err
		}
		if err := pruneOutcomes(tx, t.Now); err != nil {
			return err
		}
		return l.meterStorage(tx, t)
	})
	if err != nil {
		l.current = false
		return admission.ClockTick{}, err
	}
	l.now, l.current = tick.Now, true
	return tick, nil
}

// clock is the admission time for calls that admit or dispatch work. It
// needs a reading recorded through this handle.
func (l *AdmissionLedger) clock() (time.Time, error) {
	if !l.current {
		return time.Time{}, refusal(admission.ReasonEngineUnavailable, "admission clock has no current reading")
	}
	return l.now, nil
}

// recordedClock is the stored high-water mark. It is enough to record the
// outcome of work that is already running.
func (l *AdmissionLedger) recordedClock() (time.Time, error) {
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
		gens, err := g.Observe(obs.Accounts, obs.Incarnations)
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
		if err = meta.Put(admissionTrackerKey, tracker); err != nil {
			return err
		}
		if err = meta.Put(admissionInventoryKey, snapshot); err != nil {
			return err
		}
		next = ledgerInventory{inv: inv, ambiguous: obs.AmbiguousDomains}
		if err = meta.Put(admissionAmbiguousKey, strconv.AppendInt(nil, int64(obs.AmbiguousDomains), 10)); err != nil {
			return err
		}
		// Queued candidates whose roots name an account that is no longer
		// current end with the inventory change that retired it.
		q, err := openQueueWith(tx, l.reg, inv, l.now)
		if err != nil {
			return err
		}
		if err = q.checkOwners(); err != nil {
			return err
		}
		return q.flush()
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

// validateStateKeys refuses state from a layout this binary does not know.
// Record decoders separately prove the required values and missing rows.
func validateStateKeys(tx *bolt.Tx) error {
	for _, state := range []struct {
		name string
		keys [][]byte
	}{
		{admissionMetaBucket, [][]byte{admissionSchemaKey, admissionClockKey, admissionClockPendingKey, admissionTrackerKey, admissionInventoryKey, admissionAmbiguousKey}},
		{admissionQueueStateBucket, [][]byte{queueStateKey, queueCountersKey, scheduleStateKey, ingressStateKey, ceilingStateKey, storageStateKey, episodeStateKey}},
	} {
		b := tx.Bucket([]byte(state.name))
		if b == nil {
			continue
		}
		if err := b.ForEach(func(k, v []byte) error {
			if v == nil || !slices.ContainsFunc(state.keys, func(key []byte) bool { return string(key) == string(k) }) {
				return admission.ErrCorruptRecord
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
