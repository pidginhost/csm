package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket names - all buckets are created on Open().
var bucketNames = []string{
	"history",
	"attacks:records",
	"attacks:events",
	"attacks:events:ip",
	"threats",
	"threats:whitelist",
	"fw:blocked",
	"fw:allowed",
	"fw:subnets",
	"fw:port_allowed",
	"reputation",
	mailGoodSourceBucket,
	"plugins",
	"plugins:sites",
	"meta",
	"email:geo",
	"email:fwd",
	"db_object_backups",
	"sig_watch",
	bucketStatsDaily,
	"phprelay:meta",
	"phprelay:msgindex",
	"phprelay:ignore",
	"phprelay:settings",
	"incidents",
	"fw:rollback",
	adminEmailsBucket,
	"botverify",
	prefsBucket,
	"scan_jobs",
	"scan_job_findings",
	scanCursorBucket,
}

// DB wraps a bbolt database.
type DB struct {
	bolt *bolt.DB
	path string
}

var (
	globalDB   *DB
	globalMu   sync.Mutex
	ensureOnce sync.Once
	ensureErr  error
)

// Global returns the singleton DB instance.
func Global() *DB {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalDB
}

// SetGlobal sets the singleton DB instance.
func SetGlobal(db *DB) {
	globalMu.Lock()
	globalDB = db
	globalMu.Unlock()
}

// WriteTxID returns the id of the most recently committed write
// transaction. bbolt bumps the id once per committed write transaction,
// so two readings bracket a code path and their difference counts its
// write commits.
func (db *DB) WriteTxID() int {
	var id int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		id = tx.ID()
		return nil
	})
	return id
}

// EnsureOpen opens the store if not already open. Safe to call from any CLI path.
// First call opens the DB; subsequent calls return immediately.
func EnsureOpen(statePath string) error {
	ensureOnce.Do(func() {
		db, err := Open(statePath)
		if err != nil {
			ensureErr = err
			return
		}
		SetGlobal(db)
	})
	return ensureErr
}

// Open opens or creates the bbolt database at {statePath}/csm.db.
// Creates all buckets if they don't exist. Runs migration if needed.
func Open(statePath string) (*DB, error) {
	dbPath := filepath.Join(statePath, "csm.db")
	if err := os.MkdirAll(statePath, 0700); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}

	bdb, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening bbolt: %w", err)
	}

	// Create all buckets
	err = bdb.Update(func(tx *bolt.Tx) error {
		for _, name := range bucketNames {
			if _, berr := tx.CreateBucketIfNotExists([]byte(name)); berr != nil {
				return fmt.Errorf("creating bucket %s: %w", name, berr)
			}
		}
		// Initialise phprelay schema_version on first open. Stored as
		// 8-byte big-endian uint64 so future migrations can read/compare
		// it consistently.
		meta := tx.Bucket([]byte("phprelay:meta"))
		if meta.Get([]byte("schema_version")) == nil {
			if perr := meta.Put([]byte("schema_version"), []byte{0, 0, 0, 0, 0, 0, 0, 1}); perr != nil {
				return fmt.Errorf("init phprelay schema_version: %w", perr)
			}
		}
		return nil
	})
	if err != nil {
		_ = bdb.Close()
		return nil, err
	}

	db := &DB{bolt: bdb, path: dbPath}

	// Run migration if needed. A failed migration does not set the "migrated"
	// sentinel, so proceeding would boot the daemon on partial security state
	// and retry the same broken migration every restart. Fail loud instead.
	if err := db.migrateIfNeeded(statePath); err != nil {
		_ = bdb.Close()
		return nil, fmt.Errorf("store migration: %w", err)
	}

	// One-time backfill of stats:daily from existing history. Runs on
	// hosts upgrading from a build that pre-dates the stats:daily bucket;
	// no-op afterwards thanks to a meta sentinel.
	if err := db.BackfillStatsDaily(); err != nil {
		fmt.Fprintf(os.Stderr, "store: stats:daily backfill warning: %v\n", err)
	}

	if err := db.seedDefaultModSecNoEscalateRules(); err != nil {
		fmt.Fprintf(os.Stderr, "store: ModSecurity no-escalate seed warning: %v\n", err)
	}

	return db, nil
}

const (
	modsecNoEscalateSeededKey              = "modsec:no_escalate_seeded"
	defaultModSecNoEscalateWPEnumerationID = 900112
)

func (db *DB) seedDefaultModSecNoEscalateRules() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if meta.Get([]byte(modsecNoEscalateSeededKey)) != nil {
			return nil
		}
		if meta.Get([]byte(modsecNoEscalateKey)) != nil {
			return meta.Put([]byte(modsecNoEscalateSeededKey), []byte("1"))
		}
		// WordPress user enumeration is blocked at the HTTP layer only.
		val, err := json.Marshal([]int{defaultModSecNoEscalateWPEnumerationID})
		if err != nil {
			return err
		}
		if err := meta.Put([]byte(modsecNoEscalateKey), val); err != nil {
			return err
		}
		return meta.Put([]byte(modsecNoEscalateSeededKey), []byte("1"))
	})
}

// Close closes the bbolt database.
func (db *DB) Close() error {
	if db.bolt == nil {
		return nil
	}
	return db.bolt.Close()
}

// Path returns the on-disk path of the bbolt database file.
func (db *DB) Path() string {
	return db.path
}

// HasBucket reports whether a top-level bucket named name exists in db.
func (db *DB) HasBucket(name string) bool {
	found := false
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(name)) != nil {
			found = true
		}
		return nil
	})
	return found
}

// TimeKey produces a fixed-width 28-byte key for chronological ordering.
// Format: YYYYMMDDHHmmssNNNNNNNNN-CCCC
// Lexicographic order equals chronological order.
func TimeKey(t time.Time, counter int) string {
	return fmt.Sprintf("%04d%02d%02d%02d%02d%02d%09d-%04d",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(),
		t.Nanosecond(), counter)
}

// ParseTimeKeyPrefix converts a date string "YYYY-MM-DD" to a seek prefix "YYYYMMDD".
func ParseTimeKeyPrefix(date string) string {
	if len(date) == 10 && date[4] == '-' && date[7] == '-' {
		return date[:4] + date[5:7] + date[8:10]
	}
	return date
}

// getCounter reads a counter from the meta bucket. Returns 0 if not found.
// HistoryCount returns the number of findings in the history bucket.
func (db *DB) HistoryCount() int {
	return db.getCounter("history:count")
}

func (db *DB) getCounter(key string) int {
	var count int
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		if v := b.Get([]byte(key)); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
		}
		return nil
	})
	return count
}

// setCounter writes a counter to the meta bucket within an existing transaction.
func setCounter(tx *bolt.Tx, key string, count int) error {
	b := tx.Bucket([]byte("meta"))
	return b.Put([]byte(key), []byte(fmt.Sprintf("%d", count)))
}

// IsHealthy returns true if the bbolt file is open and all required buckets exist.
func (db *DB) IsHealthy() bool {
	if db == nil || db.bolt == nil {
		return false
	}
	err := db.bolt.View(func(tx *bolt.Tx) error {
		for _, name := range []string{"history", "fw:blocked", "meta"} {
			if tx.Bucket([]byte(name)) == nil {
				return fmt.Errorf("bucket missing: %s", name)
			}
		}
		return nil
	})
	return err == nil
}

// SizeBytes returns the on-disk size of the bbolt database file. Returns 0 if unavailable.
func (db *DB) SizeBytes() int64 {
	if db == nil || db.path == "" {
		return 0
	}
	info, err := os.Stat(db.path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// incrCounter increments a counter within an existing transaction.
func incrCounter(tx *bolt.Tx, key string, delta int) error {
	b := tx.Bucket([]byte("meta"))
	var current int
	if v := b.Get([]byte(key)); v != nil {
		fmt.Sscanf(string(v), "%d", &current)
	}
	return b.Put([]byte(key), []byte(fmt.Sprintf("%d", current+delta)))
}

type dryRunBlockRecord struct {
	IP         string `json:"ip"`
	Reason     string `json:"reason"`
	TimeoutSec int    `json:"timeout_sec"`
}

// RecordDryRunBlock appends a dry-run-block record to the "dry_run_blocks"
// bucket. Called by the firewall engine when auto_response.dry_run is active
// so operators can review "what would have been blocked" before going live.
func (db *DB) RecordDryRunBlock(ip, reason string, timeout time.Duration) {
	if db == nil || db.bolt == nil {
		return
	}
	// Log-derived reasons can carry raw control bytes; the JSON encoder
	// emits escape forms that dry-run readers can decode.
	payload := dryRunBlockRecord{
		IP:         ip,
		Reason:     reason,
		TimeoutSec: int(timeout.Seconds()),
	}
	val, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("dry_run_blocks"))
		if err != nil {
			return err
		}
		key := []byte(time.Now().UTC().Format(time.RFC3339Nano) + ":" + ip)
		return b.Put(key, val)
	})
}

// PurgeAllDryRunBlocks deletes every record from the dry_run_blocks
// bucket and returns the number removed. Called when the operator
// flips auto_response.dry_run from true to false so /api/v1/status no
// longer reports a stale count from the previous dry-run window. A
// later periodic prune handles the slow accumulation case via
// PurgeDryRunBlocksOlderThan.
func (db *DB) PurgeAllDryRunBlocks() int {
	if db == nil || db.bolt == nil {
		return 0
	}
	removed := 0
	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("dry_run_blocks"))
		if b == nil {
			return nil
		}
		removed = b.Stats().KeyN
		return tx.DeleteBucket([]byte("dry_run_blocks"))
	})
	return removed
}

// PurgeDryRunBlocksOlderThan removes every dry_run_blocks record
// whose timestamp prefix is strictly older than cutoff. Returns the
// number removed. Key format is "<RFC3339Nano>:<ip>"; entries with a
// key that does not parse as a timestamp are left in place so a
// future key-format change does not silently drop records.
func (db *DB) PurgeDryRunBlocksOlderThan(cutoff time.Time) int {
	if db == nil || db.bolt == nil {
		return 0
	}
	removed := 0
	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("dry_run_blocks"))
		if b == nil {
			return nil
		}
		var stale [][]byte
		_ = b.ForEach(func(k, _ []byte) error {
			s := string(k)
			// RecordDryRunBlock writes UTC timestamps which always
			// end in `Z`, so the first `Z:` reliably separates the
			// timestamp from the IP (the IP itself can contain
			// colons in v6 form, ruling out a naive first-colon
			// split).
			idx := strings.Index(s, "Z:")
			if idx < 0 {
				return nil
			}
			ts, err := time.Parse(time.RFC3339Nano, s[:idx+1])
			if err != nil {
				// Forward-compat: unrecognised key format is left
				// in place rather than treated as stale, so a
				// future schema change does not silently drop
				// records during the rolling upgrade window.
				return nil //nolint:nilerr // intentional skip
			}
			if ts.Before(cutoff) {
				keyCopy := append([]byte(nil), k...)
				stale = append(stale, keyCopy)
			}
			return nil
		})
		for _, k := range stale {
			if err := b.Delete(k); err == nil {
				removed++
			}
		}
		return nil
	})
	return removed
}

// DryRunBlocksCount returns the number of recorded dry-run block entries.
func (db *DB) DryRunBlocksCount() int {
	if db == nil || db.bolt == nil {
		return 0
	}
	count := 0
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte("dry_run_blocks")); b != nil {
			count = b.Stats().KeyN
		}
		return nil
	})
	return count
}

// migrateIfNeeded checks for the meta:migrated key and runs migration if absent.
func (db *DB) migrateIfNeeded(statePath string) error {
	var migrated bool
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		if b.Get([]byte("migrated")) != nil {
			migrated = true
		}
		return nil
	})
	if migrated {
		return nil
	}
	return db.runMigration(statePath)
}
