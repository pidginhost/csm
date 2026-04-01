package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket names — all buckets are created on Open().
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
	"plugins",
	"plugins:sites",
	"meta",
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
	if err := os.MkdirAll(statePath, 0755); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}

	bdb, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening bbolt: %w", err)
	}

	// Create all buckets
	err = bdb.Update(func(tx *bolt.Tx) error {
		for _, name := range bucketNames {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("creating bucket %s: %w", name, err)
			}
		}
		return nil
	})
	if err != nil {
		bdb.Close()
		return nil, err
	}

	db := &DB{bolt: bdb, path: dbPath}

	// Run migration if needed
	if err := db.migrateIfNeeded(statePath); err != nil {
		fmt.Fprintf(os.Stderr, "store: migration warning: %v\n", err)
	}

	return db, nil
}

// Close closes the bbolt database.
func (db *DB) Close() error {
	if db.bolt == nil {
		return nil
	}
	return db.bolt.Close()
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
func (db *DB) getCounter(key string) int {
	var count int
	db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		if v := b.Get([]byte(key)); v != nil {
			fmt.Sscanf(string(v), "%d", &count)
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

// incrCounter increments a counter within an existing transaction.
func incrCounter(tx *bolt.Tx, key string, delta int) error {
	b := tx.Bucket([]byte("meta"))
	var current int
	if v := b.Get([]byte(key)); v != nil {
		fmt.Sscanf(string(v), "%d", &current)
	}
	return b.Put([]byte(key), []byte(fmt.Sprintf("%d", current+delta)))
}

// migrateIfNeeded checks for the meta:migrated key and runs migration if absent.
func (db *DB) migrateIfNeeded(statePath string) error {
	var migrated bool
	db.bolt.View(func(tx *bolt.Tx) error {
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

// runMigration is implemented in migrate.go (Task 8).
// This placeholder allows db.go to compile before migrate.go exists.
func (db *DB) runMigration(statePath string) error {
	return nil
}
