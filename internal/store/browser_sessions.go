package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/session"
	bolt "go.etcd.io/bbolt"
)

const browserSessionsBucket = "browser_sessions"

func (db *DB) ReplaceBrowserSession(rec session.Record, previous string, now time.Time, idle time.Duration) error {
	if !rec.Valid(now, idle) {
		return session.ErrInvalid
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return boltUpdate(db.bolt, func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(browserSessionsBucket))
		if err != nil {
			return err
		}
		if previous != "" {
			if _, readErr := readBrowserSession(tx, previous, now, idle); readErr != nil {
				return readErr
			}
		}
		c := b.Cursor()
		count := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var old session.Record
			if err := json.Unmarshal(v, &old); err != nil {
				return fmt.Errorf("decode browser session: %w", err)
			}
			if string(k) == previous || !old.Valid(now, idle) {
				if err := c.Delete(); err != nil {
					return err
				}
				continue
			}
			count++
		}
		if count >= session.MaxSessions {
			return session.ErrFull
		}
		if b.Get([]byte(rec.Verifier)) != nil {
			return errors.New("browser session identity collision")
		}
		return b.Put([]byte(rec.Verifier), raw)
	})
}

func readBrowserSession(tx *bolt.Tx, key string, now time.Time, idle time.Duration) (session.Record, error) {
	b := tx.Bucket([]byte(browserSessionsBucket))
	if b == nil {
		return session.Record{}, session.ErrInvalid
	}
	raw := b.Get([]byte(key))
	if raw == nil {
		return session.Record{}, session.ErrInvalid
	}
	var rec session.Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return session.Record{}, fmt.Errorf("decode browser session: %w", err)
	}
	if rec.Verifier != key || !rec.Valid(now, idle) {
		return session.Record{}, session.ErrInvalid
	}
	return rec, nil
}

func (db *DB) AccessBrowserSession(key string, now time.Time, idle time.Duration, touch bool) (session.Record, error) {
	var rec session.Record
	err := db.bolt.View(func(tx *bolt.Tx) error {
		var readErr error
		rec, readErr = readBrowserSession(tx, key, now, idle)
		return readErr
	})
	if err != nil || !touch {
		return rec, err
	}
	// Bound write amplification from dashboard polling. Expiry remains based on
	// the last committed activity, so this can only shorten the idle window.
	interval := min(30*time.Second, idle/4)
	if now.Sub(rec.LastSeen) < interval {
		return rec, nil
	}
	err = boltUpdate(db.bolt, func(tx *bolt.Tx) error {
		current, readErr := readBrowserSession(tx, key, now, idle)
		if readErr != nil {
			return readErr
		}
		current.LastSeen = now
		raw, marshalErr := json.Marshal(current)
		if marshalErr != nil {
			return marshalErr
		}
		if putErr := tx.Bucket([]byte(browserSessionsBucket)).Put([]byte(key), raw); putErr != nil {
			return putErr
		}
		rec = current
		return nil
	})
	if err != nil {
		return session.Record{}, err
	}
	return rec, nil
}

func (db *DB) ListBrowserSessions(now time.Time, idle time.Duration) ([]session.Record, error) {
	records := make([]session.Record, 0)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(browserSessionsBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var rec session.Record
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("decode browser session: %w", err)
			}
			if rec.Verifier != string(k) {
				return errors.New("browser session identity mismatch")
			}
			if rec.Valid(now, idle) {
				records = append(records, rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Created.After(records[j].Created) })
	return records, nil
}

func (db *DB) RevokeBrowserSession(id string) error {
	return boltUpdate(db.bolt, func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(browserSessionsBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec session.Record
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("decode browser session: %w", err)
			}
			if rec.ID == id {
				return c.Delete()
			}
		}
		return nil
	})
}

func (db *DB) ClearBrowserSessions() error {
	return boltUpdate(db.bolt, func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(browserSessionsBucket)) == nil {
			return nil
		}
		return tx.DeleteBucket([]byte(browserSessionsBucket))
	})
}

// DisarmBrowserSessionsSnapshot strips verifiers from a private, stopped
// snapshot. It must never be called on the daemon's live database.
func DisarmBrowserSessionsSnapshot(path string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".session-free-*")
	if err != nil {
		return err
	}
	cleanPath := file.Name()
	defer func() { _ = os.Remove(cleanPath) }()
	if err = file.Close(); err != nil {
		return err
	}
	err = func() (result error) {
		snapshot, openErr := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
		if openErr != nil {
			return openErr
		}
		defer func() { result = errors.Join(result, snapshot.Close()) }()
		db := &DB{bolt: snapshot, path: path}
		if clearErr := db.ClearBrowserSessions(); clearErr != nil {
			return clearErr
		}
		// Compact even if the bucket was already absent: earlier revocations
		// may have left metadata in free pages. Only live records are copied.
		_, _, compactErr := db.CompactInto(cleanPath, 16*1024*1024)
		return compactErr
	}()
	if err != nil {
		return err
	}
	return os.Rename(cleanPath, path)
}
