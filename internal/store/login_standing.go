package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// loginStandingBucket maps an address and mailbox to the trusted logins
// that give the address standing on that mailbox.
const loginStandingBucket = "mail:login_standing"

// maxLoginStandingRecords bounds a load: the daemon's index and as many
// again waiting for deletion.
const maxLoginStandingRecords = 200000

// A key names one address and one bounded mailbox name, and a value holds a
// few timestamps. Anything larger is damage and is not decoded.
const (
	maxLoginStandingKeyBytes   = 320
	maxLoginStandingValueBytes = 1024
)

// LoginStanding is one address's trusted logins to one mailbox, in Unix
// seconds: the first, and the earliest and latest of each recent UTC date.
// When Lasts is absent, each date has only its recorded earliest success.
type LoginStanding struct {
	First int64   `json:"first"`
	Days  []int64 `json:"days"`
	Lasts []int64 `json:"lasts,omitempty"`
}

// SaveLoginStanding writes upserts and removes deletes in one transaction.
// replace empties the bucket first, so it then holds exactly upserts.
func (db *DB) SaveLoginStanding(upserts map[string]LoginStanding, deletes []string, replace bool) error {
	if len(upserts)+len(deletes) == 0 && !replace {
		return nil
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		if replace {
			if err := tx.DeleteBucket([]byte(loginStandingBucket)); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
				return err
			}
		}
		b, err := tx.CreateBucketIfNotExists([]byte(loginStandingBucket))
		if err != nil {
			return err
		}
		for _, key := range deletes {
			if key == "" {
				continue
			}
			if err := b.Delete([]byte(key)); err != nil {
				return err
			}
		}
		// bbolt appends keys written in order; random order makes a rewrite
		// of a large bucket split pages over and over.
		for _, key := range slices.Sorted(maps.Keys(upserts)) {
			if key == "" {
				continue
			}
			val, err := json.Marshal(upserts[key])
			if err != nil {
				return err
			}
			if err := b.Put([]byte(key), val); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadLoginStanding returns at most maxLoginStandingRecords readable
// records. Validating keys and times is the caller's job. Malformed,
// oversized and surplus records are deleted, so the bucket stays bounded;
// the records are still returned when that deletion fails.
func (db *DB) LoadLoginStanding() (map[string]LoginStanding, error) {
	out := make(map[string]LoginStanding)
	// Keep selection and pruning in the same transaction so a concurrent
	// save cannot replace a rejected row before we delete it. Prune in
	// place rather than retaining an unbounded list of rejected keys.
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(loginStandingBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; {
			if len(out) < maxLoginStandingRecords {
				if row, ok := decodeLoginStanding(k, v); ok {
					out[string(k)] = row
					k, v = c.Next()
					continue
				}
			}
			key := bytes.Clone(k)
			if v == nil {
				if err := b.DeleteBucket(key); err != nil {
					return err
				}
			} else if err := c.Delete(); err != nil {
				return err
			}
			// Deletion shifts the cursor; seek to avoid skipping its successor.
			k, v = c.Seek(key)
		}
		return nil
	})
	return out, err
}

// decodeLoginStanding reads one record, refusing one too large to be ours.
func decodeLoginStanding(k, v []byte) (LoginStanding, bool) {
	var row LoginStanding
	if len(k) > maxLoginStandingKeyBytes || len(v) > maxLoginStandingValueBytes {
		return row, false
	}
	return row, json.Unmarshal(v, &row) == nil
}

// DisarmLoginStandingSnapshot removes login standing from a stopped, private
// bbolt snapshot. Standing is earned from live logins: a backup restored
// later or on another host must not excuse failures with it. It must never
// be called on the daemon's live database.
func DisarmLoginStandingSnapshot(path string) error {
	if err := verifySnapshot(path); err != nil {
		return err
	}
	snapshot, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("opening state snapshot: %w", err)
	}
	held := false
	if err = snapshot.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte(loginStandingBucket)); b != nil {
			k, _ := b.Cursor().First()
			held = k != nil
		}
		return nil
	}); err != nil {
		_ = snapshot.Close()
		return fmt.Errorf("checking login standing snapshot: %w", err)
	}
	if err = snapshot.Close(); err != nil {
		return fmt.Errorf("closing state snapshot: %w", err)
	}
	// Even opening writable can persist a missing freelist and rewrite
	// metadata. Only reopen for writing when standing must be removed.
	if !held {
		return nil
	}
	snapshot, err = bolt.Open(path, 0o600, nil)
	if err != nil {
		return fmt.Errorf("opening state snapshot for disarming: %w", err)
	}
	if err = snapshot.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte(loginStandingBucket))
	}); err != nil {
		_ = snapshot.Close()
		return fmt.Errorf("disarming login standing snapshot: %w", err)
	}
	if err = snapshot.Close(); err != nil {
		return fmt.Errorf("closing state snapshot: %w", err)
	}
	return nil
}
