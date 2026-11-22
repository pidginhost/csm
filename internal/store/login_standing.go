package store

import (
	"encoding/json"
	"errors"
	"fmt"

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
// seconds: the first, and the earliest of each recent UTC date.
type LoginStanding struct {
	First int64   `json:"first"`
	Days  []int64 `json:"days"`
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
		for key, row := range upserts {
			if key == "" {
				continue
			}
			val, err := json.Marshal(row)
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
	var drop [][]byte
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(loginStandingBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			row, ok := decodeLoginStanding(k, v)
			if !ok || len(out) >= maxLoginStandingRecords {
				drop = append(drop, append([]byte(nil), k...))
				return nil
			}
			out[string(k)] = row
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if len(drop) > 0 {
		err = db.bolt.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(loginStandingBucket))
			for _, k := range drop {
				if derr := b.Delete(k); derr != nil {
					return derr
				}
			}
			return nil
		})
	}
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
	snapshot, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return fmt.Errorf("opening state snapshot: %w", err)
	}
	held := false
	if err := snapshot.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte(loginStandingBucket)); b != nil {
			k, _ := b.Cursor().First()
			held = k != nil
		}
		return nil
	}); err != nil {
		_ = snapshot.Close()
		return fmt.Errorf("checking login standing snapshot: %w", err)
	}
	// A write transaction rewrites metadata: leave a clean snapshot as it is.
	if !held {
		if err := snapshot.Close(); err != nil {
			return fmt.Errorf("closing state snapshot: %w", err)
		}
		return nil
	}
	if err := snapshot.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte(loginStandingBucket))
	}); err != nil {
		_ = snapshot.Close()
		return fmt.Errorf("disarming login standing snapshot: %w", err)
	}
	if err := snapshot.Close(); err != nil {
		return fmt.Errorf("closing state snapshot: %w", err)
	}
	return nil
}
