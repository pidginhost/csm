package store

import (
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

const spamSourceBucket = "mail:spam_source"

// SpamSource is the persisted spam source tracker state for one IP. Keeping it
// across restarts stops a daemon restart from resetting the reject occasions,
// the clean-mail window and the report throttle.
type SpamSource struct {
	Occasions   []time.Time `json:"occasions,omitempty"` // counted reject occasions, oldest first
	LastClean   time.Time   `json:"last_clean,omitzero"`
	LastFinding time.Time   `json:"last_finding,omitzero"`
	Seen        time.Time   `json:"seen"`
}

// SaveSpamSources replaces the persisted tracker state with m. The bucket is
// rewritten in one transaction so IPs the tracker has dropped do not come back
// at the next load.
func (db *DB) SaveSpamSources(m map[string]SpamSource) error {
	encoded := make(map[string][]byte, len(m))
	for ip, src := range m {
		if ip == "" {
			continue
		}
		val, err := json.Marshal(src)
		if err != nil {
			return err
		}
		encoded[ip] = val
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(spamSourceBucket)); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
			return err
		}
		b, err := tx.CreateBucket([]byte(spamSourceBucket))
		if err != nil {
			return err
		}
		for ip, val := range encoded {
			if perr := b.Put([]byte(ip), val); perr != nil {
				return perr
			}
		}
		return nil
	})
}

// LoadSpamSources returns the persisted tracker state keyed by IP, or an empty
// map when nothing has been saved yet.
func (db *DB) LoadSpamSources() (map[string]SpamSource, error) {
	out := make(map[string]SpamSource)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(spamSourceBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var src SpamSource
			if json.Unmarshal(v, &src) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			out[string(k)] = src
			return nil
		})
	})
	return out, err
}
