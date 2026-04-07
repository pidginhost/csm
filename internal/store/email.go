package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// GeoHistory tracks the countries from which a mailbox has logged in.
type GeoHistory struct {
	Countries  map[string]int64 `json:"countries"`
	LoginCount int              `json:"login_count"`
}

// SetGeoHistory stores geo login history for a mailbox in the email:geo bucket.
func (db *DB) SetGeoHistory(mailbox string, h GeoHistory) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("email:geo"))
		val, err := json.Marshal(h)
		if err != nil {
			return err
		}
		return b.Put([]byte(mailbox), val)
	})
}

// GetGeoHistory retrieves geo login history for a mailbox.
// Returns the entry and true if found, or a zero value and false if not.
func (db *DB) GetGeoHistory(mailbox string) (GeoHistory, bool) {
	var h GeoHistory
	var found bool

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("email:geo"))
		v := b.Get([]byte(mailbox))
		if v == nil {
			return nil
		}
		if json.Unmarshal(v, &h) != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		found = true
		return nil
	})

	return h, found
}

// SetForwarderHash stores a forwarder config hash in the email:fwd bucket.
func (db *DB) SetForwarderHash(key, hash string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("email:fwd"))
		return b.Put([]byte(key), []byte(hash))
	})
}

// GetForwarderHash retrieves a forwarder config hash.
// Returns the hash and true if found, or an empty string and false if not.
func (db *DB) GetForwarderHash(key string) (string, bool) {
	var hash string
	var found bool

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("email:fwd"))
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		hash = string(v)
		found = true
		return nil
	})

	return hash, found
}

// GetEmailPWLastRefresh reads the last email password-check refresh timestamp
// from the meta bucket. Returns the zero time if not set.
func (db *DB) GetEmailPWLastRefresh() time.Time {
	var t time.Time

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		v := b.Get([]byte("email:pw_last_refresh"))
		if v == nil {
			return nil
		}
		parsed, err := time.Parse(time.RFC3339, string(v))
		if err != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		t = parsed
		return nil
	})

	return t
}

// SetEmailPWLastRefresh writes the email password-check refresh timestamp
// to the meta bucket.
func (db *DB) SetEmailPWLastRefresh(t time.Time) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		return b.Put([]byte("email:pw_last_refresh"), []byte(t.Format(time.RFC3339)))
	})
}

// GetMetaString reads a string value from the meta bucket.
// Returns an empty string if the key is not found.
func (db *DB) GetMetaString(key string) string {
	var val string

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		val = string(v)
		return nil
	})

	return val
}

// SetMetaString writes a string value to the meta bucket.
func (db *DB) SetMetaString(key, val string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		return b.Put([]byte(key), []byte(val))
	})
}
