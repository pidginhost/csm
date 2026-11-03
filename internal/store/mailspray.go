package store

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

const mailSprayBucket = "mail:spray"

// Key prefixes in mailSprayBucket: one entry per evidence IP, per trusted
// IP, and per corroborated mailbox name.
const (
	mailSprayIPPrefix    = "ip:"
	mailSprayTrustPrefix = "trust:"
	mailSprayNamePrefix  = "name:"
)

// MailSprayFailure is one failed mailbox name of one IP.
type MailSprayFailure struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Count int       `json:"count"`
	Exist uint8     `json:"exist,omitzero"`
}

// MailSprayIP is the persisted failure evidence of one IP.
type MailSprayIP struct {
	Failed          map[string]MailSprayFailure `json:"failed,omitempty"`
	WeakAlerted     map[string]time.Time        `json:"weak_alerted,omitempty"`
	Revoked         map[string]time.Time        `json:"revoked,omitempty"` // cracked mailboxes that cannot earn trust
	Untracked       time.Time                   `json:"untracked,omitzero"`
	SuppressedUntil time.Time                   `json:"suppressed_until,omitzero"`
	CompromiseUntil time.Time                   `json:"compromise_until,omitzero"`
	VerdictAt       time.Time                   `json:"verdict_at,omitzero"`
	LastSeen        time.Time                   `json:"last_seen"`
}

// MailSprayState is the persisted mail login spray memory. Keeping it across
// restarts stops a nightly restart from wiping a week of slow spray evidence
// and the clean-login trust that exempts real users.
type MailSprayState struct {
	IPs      map[string]MailSprayIP               // failure evidence by IP
	Trust    map[string]map[string]GoodSourcePair // clean logins by IP, then mailbox
	Networks map[string]map[string]time.Time      // missing name to the networks that tried it
}

// MailSprayDelta is a change to the persisted spray memory: entries to
// write, keyed as in MailSprayState, and keys to delete.
type MailSprayDelta struct {
	Put         MailSprayState
	DeleteIPs   []string
	DeleteTrust []string
	DeleteNames []string
}

// Empty reports whether the delta changes nothing.
func (d MailSprayDelta) Empty() bool {
	return len(d.Put.IPs)+len(d.Put.Trust)+len(d.Put.Networks)+
		len(d.DeleteIPs)+len(d.DeleteTrust)+len(d.DeleteNames) == 0
}

// SaveMailSpray replaces the persisted spray memory with st. The bucket is
// rewritten in one transaction so entries the detector has dropped do not
// come back at the next load.
func (db *DB) SaveMailSpray(st MailSprayState) error {
	encoded, err := encodeMailSpray(st)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(mailSprayBucket)); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
			return err
		}
		b, err := tx.CreateBucket([]byte(mailSprayBucket))
		if err != nil {
			return err
		}
		return putMailSpray(b, encoded)
	})
}

// ApplyMailSprayDelta writes and deletes only the delta's keys in one
// transaction, leaving the rest of the bucket in place.
func (db *DB) ApplyMailSprayDelta(d MailSprayDelta) error {
	encoded, err := encodeMailSpray(d.Put)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(mailSprayBucket))
		if err != nil {
			return err
		}
		for prefix, keys := range map[string][]string{
			mailSprayIPPrefix:    d.DeleteIPs,
			mailSprayTrustPrefix: d.DeleteTrust,
			mailSprayNamePrefix:  d.DeleteNames,
		} {
			for _, k := range keys {
				if k == "" {
					continue
				}
				if derr := b.Delete([]byte(prefix + k)); derr != nil {
					return derr
				}
			}
		}
		return putMailSpray(b, encoded)
	})
}

func encodeMailSpray(st MailSprayState) (map[string][]byte, error) {
	encoded := make(map[string][]byte, len(st.IPs)+len(st.Trust)+len(st.Networks))
	put := func(prefix, key string, v any) error {
		if key == "" {
			return nil
		}
		val, err := json.Marshal(v)
		if err != nil {
			return err
		}
		encoded[prefix+key] = val
		return nil
	}
	for ip, e := range st.IPs {
		if err := put(mailSprayIPPrefix, ip, e); err != nil {
			return nil, err
		}
	}
	for ip, t := range st.Trust {
		if err := put(mailSprayTrustPrefix, ip, t); err != nil {
			return nil, err
		}
	}
	for name, n := range st.Networks {
		if err := put(mailSprayNamePrefix, name, n); err != nil {
			return nil, err
		}
	}
	return encoded, nil
}

func putMailSpray(b *bolt.Bucket, encoded map[string][]byte) error {
	for k, val := range encoded {
		if err := b.Put([]byte(k), val); err != nil {
			return err
		}
	}
	return nil
}

// LoadMailSpray returns the persisted spray memory, empty when nothing has
// been saved yet. An entry that does not decode is skipped: failing the load
// would start the detector cold on every restart, while skipping loses only
// that entry.
func (db *DB) LoadMailSpray() (MailSprayState, error) {
	st := MailSprayState{
		IPs:      make(map[string]MailSprayIP),
		Trust:    make(map[string]map[string]GoodSourcePair),
		Networks: make(map[string]map[string]time.Time),
	}
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(mailSprayBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			key := string(k)
			if ip, ok := strings.CutPrefix(key, mailSprayIPPrefix); ok && ip != "" {
				var e MailSprayIP
				if json.Unmarshal(v, &e) == nil {
					st.IPs[ip] = e
				}
			} else if ip, ok = strings.CutPrefix(key, mailSprayTrustPrefix); ok && ip != "" {
				var t map[string]GoodSourcePair
				if json.Unmarshal(v, &t) == nil {
					st.Trust[ip] = t
				}
			} else if name, ok := strings.CutPrefix(key, mailSprayNamePrefix); ok && name != "" {
				var n map[string]time.Time
				if json.Unmarshal(v, &n) == nil {
					st.Networks[name] = n
				}
			}
			return nil
		})
	})
	return st, err
}
