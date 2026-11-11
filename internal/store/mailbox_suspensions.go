package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Suspension kinds and the parts a mail server applied.
const (
	SuspensionKindMailbox = "mailbox" // one mailbox's logins and/or outgoing mail
	SuspensionKindAccount = "account" // a hosting account's outgoing mail hold

	AppliedSuspendLogin    = "suspend_login"
	AppliedSuspendOutgoing = "suspend_outgoing"
	AppliedHoldOutgoing    = "hold_outgoing"
)

const mailboxSuspensionsBucket = "mail:suspensions"

// mailboxSuspensionRetention keeps a released row visible for context before
// the next write prunes it.
const mailboxSuspensionRetention = 30 * 24 * time.Hour

// ErrMailboxSuspensionNotFound reports an ID with no stored suspension.
var ErrMailboxSuspensionNotFound = errors.New("mailbox suspension not found")

// MailboxSuspension records one suspension CSM made, so it can be listed and
// released. Subject is the identity the trigger named: a mailbox, a bare
// hosting account, or a domain whose owner was held.
type MailboxSuspension struct {
	ID          string     `json:"id"`
	Backend     string     `json:"backend"`
	Subject     string     `json:"subject"`
	Kind        string     `json:"kind"`
	Account     string     `json:"account,omitempty"`
	Applied     []string   `json:"applied"`
	Check       string     `json:"check"`
	Reason      string     `json:"reason"`
	SuspendedAt time.Time  `json:"suspended_at"`
	ReleasedAt  *time.Time `json:"released_at,omitempty"`
	ReleasedBy  string     `json:"released_by,omitempty"`
}

// MailboxSuspensionID is the stable key of a subject on one mail server.
// Mail identities compare case-insensitively.
func MailboxSuspensionID(backend, subject string) string {
	sum := sha256.Sum256([]byte(backend + "\x00" + strings.ToLower(subject)))
	return hex.EncodeToString(sum[:8])
}

// PutMailboxSuspension upserts s by its ID and prunes released rows older
// than the retention period.
func (db *DB) PutMailboxSuspension(s MailboxSuspension) error {
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-mailboxSuspensionRetention)
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(mailboxSuspensionsBucket))
		var stale [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var old MailboxSuspension
			if json.Unmarshal(v, &old) == nil && old.ReleasedAt != nil && old.ReleasedAt.Before(cutoff) {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return b.Put([]byte(s.ID), payload)
	})
}

// GetMailboxSuspension returns the suspension stored under id.
func (db *DB) GetMailboxSuspension(id string) (MailboxSuspension, bool, error) {
	var s MailboxSuspension
	var found bool
	err := db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(mailboxSuspensionsBucket)).Get([]byte(id))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &s)
	})
	return s, found, err
}

// ListMailboxSuspensions returns every stored suspension, newest first.
func (db *DB) ListMailboxSuspensions() ([]MailboxSuspension, error) {
	var out []MailboxSuspension
	err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(mailboxSuspensionsBucket)).ForEach(func(k, v []byte) error {
			var s MailboxSuspension
			if err := json.Unmarshal(v, &s); err != nil {
				return fmt.Errorf("mailbox suspension %s: %w", k, err)
			}
			out = append(out, s)
			return nil
		})
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].SuspendedAt.After(out[j].SuspendedAt) })
	return out, err
}

// MarkMailboxSuspensionReleased stamps the release time and who released it.
func (db *DB) MarkMailboxSuspensionReleased(id string, at time.Time, by string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(mailboxSuspensionsBucket))
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrMailboxSuspensionNotFound, id)
		}
		var s MailboxSuspension
		if err := json.Unmarshal(v, &s); err != nil {
			return err
		}
		s.ReleasedAt, s.ReleasedBy = &at, by
		payload, err := json.Marshal(s)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), payload)
	})
}
