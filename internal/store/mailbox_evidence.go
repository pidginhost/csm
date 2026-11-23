package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// mailboxEvidenceBucket holds one MailboxEvidence per mailbox, keyed by the
// lower-cased address.
const mailboxEvidenceBucket = "mail:evidence"

// MailboxEvidenceKey folds ASCII case in mailbox addresses. Unicode folding could
// identify an unrelated login as an ASCII mailbox.
func MailboxEvidenceKey(account string) string {
	if !strings.Contains(account, "@") {
		return account
	}
	b := []byte(account)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// MailboxSignal is one kind of compromise evidence seen for a mailbox. Key
// tells repeats of the same evidence (one country, one redirect target)
// apart from new evidence of that kind.
type MailboxSignal struct {
	LastDatedRedirect time.Time `json:"last_dated_redirect,omitzero"`
	Overflow          bool      `json:"overflow,omitempty"`
	Kind              string    `json:"kind"`
	Key               string    `json:"key,omitempty"`
	First             time.Time `json:"first"`
	Last              time.Time `json:"last"`
	Count             int       `json:"count"`
	Detail            string    `json:"detail"`
}

// MailboxEvidence is a mailbox's compromise ledger. ReportedAt marks the
// incident already reported, so the same evidence never reports twice.
// LastNewCountry outlives the signals: a redirect is dated against it.
type MailboxEvidence struct {
	Signals        []MailboxSignal `json:"signals,omitempty"`
	LastNewCountry time.Time       `json:"last_new_country,omitzero"`
	ClearedAt      time.Time       `json:"cleared_at,omitzero"`
	ReportedAt     *time.Time      `json:"reported_at,omitempty"`
	// Sending is handled once a restriction stops the mailbox or sending
	// evidence has had its own response. A withheld login response is not
	// enough, including after a restart.
	SendingHandled bool `json:"sending_handled,omitempty"`
}

func (e MailboxEvidence) empty() bool {
	return len(e.Signals) == 0 && e.LastNewCountry.IsZero() && e.ReportedAt == nil && e.ClearedAt.IsZero()
}

// UpdateMailboxEvidence applies fn to a mailbox's ledger in one write
// transaction and returns the result. An empty result removes the row. An
// unreadable row is an error and fn never runs: damaged evidence must not
// be replaced by a fresh ledger that forgets an open incident.
func (db *DB) UpdateMailboxEvidence(mailbox string, fn func(*MailboxEvidence)) (MailboxEvidence, error) {
	key := []byte(MailboxEvidenceKey(mailbox))
	var e MailboxEvidence
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(mailboxEvidenceBucket))
		if v := b.Get(key); v != nil {
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
		}
		fn(&e)
		if e.empty() {
			return b.Delete(key)
		}
		val, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return b.Put(key, val)
	})
	if err != nil {
		return MailboxEvidence{}, err
	}
	return e, nil
}

// GetMailboxEvidence reads the current ledger after a waiter obtains the
// response lock. Release may have cleared the evidence while it waited.
func (db *DB) GetMailboxEvidence(mailbox string) (MailboxEvidence, error) {
	var e MailboxEvidence
	err := db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(mailboxEvidenceBucket)).Get([]byte(MailboxEvidenceKey(mailbox)))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &e)
	})
	return e, err
}

// PruneMailboxEvidence applies fn to every ledger and removes the ones it
// leaves empty, so a mailbox that never sends again does not keep evidence.
// The walk only collects; bbolt leaves a cursor undefined once its bucket
// is written.
func (db *DB) PruneMailboxEvidence(fn func(mailbox string, e *MailboxEvidence)) error {
	var damaged error
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(mailboxEvidenceBucket))
		var expired [][]byte
		rewritten := map[string][]byte{}
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var e MailboxEvidence
			if err := json.Unmarshal(v, &e); err != nil {
				if damaged == nil {
					damaged = fmt.Errorf("mailbox evidence for %q: %w", k, err)
				}
				continue
			}
			fn(string(k), &e)
			if e.empty() {
				expired = append(expired, append([]byte(nil), k...))
				continue
			}
			val, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if !bytes.Equal(v, val) {
				rewritten[string(k)] = val
			}
		}
		for _, k := range expired {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		for k, val := range rewritten {
			if err := b.Put([]byte(k), val); err != nil {
				return err
			}
		}
		return nil
	})
	return errors.Join(err, damaged)
}
