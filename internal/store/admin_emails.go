package store

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// AdminEmailEntry records that a given email was observed as a WordPress
// administrator on (Account, Schema). One email may carry multiple
// entries when the same person administers several customer sites --
// surfacing that overlap is the whole point of the bucket.
type AdminEmailEntry struct {
	Account  string    `json:"account"`
	Schema   string    `json:"schema"`
	LastSeen time.Time `json:"last_seen"`
}

const adminEmailsBucket = "admin:emails"

// RecordAdminEmail upserts an observation that `email` is administrator
// on (account, schema) at `now`. Re-recording the same triple updates
// LastSeen without creating a duplicate row; recording the same email
// across a different (account, schema) appends to the owner list. The
// email is lowercased before storage so case-mismatched recordings
// collapse to a single key.
func (db *DB) RecordAdminEmail(email, account, schema string, now time.Time) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || account == "" {
		return nil
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(adminEmailsBucket))
		var entries []AdminEmailEntry
		if v := b.Get([]byte(email)); v != nil {
			if err := json.Unmarshal(v, &entries); err != nil {
				// Corrupt entry: restart the list rather than fail the
				// whole write -- we'd rather lose one stale observation
				// than block detection on a malformed payload.
				entries = nil
			}
		}
		updated := false
		for i := range entries {
			if entries[i].Account == account && entries[i].Schema == schema {
				entries[i].LastSeen = now
				updated = true
				break
			}
		}
		if !updated {
			entries = append(entries, AdminEmailEntry{
				Account:  account,
				Schema:   schema,
				LastSeen: now,
			})
		}
		payload, err := json.Marshal(entries)
		if err != nil {
			return err
		}
		return b.Put([]byte(email), payload)
	})
}

// AdminEmailOwners returns the full list of (account, schema, last_seen)
// triples recorded for `email`. Returns an empty slice when the email
// is unknown.
func (db *DB) AdminEmailOwners(email string) ([]AdminEmailEntry, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var out []AdminEmailEntry
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(adminEmailsBucket))
		v := b.Get([]byte(email))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &out)
	})
	return out, err
}

// OverlappingAdminEmails returns every email whose owner list has at
// least `minAccounts` distinct accounts after stale entries (older than
// `retention`) are pruned.
//
// `minAccounts` smaller than 2 is clamped to 2 because a single-account
// observation is never an overlap by definition.
func (db *DB) OverlappingAdminEmails(minAccounts int, retention time.Duration) (map[string][]AdminEmailEntry, error) {
	if minAccounts < 2 {
		minAccounts = 2
	}
	cutoff := time.Now().Add(-retention)
	out := map[string][]AdminEmailEntry{}
	type pruneItem struct {
		key      []byte
		original []byte
		fresh    []byte
	}
	var toPrune []pruneItem
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(adminEmailsBucket))
		return b.ForEach(func(k, v []byte) error {
			var entries []AdminEmailEntry
			if err := json.Unmarshal(v, &entries); err != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			fresh := entries[:0]
			seen := map[string]struct{}{}
			for _, e := range entries {
				if e.LastSeen.Before(cutoff) {
					continue
				}
				key := e.Account + "|" + e.Schema
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				fresh = append(fresh, e)
			}
			distinct := map[string]struct{}{}
			for _, e := range fresh {
				distinct[e.Account] = struct{}{}
			}
			if len(distinct) >= minAccounts {
				out[string(k)] = append([]AdminEmailEntry(nil), fresh...)
			}
			if len(fresh) == 0 {
				toPrune = append(toPrune, pruneItem{key: append([]byte(nil), k...), original: append([]byte(nil), v...)})
			} else if len(fresh) != len(entries) {
				payload, err := json.Marshal(fresh)
				if err != nil {
					return err
				}
				toPrune = append(toPrune, pruneItem{
					key:      append([]byte(nil), k...),
					original: append([]byte(nil), v...),
					fresh:    payload,
				})
			}
			return nil
		})
	})
	if err != nil || len(toPrune) == 0 {
		return out, err
	}
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(adminEmailsBucket))
		for _, item := range toPrune {
			if !bytes.Equal(b.Get(item.key), item.original) {
				continue
			}
			if len(item.fresh) == 0 {
				if deleteErr := b.Delete(item.key); deleteErr != nil {
					return deleteErr
				}
				continue
			}
			if putErr := b.Put(item.key, item.fresh); putErr != nil {
				return putErr
			}
		}
		return nil
	})
	return out, err
}
