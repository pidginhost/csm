package store

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// DBObjectBackup is the persisted record of a SHOW CREATE captured
// before a manual `csm db-clean drop-object`. The CREATE SQL is the
// backup -- replaying it restores the object verbatim. Fields are
// public so the future cleanup-history UI can render them without a
// separate API.
type DBObjectBackup struct {
	Account   string    `json:"account"`
	Schema    string    `json:"schema"`
	Kind      string    `json:"kind"` // trigger | event | procedure | function
	Name      string    `json:"name"`
	CreateSQL string    `json:"create_sql"`
	DroppedAt time.Time `json:"dropped_at"`
	DroppedBy string    `json:"dropped_by"` // operator login or "csm" for daemon-driven
	FindingID string    `json:"finding_id,omitempty"`
}

// PutDBObjectBackup writes one backup record. Key shape:
// `<account>:<schema>:<kind>:<name>:<unix_nanos>` so multiple drops of
// the same object name (e.g., re-creates by an attacker) each get
// their own record.
func (db *DB) PutDBObjectBackup(b DBObjectBackup) error {
	if b.Account == "" || b.Schema == "" || b.Kind == "" || b.Name == "" {
		return fmt.Errorf("PutDBObjectBackup: account/schema/kind/name all required")
	}
	if b.DroppedAt.IsZero() {
		b.DroppedAt = time.Now().UTC()
	}
	key := fmt.Sprintf("%s:%s:%s:%s:%d",
		b.Account, b.Schema, b.Kind, b.Name, b.DroppedAt.UnixNano())
	payload, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("marshal backup: %w", err)
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("db_object_backups"))
		if bucket == nil {
			return fmt.Errorf("db_object_backups bucket missing (store not migrated)")
		}
		return bucket.Put([]byte(key), payload)
	})
}

// ListDBObjectBackups returns every record for the given account, in
// insertion order. Used by the CLI's listing path (and by the future
// cleanup-history UI).
func (db *DB) ListDBObjectBackups(account string) ([]DBObjectBackup, error) {
	var out []DBObjectBackup
	prefix := []byte(account + ":")
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("db_object_backups"))
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
			var b DBObjectBackup
			if err := json.Unmarshal(v, &b); err != nil {
				continue
			}
			out = append(out, b)
		}
		return nil
	})
	return out, err
}

// GetDBObjectBackupByKey fetches a single record by its exact bbolt
// key. Returns ok=false (not an error) when the key is missing,
// matching the lookup-then-act flow callers use.
func (db *DB) GetDBObjectBackupByKey(key string) (DBObjectBackup, bool, error) {
	var rec DBObjectBackup
	var found bool
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("db_object_backups"))
		if bucket == nil {
			return nil
		}
		raw := bucket.Get([]byte(key))
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		found = true
		return nil
	})
	return rec, found, err
}

// ListDBObjectBackupsAll returns every record in the bucket,
// regardless of account, in insertion order. Used by the webui
// cleanup-history listing where the operator browses across all
// accounts at once.
func (db *DB) ListDBObjectBackupsAll() ([]DBObjectBackup, []string, error) {
	var records []DBObjectBackup
	var keys []string
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("db_object_backups"))
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var b DBObjectBackup
			// Skip malformed rows silently; returning the unmarshal
			// error from ForEach would abort the entire iteration,
			// which is the wrong choice when one bad row shouldn't
			// hide every other operator's history.
			if json.Unmarshal(v, &b) == nil {
				records = append(records, b)
				keys = append(keys, string(k))
			}
			return nil
		})
	})
	return records, keys, err
}

func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i, c := range prefix {
		if b[i] != c {
			return false
		}
	}
	return true
}
