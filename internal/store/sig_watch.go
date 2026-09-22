package store

import (
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Persistence helpers for the signature-update watcher. The daemon stores
// what it last saw of each signature file in bbolt so a restart does not
// trigger a phantom rescan -- without this the in-memory map starts empty
// after every restart and every file looks new.

const sigWatchKey = "last_mtimes"

// SignatureFileState is what the watcher last saw of one rules file. SHA256
// is empty when the content was never hashed, and Size is -1 when unknown:
// both hold for entries recorded before content hashes were tracked.
type SignatureFileState struct {
	Mtime  time.Time `json:"mtime"`
	Size   int64     `json:"size"`
	SHA256 string    `json:"sha256,omitempty"`
}

// GetSignatureFiles returns the persisted watcher state. Empty (not nil) when
// nothing has been persisted yet. A map written before content hashes were
// tracked holds bare mtimes; its entries come back with Size -1 and no hash.
func (db *DB) GetSignatureFiles() (map[string]SignatureFileState, error) {
	out := map[string]SignatureFileState{}
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sig_watch"))
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(sigWatchKey))
		if len(raw) == 0 {
			return nil
		}
		if err := json.Unmarshal(raw, &out); err == nil {
			return nil
		}
		var legacy map[string]time.Time
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return err
		}
		out = make(map[string]SignatureFileState, len(legacy))
		for path, mtime := range legacy {
			out[path] = SignatureFileState{Mtime: mtime, Size: -1}
		}
		return nil
	})
	return out, err
}

// PutSignatureFiles overwrites the persisted watcher state. Removed files
// must disappear from the store, so the whole map is replaced.
func (db *DB) PutSignatureFiles(m map[string]SignatureFileState) error {
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sig_watch"))
		if b == nil {
			return errors.New("sig_watch bucket missing (store not migrated)")
		}
		return b.Put([]byte(sigWatchKey), payload)
	})
}
