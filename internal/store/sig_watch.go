package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Persistence helpers for the signature-update watcher. The daemon stores
// what it last saw of each signature file in bbolt so a restart does not
// trigger a phantom rescan -- without this the in-memory map starts empty
// after every restart and every file looks new.

const (
	sigWatchKey  = "last_mtimes"
	sigRescanKey = "rescan"
)

// ErrSignatureRescanCorrupt means the queue cannot establish whether a sweep
// is owed. The watcher repairs it by conservatively queuing a fresh sweep.
var ErrSignatureRescanCorrupt = errors.New("corrupt signature rescan record")

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
	_, err := db.putSignatureFiles(m, false)
	return err
}

// PutSignatureFilesWithRescan writes the watcher state and queues a rescan
// in one transaction, so a restart cannot keep the new rule state while
// losing the rescan it calls for. It returns the generation that only the
// pass covering this queue may clear.
func (db *DB) PutSignatureFilesWithRescan(m map[string]SignatureFileState) (uint64, error) {
	return db.putSignatureFiles(m, true)
}

// signatureRescan is the queued rescan. Generation keeps counting after a
// clear, so a pass can never clear a queue armed after it read its own.
type signatureRescan struct {
	Generation uint64 `json:"generation"`
	Pending    bool   `json:"pending"`
}

func (db *DB) putSignatureFiles(m map[string]SignatureFileState, rescan bool) (uint64, error) {
	payload, marshalErr := json.Marshal(m)
	if marshalErr != nil {
		return 0, marshalErr
	}
	var gen uint64
	update := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sig_watch"))
		if b == nil {
			return errors.New("sig_watch bucket missing (store not migrated)")
		}
		if err := b.Put([]byte(sigWatchKey), payload); err != nil {
			return err
		}
		if !rescan {
			return nil
		}
		q, err := readSignatureRescan(b)
		if err != nil && !errors.Is(err, ErrSignatureRescanCorrupt) {
			return err
		}
		// Keep the generation outside the JSON record too, so repairing it
		// cannot reuse an in-flight sweep's token. The transaction ID also
		// seeds stores written before the bucket sequence was used.
		transactionID := uint64(tx.ID()) // #nosec G115 -- bbolt transaction IDs are positive.
		previous := max(b.Sequence(), q.Generation, transactionID)
		if previous == math.MaxUint64 {
			return errors.New("signature rescan generation exhausted")
		}
		q.Generation = previous + 1
		if err := b.SetSequence(q.Generation); err != nil {
			return err
		}
		q.Pending = true
		gen = q.Generation
		return writeSignatureRescan(b, q)
	}
	if err := db.bolt.Update(update); err != nil {
		return 0, err
	}
	return gen, nil
}

// SignatureRescanPending returns the generation of the queued rescan,
// or 0 when none is queued.
func (db *DB) SignatureRescanPending() (uint64, error) {
	var q signatureRescan
	var sequence uint64
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sig_watch"))
		if b == nil {
			return nil
		}
		var err error
		q, err = readSignatureRescan(b)
		sequence = b.Sequence()
		return err
	})
	if err != nil {
		return 0, err
	}
	// Preserve legacy tokens before handing them to a sweep. Compaction can
	// lower the transaction ID, so it alone cannot fence a repaired queue.
	if q.Generation > sequence {
		if err := db.bolt.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("sig_watch"))
			if b == nil {
				return errors.New("sig_watch bucket missing (store not migrated)")
			}
			return b.SetSequence(max(b.Sequence(), q.Generation))
		}); err != nil {
			return 0, err
		}
	}
	if !q.Pending {
		return 0, nil
	}
	return q.Generation, nil
}

// ClearSignatureRescan removes the queued rescan when gen is still the
// queued generation, and reports whether it did.
func (db *DB) ClearSignatureRescan(gen uint64) (bool, error) {
	cleared := false
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sig_watch"))
		if b == nil {
			return errors.New("sig_watch bucket missing (store not migrated)")
		}
		q, err := readSignatureRescan(b)
		if err != nil || !q.Pending || q.Generation != gen {
			return err
		}
		q.Pending = false
		cleared = true
		return writeSignatureRescan(b, q)
	})
	if err != nil {
		return false, err
	}
	return cleared, nil
}

func readSignatureRescan(b *bolt.Bucket) (signatureRescan, error) {
	raw := b.Get([]byte(sigRescanKey))
	if raw == nil {
		return signatureRescan{}, nil
	}
	var record struct {
		Generation uint64 `json:"generation"`
		Pending    *bool  `json:"pending"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return signatureRescan{}, fmt.Errorf("%w: %v", ErrSignatureRescanCorrupt, err)
	}
	if record.Generation == 0 || record.Pending == nil {
		return signatureRescan{}, ErrSignatureRescanCorrupt
	}
	return signatureRescan{Generation: record.Generation, Pending: *record.Pending}, nil
}

func writeSignatureRescan(b *bolt.Bucket, q signatureRescan) error {
	raw, err := json.Marshal(q)
	if err != nil {
		return err
	}
	return b.Put([]byte(sigRescanKey), raw)
}
