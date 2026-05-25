package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// prefsBucket holds per-operator preference blobs:
//   - "<opkey>:user"            -> user settings JSON (density, timezone, etc.)
//   - "<opkey>:views:<page>"    -> saved filter views JSON
//   - "<opkey>:table:<tableID>" -> per-table column visibility JSON
//   - "<opkey>:undo:<seq>"      -> bulk-action undo entry (sequence is
//     big-endian uint64 of unix nano, so prefix iteration is chronological)
//
// opkey is a SHA-256 hex of the operator's auth token, computed at request
// time by the webui layer. The store never sees the token itself.
const prefsBucket = "prefs:operator"

// MaxPrefBlobSize caps the size of any single preference blob. Large enough
// for saved views with dozens of params, small enough to keep abuse bounded.
const MaxPrefBlobSize = 64 * 1024

// MaxUndoEntries caps how many undo entries one operator may have queued at
// once. Older entries fall out as new ones are recorded.
const MaxUndoEntries = 32

// UndoTTL is how long an undo entry remains valid. Matches the banner timeout
// the UI advertises so an operator can never undo an action whose banner has
// already disappeared.
const UndoTTL = 30 * time.Second

// ErrPrefBlobTooLarge is returned when a preference blob exceeds MaxPrefBlobSize.
var ErrPrefBlobTooLarge = errors.New("preference blob too large")

func prefsKey(opkey, ns string) []byte {
	return []byte(opkey + ":" + ns)
}

func undoKey(opkey string, seq uint64) []byte {
	out := make([]byte, 0, len(opkey)+6+8)
	out = append(out, opkey...)
	out = append(out, ':', 'u', 'n', 'd', 'o', ':')
	var seqBE [8]byte
	binary.BigEndian.PutUint64(seqBE[:], seq)
	return append(out, seqBE[:]...)
}

func undoKeyPrefix(opkey string) []byte {
	return []byte(opkey + ":undo:")
}

// GetOperatorPref returns the raw JSON blob stored at (opkey, ns). Returns
// nil with nil error when no entry exists.
func (db *DB) GetOperatorPref(opkey, ns string) ([]byte, error) {
	if db == nil || db.bolt == nil {
		return nil, errors.New("store unavailable")
	}
	if opkey == "" || ns == "" {
		return nil, errors.New("opkey and namespace required")
	}
	var out []byte
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b, err := bucketOrCreate(tx, prefsBucket)
		if err != nil {
			return err
		}
		v := b.Get(prefsKey(opkey, ns))
		if v == nil {
			return nil
		}
		// Bolt invalidates the slice after the tx ends; copy out.
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

// PutOperatorPref writes the JSON blob to (opkey, ns). Rejects payloads above
// MaxPrefBlobSize.
func (db *DB) PutOperatorPref(opkey, ns string, data []byte) error {
	if db == nil || db.bolt == nil {
		return errors.New("store unavailable")
	}
	if opkey == "" || ns == "" {
		return errors.New("opkey and namespace required")
	}
	if len(data) > MaxPrefBlobSize {
		return ErrPrefBlobTooLarge
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := bucketOrCreate(tx, prefsBucket)
		if err != nil {
			return err
		}
		return b.Put(prefsKey(opkey, ns), data)
	})
}

// DeleteOperatorPref removes the blob at (opkey, ns). No error if absent.
func (db *DB) DeleteOperatorPref(opkey, ns string) error {
	if db == nil || db.bolt == nil {
		return errors.New("store unavailable")
	}
	if opkey == "" || ns == "" {
		return errors.New("opkey and namespace required")
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := bucketOrCreate(tx, prefsBucket)
		if err != nil {
			return err
		}
		return b.Delete(prefsKey(opkey, ns))
	})
}

// UndoEntry is one record in the bulk-action undo queue.
type UndoEntry struct {
	ID         string    `json:"id"`          // matches the seq encoded in the bbolt key
	RecordedAt time.Time `json:"recorded_at"` // wall time the entry was written
	Action     string    `json:"action"`      // e.g. "threat_bulk_block"
	Inverse    string    `json:"inverse"`     // inverse action key the runner will dispatch
	Payload    []byte    `json:"payload"`     // opaque JSON the runner understands
	Summary    string    `json:"summary"`     // human-readable label for the banner
}

// AppendUndoEntry queues an undo entry for opkey. The entry's ID and
// RecordedAt are filled in. Prunes expired entries and trims the queue to
// MaxUndoEntries before writing. Returns the saved entry.
func (db *DB) AppendUndoEntry(opkey string, e UndoEntry) (UndoEntry, error) {
	if db == nil || db.bolt == nil {
		return UndoEntry{}, errors.New("store unavailable")
	}
	if opkey == "" {
		return UndoEntry{}, errors.New("opkey required")
	}
	if e.Inverse == "" {
		return UndoEntry{}, errors.New("inverse action required")
	}
	now := time.Now().UTC()
	seq := uint64(now.UnixNano())
	e.ID = fmt.Sprintf("%016x", seq)
	e.RecordedAt = now
	raw, err := encodeUndoEntry(e)
	if err != nil {
		return UndoEntry{}, err
	}
	if len(raw) > MaxPrefBlobSize {
		return UndoEntry{}, ErrPrefBlobTooLarge
	}
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		b, berr := bucketOrCreate(tx, prefsBucket)
		if berr != nil {
			return berr
		}
		if perr := pruneOperatorUndo(b, opkey, now); perr != nil {
			return perr
		}
		return b.Put(undoKey(opkey, seq), raw)
	})
	if err != nil {
		return UndoEntry{}, err
	}
	return e, nil
}

// LatestUndoEntry returns the most recent non-expired undo entry for opkey,
// or (zero, false, nil) if none exists.
func (db *DB) LatestUndoEntry(opkey string) (UndoEntry, bool, error) {
	if db == nil || db.bolt == nil {
		return UndoEntry{}, false, errors.New("store unavailable")
	}
	if opkey == "" {
		return UndoEntry{}, false, errors.New("opkey required")
	}
	now := time.Now().UTC()
	var entry UndoEntry
	var found bool
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(prefsBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		prefix := undoKeyPrefix(opkey)
		// Seek to first key strictly greater than the prefix, then walk
		// backwards. Newest entries sort last because the suffix is the
		// big-endian nano timestamp.
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if !bytes.HasPrefix(k, prefix) {
				if bytes.Compare(k, prefix) < 0 {
					return nil
				}
				continue
			}
			e, err := decodeUndoEntry(v)
			if err != nil {
				continue
			}
			if now.Sub(e.RecordedAt) > UndoTTL {
				return nil
			}
			entry = e
			found = true
			return nil
		}
		return nil
	})
	return entry, found, err
}

// ConsumeUndoEntry removes the entry identified by id from opkey's queue and
// returns the decoded value. Returns (zero, false, nil) if the entry has
// already expired or never existed.
func (db *DB) ConsumeUndoEntry(opkey, id string) (UndoEntry, bool, error) {
	if db == nil || db.bolt == nil {
		return UndoEntry{}, false, errors.New("store unavailable")
	}
	if opkey == "" || id == "" {
		return UndoEntry{}, false, errors.New("opkey and id required")
	}
	now := time.Now().UTC()
	var entry UndoEntry
	var found bool
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := bucketOrCreate(tx, prefsBucket)
		if err != nil {
			return err
		}
		if perr := pruneOperatorUndo(b, opkey, now); perr != nil {
			return perr
		}
		c := b.Cursor()
		prefix := undoKeyPrefix(opkey)
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			e, derr := decodeUndoEntry(v)
			if derr != nil {
				continue
			}
			if e.ID != id {
				continue
			}
			if now.Sub(e.RecordedAt) > UndoTTL {
				return b.Delete(k)
			}
			entry = e
			found = true
			return b.Delete(k)
		}
		return nil
	})
	return entry, found, err
}

// PurgeOperatorUndo drops every undo entry for opkey (used when an operator
// logs out or when tests need to reset state).
func (db *DB) PurgeOperatorUndo(opkey string) error {
	if db == nil || db.bolt == nil {
		return errors.New("store unavailable")
	}
	if opkey == "" {
		return errors.New("opkey required")
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(prefsBucket))
		if b == nil {
			return nil
		}
		var keys [][]byte
		prefix := undoKeyPrefix(opkey)
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			keys = append(keys, append([]byte(nil), k...))
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// pruneOperatorUndo drops expired entries and trims the queue to
// MaxUndoEntries. Must run inside a writable transaction.
func pruneOperatorUndo(b *bolt.Bucket, opkey string, now time.Time) error {
	prefix := undoKeyPrefix(opkey)
	type kv struct {
		key   []byte
		entry UndoEntry
	}
	var kept []kv
	var expired [][]byte
	c := b.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		e, err := decodeUndoEntry(v)
		if err != nil {
			expired = append(expired, append([]byte(nil), k...))
			continue
		}
		if now.Sub(e.RecordedAt) > UndoTTL {
			expired = append(expired, append([]byte(nil), k...))
			continue
		}
		kept = append(kept, kv{key: append([]byte(nil), k...), entry: e})
	}
	for _, k := range expired {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	// kept is already in chronological order because keys sort by big-endian
	// nano suffix. Trim oldest first.
	if len(kept) >= MaxUndoEntries {
		drop := len(kept) - MaxUndoEntries + 1
		for i := 0; i < drop; i++ {
			if err := b.Delete(kept[i].key); err != nil {
				return err
			}
		}
	}
	return nil
}

func bucketOrCreate(tx *bolt.Tx, name string) (*bolt.Bucket, error) {
	if tx.Writable() {
		return tx.CreateBucketIfNotExists([]byte(name))
	}
	if b := tx.Bucket([]byte(name)); b != nil {
		return b, nil
	}
	return nil, fmt.Errorf("bucket %s not initialised", name)
}
