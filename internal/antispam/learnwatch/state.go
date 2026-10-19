package learnwatch

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// SeenRetention keeps entries absent from their folder this long (spec
// 7.2); lastSeenRefresh bounds presence writes to one per entry per day.
const (
	SeenRetention   = 90 * 24 * time.Hour
	lastSeenRefresh = 24 * time.Hour
)

// Seen statuses. A skip is "skipped:<reason>".
const (
	StatusBaseline  = "baseline"
	StatusPending   = "pending"
	StatusSubmitted = "submitted"
)

// SkippedStatus is the terminal status for reason.
func SkippedStatus(reason string) string { return "skipped:" + reason }

var errNoFolder = errors.New("learnwatch: folder has no state; open it first")

// FolderKey names one observed folder of one mailbox; its new and cur
// subdirectories share the seen identities.
type FolderKey struct {
	UID                 int
	Domain, Box, Folder string
}

func uidPrefix(uid int) []byte {
	// #nosec G115 -- account UIDs are positive and below 2^32
	return binary.BigEndian.AppendUint64(nil, uint64(uid))
}

// Names never contain NUL, so the separators keep keys unambiguous.
func (k FolderKey) key() []byte {
	b := append(uidPrefix(k.UID), 0)
	b = append(append(b, k.Domain...), 0)
	b = append(append(b, k.Box...), 0)
	return append(b, k.Folder...)
}

func seenKey(k FolderKey, base string) []byte {
	return append(append(k.key(), 0), base...)
}

// DirIdent is a subdirectory's identity and timestamps.
type DirIdent struct {
	Dev, Ino         uint64
	MtimeNs, CtimeNs int64
}

// FolderState is one folder's baseline. Listed holds each subdirectory's
// identity as of its last complete enumeration; Dirs its current one.
type FolderState struct {
	Dirs         map[string]DirIdent `json:"dirs"`
	Listed       map[string]DirIdent `json:"listed,omitempty"`
	BaselineDone bool                `json:"baseline_done"`
	Epoch        uint64              `json:"epoch"`
}

// SeenEntry is one message identity of a folder.
type SeenEntry struct {
	Dev       uint64    `json:"dev"`
	Ino       uint64    `json:"ino"`
	Size      int64     `json:"size"`
	MtimeNs   int64     `json:"mtime_ns"`
	CtimeNs   int64     `json:"ctime_ns"`
	Status    string    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

func (e *SeenEntry) setMeta(m Meta) {
	e.Dev, e.Ino, e.Size, e.MtimeNs, e.CtimeNs = m.Dev, m.Ino, m.Size, m.MtimeNs, m.CtimeNs
}

func (e SeenEntry) sameContent(m Meta) bool {
	return e.Dev == m.Dev && e.Ino == m.Ino && e.Size == m.Size && e.MtimeNs == m.MtimeNs && e.CtimeNs == m.CtimeNs
}

type kv interface {
	LearnUpdate(func(store.LearnTx) error) error
	LearnView(func(store.LearnTx) error) error
}

// State is the watcher's persisted folder and seen state.
type State struct {
	db  kv
	now func() time.Time
}

// NewState returns the state over db; now reads the clock.
func NewState(db kv, now func() time.Time) *State {
	if now == nil {
		now = time.Now
	}
	return &State{db: db, now: now}
}

// Update runs fn in one write transaction; callers batch a discovery chunk.
func (s *State) Update(fn func(StateTx) error) error {
	now := s.now()
	return s.db.LearnUpdate(func(tx store.LearnTx) error { return fn(StateTx{tx: tx, now: now}) })
}

// View runs fn in one read transaction.
func (s *State) View(fn func(StateTx) error) error {
	now := s.now()
	return s.db.LearnView(func(tx store.LearnTx) error { return fn(StateTx{tx: tx, now: now}) })
}

// StateTx is one transaction over the watcher state.
type StateTx struct {
	tx  store.LearnTx
	now time.Time
}

func getJSON[T any](tx store.LearnTx, bucket string, key []byte) (T, bool, error) {
	var v T
	raw, err := tx.Get(bucket, key)
	if err != nil || raw == nil {
		return v, false, err
	}
	return v, true, json.Unmarshal(raw, &v)
}

func putJSON(tx store.LearnTx, bucket string, key []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Put(bucket, key, raw)
}

// Folder returns k's state.
func (t StateTx) Folder(k FolderKey) (FolderState, bool, error) {
	return getJSON[FolderState](t.tx, store.LearnWatchFoldersBucket, k.key())
}

// Open records sub's current identity. A folder without state, a new
// subdirectory or a replaced one (device or inode changed) starts a new
// baseline. Unchanged means the baseline is done and sub has not changed
// since its last complete enumeration.
func (t StateTx) Open(k FolderKey, sub string, id DirIdent) (baseline, unchanged bool, err error) {
	st, ok, err := t.Folder(k)
	if err != nil {
		return false, false, err
	}
	prev, known := st.Dirs[sub]
	switch {
	case !ok:
		st = FolderState{Epoch: 1}
		baseline = true
	case !known || prev.Dev != id.Dev || prev.Ino != id.Ino:
		st = FolderState{Epoch: st.Epoch + 1}
		baseline = true
	default:
		baseline = !st.BaselineDone
		unchanged = st.BaselineDone && st.Listed[sub] == id
	}
	if st.Dirs == nil {
		st.Dirs = map[string]DirIdent{}
	}
	st.Dirs[sub] = DirIdent{Dev: id.Dev, Ino: id.Ino}
	return baseline, unchanged, putJSON(t.tx, store.LearnWatchFoldersBucket, k.key(), st)
}

// Listed records a complete enumeration of sub at identity id.
func (t StateTx) Listed(k FolderKey, sub string, id DirIdent) error {
	st, ok, err := t.Folder(k)
	if err != nil || !ok {
		return errors.Join(err, errNoFolder)
	}
	if cur := st.Dirs[sub]; cur.Dev != id.Dev || cur.Ino != id.Ino {
		return nil
	}
	if st.Listed == nil {
		st.Listed = map[string]DirIdent{}
	}
	st.Listed[sub] = id
	return putJSON(t.tx, store.LearnWatchFoldersBucket, k.key(), st)
}

// FinishBaseline marks the observation boundary: later new identities are
// candidates.
func (t StateTx) FinishBaseline(k FolderKey) error {
	st, ok, err := t.Folder(k)
	if err != nil || !ok {
		return errors.Join(err, errNoFolder)
	}
	st.BaselineDone = true
	return putJSON(t.tx, store.LearnWatchFoldersBucket, k.key(), st)
}

// Seen returns the entry for base.
func (t StateTx) Seen(k FolderKey, base string) (SeenEntry, bool, error) {
	return getJSON[SeenEntry](t.tx, store.LearnWatchSeenBucket, seenKey(k, base))
}

// Observe records a listed message and reports whether it is a candidate:
// a new identity after the baseline, a different inode under a seen name,
// or an entry still pending. An edit to a seen inode is not a candidate.
func (t StateTx) Observe(k FolderKey, base string, m Meta) (bool, error) {
	st, ok, err := t.Folder(k)
	if err != nil || !ok {
		return false, errors.Join(err, errNoFolder)
	}
	key := seenKey(k, base)
	e, found, err := t.Seen(k, base)
	if err != nil {
		return false, err
	}
	switch {
	case found && e.Status == StatusPending:
		if e.sameContent(m) && t.now.Sub(e.LastSeen) < lastSeenRefresh {
			return true, nil
		}
		e.setMeta(m)
		e.LastSeen = t.now
		return true, putJSON(t.tx, store.LearnWatchSeenBucket, key, e)
	case found && e.Dev == m.Dev && e.Ino == m.Ino:
		if t.now.Sub(e.LastSeen) < lastSeenRefresh {
			return false, nil
		}
		e.LastSeen = t.now
		return false, putJSON(t.tx, store.LearnWatchSeenBucket, key, e)
	}
	e = SeenEntry{Status: StatusPending, FirstSeen: t.now, LastSeen: t.now}
	if !st.BaselineDone {
		e.Status = StatusBaseline
	}
	e.setMeta(m)
	return e.Status == StatusPending, putJSON(t.tx, store.LearnWatchSeenBucket, key, e)
}

// Mark sets an existing entry's status.
func (t StateTx) Mark(k FolderKey, base, status string) error {
	e, found, err := t.Seen(k, base)
	if err != nil || !found {
		return errors.Join(err, errors.New("learnwatch: no seen entry to mark"))
	}
	e.Status = status
	return putJSON(t.tx, store.LearnWatchSeenBucket, seenKey(k, base), e)
}

// Forget drops an entry, as for a vanished message.
func (t StateTx) Forget(k FolderKey, base string) error {
	return t.tx.Delete(store.LearnWatchSeenBucket, seenKey(k, base))
}

// Prune drops entries absent from their folder for SeenRetention. Pending
// entries are never pruned.
func (t StateTx) Prune() (int, error) {
	var stale [][]byte
	err := t.tx.ForEach(store.LearnWatchSeenBucket, func(k, v []byte) error {
		var e SeenEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		if e.Status != StatusPending && t.now.Sub(e.LastSeen) > SeenRetention {
			stale = append(stale, bytes.Clone(k))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, k := range stale {
		if err := t.tx.Delete(store.LearnWatchSeenBucket, k); err != nil {
			return 0, err
		}
	}
	return len(stale), nil
}

// ResetOnOptOut drops every folder and seen record of uid: unsent work is
// cancelled and re-entry starts new baselines. Contribution guards live in
// the learning ledger and are untouched.
func (t StateTx) ResetOnOptOut(uid int) error {
	for _, bucket := range store.WatchBuckets {
		if err := t.deletePrefix(bucket, append(uidPrefix(uid), 0)); err != nil {
			return err
		}
	}
	return nil
}

func (t StateTx) deletePrefix(bucket string, prefix []byte) error {
	var keys [][]byte
	err := t.tx.Scan(bucket, prefix[:len(prefix)-1], func(k, _ []byte) (bool, error) {
		if !bytes.HasPrefix(k, prefix) {
			return false, nil
		}
		keys = append(keys, bytes.Clone(k))
		return true, nil
	})
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := t.tx.Delete(bucket, k); err != nil {
			return err
		}
	}
	return nil
}
