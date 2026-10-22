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
	Dirs     map[string]DirIdent  `json:"dirs"`
	Listed   map[string]DirIdent  `json:"listed,omitempty"`
	ListedAt map[string]time.Time `json:"listed_at,omitempty"`
	// PresentAt is when the folder was last opened, refreshed at most
	// daily; a folder absent for SeenRetention is pruned with its entries.
	PresentAt    time.Time `json:"present_at"`
	BaselineDone bool      `json:"baseline_done"`
	Epoch        uint64    `json:"epoch"`
}

// SeenEntry is one message identity of a folder. Sub and Name are where
// the last listing saw it; Attempts and LastAttempt order the retry queue.
type SeenEntry struct {
	Sub         string    `json:"sub,omitempty"`
	Name        string    `json:"name,omitempty"`
	Attempts    int       `json:"attempts,omitempty"`
	Errors      int       `json:"errors,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	Dev         uint64    `json:"dev"`
	Ino         uint64    `json:"ino"`
	Size        int64     `json:"size"`
	MtimeNs     int64     `json:"mtime_ns"`
	CtimeNs     int64     `json:"ctime_ns"`
	Status      string    `json:"status"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	// StableSince tracks the current version, independently of queue age.
	// Ctime changes when a move adds or removes a hard link elsewhere.
	StableSince time.Time `json:"stable_since,omitzero"`
}

func (e *SeenEntry) setMeta(m Meta, now time.Time) {
	if e.StableSince.IsZero() || !e.sameContent(m) {
		e.StableSince = now
	}
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
		// Both Maildir subdirectories belong to this baseline. Forgetting
		// the sibling would make alternating opens restart it forever.
		st.Epoch++
		st.BaselineDone = false
		st.Listed, st.ListedAt = nil, nil
		baseline = true
		// The sibling may already have been listed or skipped this pass.
		// Cancel its old pending work too, before completing this baseline.
		items, e := t.Pending(k)
		if e != nil {
			return false, false, e
		}
		for _, it := range items {
			if e = t.Mark(k, it.Base, StatusBaseline); e != nil {
				return false, false, e
			}
		}
	default:
		baseline = !st.BaselineDone
		unchanged = st.BaselineDone && st.Listed[sub] == id && t.now.Sub(st.ListedAt[sub]) < FullRescanEvery
	}
	if st.Dirs == nil {
		st.Dirs = map[string]DirIdent{}
	}
	st.Dirs[sub] = DirIdent{Dev: id.Dev, Ino: id.Ino}
	st.PresentAt = t.now
	return baseline, unchanged, putJSON(t.tx, store.LearnWatchFoldersBucket, k.key(), st)
}

// Unchanged is Open's unchanged answer without a write: the baseline is
// done, sub has its recorded identity and timestamps since a recent
// complete listing, and the folder's presence was recorded within a day.
// Callers write through Open only when it is false, so a pass over
// unchanged folders writes nothing.
func (t StateTx) Unchanged(k FolderKey, sub string, id DirIdent) (bool, error) {
	st, ok, err := t.Folder(k)
	if err != nil || !ok {
		return false, err
	}
	known, listed := st.Dirs[sub]
	return listed && st.BaselineDone && known.Dev == id.Dev && known.Ino == id.Ino &&
		st.Listed[sub] == id && t.now.Sub(st.ListedAt[sub]) < FullRescanEvery &&
		t.now.Sub(st.PresentAt) < lastSeenRefresh, nil
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
	if st.ListedAt == nil {
		st.ListedAt = map[string]time.Time{}
	}
	st.Listed[sub], st.ListedAt[sub] = id, t.now
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
// Created reports a new entry, which counts against the seen allowance.
func (t StateTx) Observe(k FolderKey, sub, name string, m Meta) (candidate, created bool, err error) {
	base, ok := BaseName(name)
	if !ok {
		return false, false, errors.New("learnwatch: unusable message name")
	}
	st, ok, err := t.Folder(k)
	if err != nil || !ok {
		return false, false, errors.Join(err, errNoFolder)
	}
	e, found, err := t.Seen(k, base)
	if err != nil {
		return false, false, err
	}
	fresh := !found || (e.Sub == sub && e.Name == name && t.now.Sub(e.LastSeen) < lastSeenRefresh)
	switch {
	case found && e.Status == StatusPending && !st.BaselineDone:
		// A new baseline must not replay pending work from the old folder,
		// even when a basename or inode is reused in its initial corpus.
		e = SeenEntry{Status: StatusBaseline, FirstSeen: t.now}
	case found && e.Status == StatusPending && e.Dev == m.Dev && e.Ino == m.Ino:
		if fresh && e.sameContent(m) && !e.StableSince.IsZero() {
			return true, false, nil
		}
	case found && e.Dev == m.Dev && e.Ino == m.Ino:
		if fresh {
			return false, false, nil
		}
	default:
		e = SeenEntry{Status: StatusPending, FirstSeen: t.now}
		if !st.BaselineDone {
			e.Status = StatusBaseline
		}
	}
	e.setMeta(m, t.now)
	e.Sub, e.Name, e.LastSeen = sub, name, t.now
	return e.Status == StatusPending, !found, t.putSeen(k, base, e)
}

// LinkedSettled checks the read snapshot against the last observed version.
// Reads must also refresh it: links outside Spam do not change the watched
// directory, so discovery may have skipped its listing this pass.
func (t StateTx) LinkedSettled(k FolderKey, base string, m Meta) (bool, error) {
	e, found, err := t.Seen(k, base)
	if err != nil || !found {
		return false, errors.Join(err, errors.New("learnwatch: no seen entry to settle"))
	}
	if e.StableSince.IsZero() || !e.sameContent(m) {
		_, _, err = t.Observe(k, e.Sub, e.Name, m)
		return false, err
	}
	return t.now.Sub(e.StableSince) >= PassEvery, nil
}

// Pending index keys sit in the folders bucket after every folder key,
// whose first byte is the high byte of a UID below 2^32; meta keys too.
var (
	cursorKey = []byte("\xfecursor")
	pruneKey  = []byte("\xfeprune")
)

func pendingKey(k FolderKey, base string) []byte {
	return append([]byte{0xff}, seenKey(k, base)...)
}

// putSeen stores e and keeps the pending index in step with its status.
func (t StateTx) putSeen(k FolderKey, base string, e SeenEntry) error {
	if err := putJSON(t.tx, store.LearnWatchSeenBucket, seenKey(k, base), e); err != nil {
		return err
	}
	if e.Status == StatusPending {
		return t.tx.Put(store.LearnWatchFoldersBucket, pendingKey(k, base), []byte{1})
	}
	return t.tx.Delete(store.LearnWatchFoldersBucket, pendingKey(k, base))
}

// Mark sets an existing entry's status.
func (t StateTx) Mark(k FolderKey, base, status string) error {
	e, found, err := t.Seen(k, base)
	if err != nil || !found {
		return errors.Join(err, errors.New("learnwatch: no seen entry to mark"))
	}
	e.Status = status
	return t.putSeen(k, base, e)
}

// Retry records a failed attempt on a pending entry: it moves to the tail
// of the retry queue.
func (t StateTx) Retry(k FolderKey, base string) error {
	e, found, err := t.Seen(k, base)
	if err != nil || !found {
		return errors.Join(err, errors.New("learnwatch: no seen entry to retry"))
	}
	e.Attempts++
	e.LastAttempt = t.now
	return t.putSeen(k, base, e)
}

// Fail records a failed submission. After MaxEntryErrors failures the
// entry becomes skipped:failed and gaveUp is true; otherwise it moves to the
// tail of the retry queue.
func (t StateTx) Fail(k FolderKey, base string) (gaveUp bool, err error) {
	e, found, err := t.Seen(k, base)
	if err != nil || !found {
		return false, errors.Join(err, errors.New("learnwatch: no seen entry to fail"))
	}
	e.Attempts++
	e.Errors++
	e.LastAttempt = t.now
	if e.Errors >= MaxEntryErrors {
		e.Status = SkippedStatus(SkipFailed)
		gaveUp = true
	}
	return gaveUp, t.putSeen(k, base, e)
}

// Forget drops an entry, as for a vanished message.
func (t StateTx) Forget(k FolderKey, base string) error {
	if err := t.tx.Delete(store.LearnWatchSeenBucket, seenKey(k, base)); err != nil {
		return err
	}
	return t.tx.Delete(store.LearnWatchFoldersBucket, pendingKey(k, base))
}

// PendingItem is a pending entry with its base name.
type PendingItem struct {
	Base string
	SeenEntry
}

// Pending lists k's pending entries in base-name order.
func (t StateTx) Pending(k FolderKey) ([]PendingItem, error) {
	prefix := pendingKey(k, "")
	var bases []string
	err := t.tx.Scan(store.LearnWatchFoldersBucket, prefix[:len(prefix)-1], func(key, _ []byte) (bool, error) {
		if !bytes.HasPrefix(key, prefix) {
			return false, nil
		}
		bases = append(bases, string(key[len(prefix):]))
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	items := make([]PendingItem, 0, len(bases))
	for _, base := range bases {
		e, found, err := t.Seen(k, base)
		if err != nil {
			return nil, err
		}
		if found && e.Status == StatusPending {
			items = append(items, PendingItem{Base: base, SeenEntry: e})
		}
	}
	return items, nil
}

// CountSeen counts uid's seen entries, the measure of its allowance.
func (t StateTx) CountSeen(uid int) (int, error) {
	n := 0
	prefix := append(uidPrefix(uid), 0)
	err := t.tx.Scan(store.LearnWatchSeenBucket, prefix[:len(prefix)-1], func(k, _ []byte) (bool, error) {
		if !bytes.HasPrefix(k, prefix) {
			return false, nil
		}
		n++
		return true, nil
	})
	return n, err
}

// HasState reports whether uid has any folder record.
func (t StateTx) HasState(uid int) (bool, error) {
	has := false
	prefix := append(uidPrefix(uid), 0)
	err := t.tx.Scan(store.LearnWatchFoldersBucket, prefix[:len(prefix)-1], func(k, _ []byte) (bool, error) {
		has = bytes.HasPrefix(k, prefix)
		return false, nil
	})
	return has, err
}

// Cursor is the UID the next pass starts at; zero starts at the lowest.
func (t StateTx) Cursor() (int, error) {
	raw, err := t.tx.Get(store.LearnWatchFoldersBucket, cursorKey)
	if err != nil || len(raw) != 8 {
		return 0, err
	}
	// #nosec G115 -- stored by SetCursor from a positive UID
	return int(binary.BigEndian.Uint64(raw)), nil
}

// SetCursor persists the rotation cursor.
func (t StateTx) SetCursor(uid int) error {
	return t.tx.Put(store.LearnWatchFoldersBucket, cursorKey, uidPrefix(uid))
}

// LastPrune is when seen entries were last pruned.
func (t StateTx) LastPrune() (time.Time, error) {
	v, _, err := getJSON[time.Time](t.tx, store.LearnWatchFoldersBucket, pruneKey)
	return v, err
}

// SetLastPrune records a prune.
func (t StateTx) SetLastPrune(at time.Time) error {
	return putJSON(t.tx, store.LearnWatchFoldersBucket, pruneKey, at)
}

// Prune drops entries absent for SeenRetention from folders whose presence
// checks completed this pass. Pending entries are never pruned.
func (t StateTx) Prune(folders []FolderKey) (int, error) {
	var stale [][]byte
	for _, folder := range folders {
		prefix := seenKey(folder, "")
		err := t.tx.Scan(store.LearnWatchSeenBucket, folder.key(), func(k, v []byte) (bool, error) {
			if !bytes.HasPrefix(k, prefix) {
				return false, nil
			}
			var e SeenEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return false, err
			}
			if e.Status != StatusPending && t.now.Sub(e.LastSeen) > SeenRetention {
				stale = append(stale, bytes.Clone(k))
			}
			return true, nil
		})
		if err != nil {
			return 0, err
		}
	}
	for _, k := range stale {
		if err := t.tx.Delete(store.LearnWatchSeenBucket, k); err != nil {
			return 0, err
		}
	}
	return len(stale), nil
}

// PruneAbsentFolders drops folders not opened for SeenRetention, such as
// deleted mailboxes and accounts, with every seen and pending entry: they
// can never be served and would hold the account's allowance. Failed or
// incomplete inventories cannot establish absence and keep their state.
func (t StateTx) PruneAbsentFolders(uncheckedAccounts []int, unreadableFolders []FolderKey) (int, error) {
	accounts := make(map[string]bool, len(uncheckedAccounts))
	for _, uid := range uncheckedAccounts {
		accounts[string(uidPrefix(uid))] = true
	}
	folders := make(map[string]bool, len(unreadableFolders))
	for _, k := range unreadableFolders {
		folders[string(k.key())] = true
	}
	var stale [][]byte
	undated := map[string]FolderState{}
	err := t.tx.ForEach(store.LearnWatchFoldersBucket, func(k, v []byte) error {
		if len(k) == 0 || k[0] == 0xfe || k[0] == 0xff {
			return nil
		}
		if (len(k) >= 8 && accounts[string(k[:8])]) || folders[string(k)] {
			return nil
		}
		var st FolderState
		if err := json.Unmarshal(v, &st); err != nil {
			return err
		}
		// Older state has no presence timestamp. Start its retention clock
		// here instead of treating the zero time as proven absence.
		if st.PresentAt.IsZero() {
			st.PresentAt = t.now
			undated[string(k)] = st
			return nil
		}
		if t.now.Sub(st.PresentAt) > SeenRetention {
			stale = append(stale, bytes.Clone(k))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for k, st := range undated {
		if err = putJSON(t.tx, store.LearnWatchFoldersBucket, []byte(k), st); err != nil {
			return 0, err
		}
	}
	for _, k := range stale {
		if err = t.tx.Delete(store.LearnWatchFoldersBucket, k); err != nil {
			return 0, err
		}
		if err = t.deletePrefix(store.LearnWatchSeenBucket, append(bytes.Clone(k), 0)); err != nil {
			return 0, err
		}
		if err = t.deletePrefix(store.LearnWatchFoldersBucket, append(append([]byte{0xff}, k...), 0)); err != nil {
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
	return t.deletePrefix(store.LearnWatchFoldersBucket, append(append([]byte{0xff}, uidPrefix(uid)...), 0))
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
