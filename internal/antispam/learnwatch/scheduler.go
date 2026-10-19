package learnwatch

import (
	"cmp"
	"context"
	"errors"
	"io"
	"io/fs"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/antispam/learn"
)

// Scheduler constants (spec 7.5). Provisional until the benchmarks of
// plan Task 11 measure them.
const (
	PassEvery            = 5 * time.Minute
	PassDeadline         = 4 * time.Minute
	MaxAttempts          = 20
	DiscoveryChunk       = 512
	AccountSeenAllowance = 65536
	FullRescanEvery      = 24 * time.Hour
	pruneEvery           = 24 * time.Hour
)

// Pass skip reasons beyond the registry, eligibility and discovery ones.
const (
	SkipHomeUnavailable    = "home_unavailable"
	SkipOptInUnreadable    = "optin_unreadable"
	SkipFolderUnreadable   = "folder_unreadable"
	SkipRegistryUnreadable = "registry_unreadable"
)

type submitter interface {
	Submit(context.Context, learn.Candidate) (learn.Outcome, error)
}

// WatcherConfig is what a watcher needs. Zero Chunk and SeenAllowance mean
// the constants; nil CanSubmit always submits.
type WatcherConfig struct {
	Source     Source
	GlobalPath string
	State      *State
	Engine     submitter
	Now        func() time.Time
	// CanDiscover false makes passes idle: nothing is listed or read.
	// CanSubmit false keeps discovery and baselines but reads no message
	// content and submits nothing.
	CanDiscover func() bool
	CanSubmit   func() bool
	// OnPass sees every completed pass, not idle or busy ones.
	OnPass        func(PassReport)
	Chunk         int
	SeenAllowance int
}

// PassReport summarizes one pass. Skipped counts reasons, never names.
// Pending counts the reports known to wait; with Unfinished set some
// folders were not enumerated, so it is a lower bound.
type PassReport struct {
	Accounts  int
	Submitted int
	// Committed counts the cluster contributions the engine committed.
	Committed     int
	Pending       int
	Skipped       map[string]int
	Unfinished    bool
	Busy          bool
	OldestPending time.Time
}

// ownerUID is the UID an account's files must belong to. Tests map their
// synthetic accounts to the test process's own UID.
var ownerUID = func(a Account) int { return a.UID }

// turnHook observes scheduling for tests: kinds turn, chunk, attempt and
// submit.
var turnHook = func(uid int, kind string) {}

// Watcher runs Spam folder passes, one at a time.
type Watcher struct {
	cfg  WatcherConfig
	busy atomic.Bool

	mu   sync.Mutex
	last PassReport
	at   time.Time
}

// NewWatcher fills defaults; nil gates are open.
func NewWatcher(cfg WatcherConfig) *Watcher {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CanDiscover == nil {
		cfg.CanDiscover = func() bool { return true }
	}
	if cfg.CanSubmit == nil {
		cfg.CanSubmit = func() bool { return true }
	}
	if cfg.Chunk <= 0 {
		cfg.Chunk = DiscoveryChunk
	}
	if cfg.SeenAllowance <= 0 {
		cfg.SeenAllowance = AccountSeenAllowance
	}
	if cfg.GlobalPath == "" {
		cfg.GlobalPath = GlobalOptInPath
	}
	return &Watcher{cfg: cfg}
}

// Run passes every PassEvery until ctx ends, starting with one now.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(PassEvery)
	defer t.Stop()
	for {
		w.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Last returns the last completed pass report and when it ended.
func (w *Watcher) Last() (PassReport, time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last, w.at
}

// Pass runs one rotation-fair pass. A concurrent call returns Busy; a
// closed discovery gate makes it idle and unrecorded.
func (w *Watcher) Pass(ctx context.Context) PassReport {
	if !w.busy.CompareAndSwap(false, true) {
		return PassReport{Busy: true}
	}
	defer w.busy.Store(false)
	if !w.cfg.CanDiscover() {
		return PassReport{}
	}
	ctx, cancel := context.WithTimeout(ctx, PassDeadline)
	defer cancel()
	r := w.pass(ctx)
	w.mu.Lock()
	w.last, w.at = r, w.cfg.Now()
	w.mu.Unlock()
	if w.cfg.OnPass != nil {
		w.cfg.OnPass(r)
	}
	return r
}

func (w *Watcher) pass(ctx context.Context) PassReport {
	r := PassReport{Skipped: map[string]int{}}
	deadline := w.cfg.Now().Add(PassDeadline)
	accounts, skips, err := Accounts(w.cfg.Source)
	if err != nil {
		r.Skipped[SkipRegistryUnreadable]++
		r.Unfinished = true
		return r
	}
	for _, s := range skips {
		r.Skipped[s.Reason]++
	}
	global, err := GlobalOptIn(w.cfg.GlobalPath)
	if err != nil {
		r.Skipped[SkipOptInUnreadable]++
		r.Unfinished = true
		return r
	}
	slices.SortFunc(accounts, func(a, b Account) int { return cmp.Compare(a.UID, b.UID) })
	var cursor int
	if err = w.cfg.State.View(func(tx StateTx) (e error) { cursor, e = tx.Cursor(); return e }); err != nil {
		r.Unfinished = true
		return r
	}
	start, _ := slices.BinarySearchFunc(accounts, cursor, func(a Account, uid int) int { return cmp.Compare(a.UID, uid) })
	accounts = append(accounts[start:], accounts[:start]...)
	runs := make([]*accountRun, 0, len(accounts))
	for _, a := range accounts {
		runs = append(runs, &accountRun{w: w, a: a, global: global})
	}
	defer func() {
		for _, run := range runs {
			run.close()
		}
	}()
	for active := runs; len(active) > 0; {
		next := active[:0]
		for _, run := range active {
			if ctx.Err() != nil || !w.cfg.Now().Before(deadline) {
				r.Unfinished = true
				w.saveCursor(run.a.UID)
				w.tally(runs, &r)
				return r
			}
			turnHook(run.a.UID, "turn")
			run.turn(ctx, &r)
			if run.done {
				run.close()
			} else {
				next = append(next, run)
			}
		}
		active = next
	}
	w.saveCursor(0)
	w.tally(runs, &r)
	w.prune()
	return r
}

func (w *Watcher) saveCursor(uid int) {
	_ = w.cfg.State.Update(func(tx StateTx) error { return tx.SetCursor(uid) })
}

func (w *Watcher) prune() {
	_ = w.cfg.State.Update(func(tx StateTx) error {
		last, err := tx.LastPrune()
		if err != nil || tx.now.Sub(last) < pruneEvery {
			return err
		}
		if _, err = tx.Prune(); err != nil {
			return err
		}
		return tx.SetLastPrune(tx.now)
	})
}

// tally adds every run's waiting reports; a run cut short leaves folders
// unenumerated, which Unfinished reports.
func (w *Watcher) tally(runs []*accountRun, r *PassReport) {
	for _, run := range runs {
		for _, q := range run.queues {
			for _, items := range [][]PendingItem{q.fresh, q.retry, q.waiting} {
				for _, it := range items {
					r.Pending++
					if r.OldestPending.IsZero() || it.FirstSeen.Before(r.OldestPending) {
						r.OldestPending = it.FirstSeen
					}
				}
			}
		}
		if !run.done {
			r.Unfinished = true
		}
	}
}

type folderQueue struct {
	key                   FolderKey
	fresh, retry, waiting []PendingItem
}

// accountRun is one account's progress through a pass: discovery walks its
// folders one chunk per turn; candidates alternate fresh and retry queues
// across folders, one attempt per turn, MaxAttempts per pass.
type accountRun struct {
	w      *Watcher
	a      Account
	global bool

	home          *Home
	started, done bool
	paused        bool
	folders       []FolderKey
	fi, si        int
	cur           *Folder
	curKey        FolderKey
	curSub        string
	curID         DirIdent
	curCapped     bool
	subsDone      map[FolderKey]int
	subsFailed    map[FolderKey]bool
	queues        []*folderQueue
	qi            int
	attempts      int
	preferRetry   bool
	seenCount     int
	capReported   bool
}

func (r *accountRun) close() {
	if r.cur != nil {
		_ = r.cur.Close()
		r.cur = nil
	}
	if r.home != nil {
		_ = r.home.Close()
		r.home = nil
	}
}

func (r *accountRun) state() *State { return r.w.cfg.State }

func (r *accountRun) turn(ctx context.Context, rep *PassReport) {
	if !r.started {
		r.started = true
		if !r.start(rep) {
			r.done = true
			return
		}
	}
	if r.discovering() {
		r.discover(rep)
	}
	if !r.done && r.canAttempt() {
		r.attempt(ctx, rep)
	}
	if !r.done && !r.discovering() && !r.canAttempt() {
		r.done = true
	}
}

func (r *accountRun) start(rep *PassReport) bool {
	fsAccount := r.a
	fsAccount.UID = ownerUID(r.a)
	home, err := OpenHome(fsAccount)
	if err != nil {
		rep.Skipped[SkipHomeUnavailable]++
		return false
	}
	r.home = home
	if !r.eligible(rep) {
		return false
	}
	rep.Accounts++
	boxes, skips, err := home.Mailboxes()
	for _, s := range skips {
		rep.Skipped[s.Reason]++
	}
	if err != nil {
		rep.Skipped[SkipFolderUnreadable]++
	}
	for _, m := range boxes {
		for _, f := range Folders {
			r.folders = append(r.folders, FolderKey{UID: r.a.UID, Domain: m.Domain, Box: m.Box, Folder: f})
		}
	}
	r.subsDone, r.subsFailed = map[FolderKey]int{}, map[FolderKey]bool{}
	return r.state().View(func(tx StateTx) (e error) { r.seenCount, e = tx.CountSeen(r.a.UID); return e }) == nil
}

// eligible rechecks the Spam Filters switch. An opt-out cancels the
// account's unsent work and starts new baselines on re-entry.
func (r *accountRun) eligible(rep *PassReport) bool {
	on, reason, err := r.home.Eligible(r.global)
	if err != nil {
		rep.Skipped[SkipOptInUnreadable]++
		return false
	}
	if on {
		return true
	}
	rep.Skipped[reason]++
	var has bool
	if r.state().View(func(tx StateTx) (e error) { has, e = tx.HasState(r.a.UID); return e }) == nil && has {
		_ = r.state().Update(func(tx StateTx) error { return tx.ResetOnOptOut(r.a.UID) })
	}
	r.queues = nil
	return false
}

func (r *accountRun) discovering() bool { return r.cur != nil || r.fi < len(r.folders) }

func (r *accountRun) advance() {
	if r.si++; r.si == len(Subdirs) {
		r.si = 0
		r.fi++
	}
}

func mailboxOf(k FolderKey) Mailbox { return Mailbox{Domain: k.Domain, Box: k.Box} }

// discover lists one chunk. Opening folders and settling unchanged or
// missing ones costs no listing, so it runs before and after the chunk.
func (r *accountRun) discover(rep *PassReport) {
	r.openNext(rep)
	if r.cur == nil {
		return
	}
	turnHook(r.a.UID, "chunk")
	names, err := r.cur.Next(r.w.cfg.Chunk)
	r.observe(names, rep)
	if err == nil && len(names) < r.w.cfg.Chunk {
		// A short batch ends the directory; confirm it in this turn.
		names, err = r.cur.Next(r.w.cfg.Chunk)
		r.observe(names, rep)
	}
	switch {
	case err == io.EOF:
		k, sub, id, capped := r.curKey, r.curSub, r.curID, r.curCapped
		_ = r.cur.Close()
		r.cur = nil
		if !capped {
			_ = r.state().Update(func(tx StateTx) error { return tx.Listed(k, sub, id) })
		}
		r.subComplete(k, rep)
	case err != nil:
		_ = r.cur.Close()
		r.cur = nil
		rep.Skipped[SkipFolderUnreadable]++
		r.subFailed(r.curKey, rep)
	}
	r.openNext(rep)
}

// openNext opens the next folder that needs listing, settling missing,
// unsafe and unchanged ones on the way.
func (r *accountRun) openNext(rep *PassReport) {
	for r.cur == nil && r.fi < len(r.folders) {
		k, sub := r.folders[r.fi], Subdirs[r.si]
		r.advance()
		f, err := r.home.OpenFolder(mailboxOf(k), k.Folder, sub)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			r.subComplete(k, rep)
			continue
		case errors.Is(err, ErrUnsafePath):
			rep.Skipped[SkipUnsafePath]++
			r.subFailed(k, rep)
			continue
		case err != nil:
			rep.Skipped[SkipFolderUnreadable]++
			r.subFailed(k, rep)
			continue
		}
		dev, ino, mtime, ctime := f.Identity()
		id := DirIdent{Dev: dev, Ino: ino, MtimeNs: mtime, CtimeNs: ctime}
		var unchanged bool
		if err = r.state().Update(func(tx StateTx) (e error) { _, unchanged, e = tx.Open(k, sub, id); return e }); err != nil {
			_ = f.Close()
			r.subFailed(k, rep)
			continue
		}
		if unchanged {
			_ = f.Close()
			r.subComplete(k, rep)
			continue
		}
		r.cur, r.curKey, r.curSub, r.curID, r.curCapped = f, k, sub, id, false
	}
}

type observed struct {
	name, base string
	meta       Meta
	status     ReadStatus
}

// observe stats a chunk's entries, then records them in one transaction.
func (r *accountRun) observe(names []string, rep *PassReport) {
	var batch []observed
	for _, name := range names {
		base, ok := BaseName(name)
		if !ok {
			rep.Skipped[SkipUnsupportedName]++
			continue
		}
		m, st, err := r.cur.Stat(name)
		if err != nil || st == ReadGone {
			continue
		}
		batch = append(batch, observed{name: name, base: base, meta: m, status: st})
	}
	if len(batch) == 0 {
		return
	}
	k, sub := r.curKey, r.curSub
	_ = r.state().Update(func(tx StateTx) error {
		for _, o := range batch {
			if r.seenCount >= r.w.cfg.SeenAllowance {
				if _, found, err := tx.Seen(k, o.base); err != nil || !found {
					r.capped(rep)
					continue
				}
			}
			cand, created, err := tx.Observe(k, sub, o.name, o.meta)
			if err != nil {
				return err
			}
			if created {
				r.seenCount++
			}
			if cand && o.status != ReadOK {
				rep.Skipped[o.status.String()]++
				if err = tx.Mark(k, o.base, SkippedStatus(o.status.String())); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// capped records that the account's seen allowance stopped discovery of
// new entries; listing goes on so pending reports are still served.
func (r *accountRun) capped(rep *PassReport) {
	r.curCapped = true
	if !r.capReported {
		r.capReported = true
		rep.Skipped[learn.SkipAccountCapacity]++
	}
}

func (r *accountRun) subFailed(k FolderKey, rep *PassReport) {
	r.subsFailed[k] = true
	r.subComplete(k, rep)
}

// subComplete counts a finished subdirectory; once both are done the
// folder's baseline may finish and its pending reports join the queues.
func (r *accountRun) subComplete(k FolderKey, rep *PassReport) {
	if r.subsDone[k]++; r.subsDone[k] < len(Subdirs) {
		return
	}
	var items []PendingItem
	err := r.state().Update(func(tx StateTx) error {
		st, ok, err := tx.Folder(k)
		if err != nil || !ok {
			return err
		}
		if !st.BaselineDone && !r.subsFailed[k] {
			if err = tx.FinishBaseline(k); err != nil {
				return err
			}
		}
		items, err = tx.Pending(k)
		return err
	})
	if err != nil || len(items) == 0 {
		return
	}
	q := &folderQueue{key: k}
	for _, it := range items {
		if it.Attempts == 0 {
			q.fresh = append(q.fresh, it)
		} else {
			q.retry = append(q.retry, it)
		}
	}
	sort.SliceStable(q.fresh, func(i, j int) bool { return q.fresh[i].FirstSeen.Before(q.fresh[j].FirstSeen) })
	sort.SliceStable(q.retry, func(i, j int) bool { return q.retry[i].LastAttempt.Before(q.retry[j].LastAttempt) })
	r.queues = append(r.queues, q)
}

func (r *accountRun) canAttempt() bool {
	if r.paused || r.attempts >= MaxAttempts || !r.w.cfg.CanSubmit() {
		return false
	}
	for _, q := range r.queues {
		if len(q.fresh)+len(q.retry) > 0 {
			return true
		}
	}
	return false
}

// next takes the next item round-robin across folders, alternating fresh
// and retry queues; each item is taken at most once per pass.
func (r *accountRun) next() (*folderQueue, PendingItem) {
	for range r.queues {
		q := r.queues[r.qi%len(r.queues)]
		r.qi++
		first, second := &q.fresh, &q.retry
		if r.preferRetry {
			first, second = second, first
		}
		for _, list := range []*[]PendingItem{first, second} {
			if len(*list) > 0 {
				it := (*list)[0]
				*list = (*list)[1:]
				r.preferRetry = !r.preferRetry
				return q, it
			}
		}
	}
	return nil, PendingItem{}
}

func (r *accountRun) attempt(ctx context.Context, rep *PassReport) {
	q, it := r.next()
	if q == nil {
		return
	}
	r.attempts++
	turnHook(r.a.UID, "attempt")
	if !r.eligible(rep) {
		r.done = true
		return
	}
	k := q.key
	retry := func() {
		q.waiting = append(q.waiting, it)
		_ = r.state().Update(func(tx StateTx) error { return tx.Retry(k, it.Base) })
	}
	mark := func(status string) {
		_ = r.state().Update(func(tx StateTx) error { return tx.Mark(k, it.Base, status) })
	}
	forget := func() {
		_ = r.state().Update(func(tx StateTx) error { return tx.Forget(k, it.Base) })
	}
	f, err := r.home.OpenFolder(mailboxOf(k), k.Folder, it.Sub)
	if errors.Is(err, fs.ErrNotExist) {
		// The folder went with the message; an unsent report is not history.
		forget()
		return
	}
	if err != nil {
		retry()
		return
	}
	snap, _, st, err := f.ReadMessage(it.Name, ownerUID(r.a))
	_ = f.Close()
	switch {
	case err != nil, st == ReadPendingLinked, st == ReadPendingChanged:
		retry()
		return
	case st == ReadGone:
		forget()
		return
	case st != ReadOK:
		rep.Skipped[st.String()]++
		mark(SkippedStatus(st.String()))
		return
	}
	if v := ParseVerdict(snap); v != VerdictEligible {
		rep.Skipped[v.String()]++
		mark(SkippedStatus(v.String()))
		return
	}
	if !r.eligible(rep) {
		r.done = true
		return
	}
	turnHook(r.a.UID, "submit")
	out, err := r.w.cfg.Engine.Submit(ctx, learn.Candidate{UID: r.a.UID, Snapshot: snap})
	switch {
	case err != nil || out.Deferred:
		retry()
	case slices.ContainsFunc(out.Skips, func(s learn.Skip) bool { return s.Reason == learn.SkipAccountCapacity }):
		retry()
		r.paused = true
		rep.Skipped[learn.SkipAccountCapacity]++
	default:
		rep.Submitted++
		rep.Committed += len(out.Committed)
		for _, s := range out.Skips {
			rep.Skipped[s.Reason]++
		}
		mark(StatusSubmitted)
	}
}
