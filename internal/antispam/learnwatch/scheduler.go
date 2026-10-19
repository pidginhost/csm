package learnwatch

import (
	"cmp"
	"context"
	"errors"
	"io"
	"io/fs"
	"maps"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/antispam/learn"
)

// Scheduler constants (spec 7.5). bench_test.go measures fixed synthetic
// workloads on an 8-core development host with SSD storage; listing
// latency depends on the host and filesystem.
const (
	// PassEvery and MaxAttempts are the spec's schedule and budget.
	PassEvery   = 5 * time.Minute
	MaxAttempts = 20
	// MaxEntryErrors bounds the failed submissions of one entry, so a
	// message that breaks the backend cannot stop every pass.
	MaxEntryErrors = 3
	// PassDeadline leaves time between passes even when discovery runs long;
	// baselining a 51217-entry folder (spike S8's largest) took 1.5 s.
	PassDeadline = 4 * time.Minute
	// DiscoveryChunk bounds the listing work before another account's turn:
	// about 15 ms per chunk at 29 microseconds per entry; during a
	// 51217-entry flood a second account was submitted after 15 to 19 ms.
	DiscoveryChunk = 512
	// AccountSeenAllowance limits identities, not database bytes; it covers
	// S8's 51217-entry folder. A synthetic entry took 353 logical bytes;
	// names, statuses and bbolt page overhead change the cost per entry.
	AccountSeenAllowance = 65536
	// FullRescanEvery relists unchanged folders daily so presence stays
	// fresh for the 90-day prune; relisting the large folder takes seconds.
	FullRescanEvery = 24 * time.Hour
	pruneEvery      = 24 * time.Hour
	// FolderOpensPerTurn bounds the folders one account turn opens, so many
	// mailboxes cost turns like a large folder does; an open walks a few
	// path components and settling an unchanged folder writes nothing.
	FolderOpensPerTurn = 256
)

// Pass skip reasons beyond the registry, eligibility and discovery ones.
const (
	SkipHomeUnavailable    = "home_unavailable"
	SkipOptInUnreadable    = "optin_unreadable"
	SkipFolderUnreadable   = "folder_unreadable"
	SkipRegistryUnreadable = "registry_unreadable"
	SkipStateUnavailable   = "state_unavailable"
	// SkipFailed: an entry failed MaxEntryErrors submissions.
	SkipFailed = "failed"
)

type submitter interface {
	SubmitReport(context.Context, learn.Candidate) (learn.Outcome, error)
	CancelUnsent(ctx context.Context, uid int) error
	ReportUIDs(context.Context) ([]int, error)
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
	// FolderOpens bounds folder opens per account turn; zero means
	// FolderOpensPerTurn.
	FolderOpens int
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
	// submitStopped: a backend error this pass; the pass keeps discovering
	// but submits nothing more, so a hung controller costs one request
	// timeout per pass. Owned by the single active pass.
	submitStopped bool
	stoppedBy     int

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
	if cfg.FolderOpens <= 0 {
		cfg.FolderOpens = FolderOpensPerTurn
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
	r := w.last
	r.Skipped = maps.Clone(r.Skipped)
	return r, w.at
}

// Pass runs one rotation-fair pass. A concurrent call returns Busy; a
// closed discovery gate makes it idle and unrecorded.
func (w *Watcher) Pass(ctx context.Context) PassReport {
	if !w.busy.CompareAndSwap(false, true) {
		return PassReport{Busy: true}
	}
	defer w.busy.Store(false)
	if ctx.Err() != nil || !w.cfg.CanDiscover() {
		return PassReport{}
	}
	ctx, cancel := context.WithTimeout(ctx, PassDeadline)
	defer cancel()
	r := w.pass(ctx)
	w.mu.Lock()
	w.last, w.at = r, w.cfg.Now()
	w.last.Skipped = maps.Clone(r.Skipped)
	w.mu.Unlock()
	if w.cfg.OnPass != nil {
		w.cfg.OnPass(r)
	}
	return r
}

// cancelRemoved cancels the unsent reservations of accounts gone from the
// registry: a removed account has lost its eligibility (spec 7.4). Only a
// complete registry read gets here. An account CSM cannot read still holds
// its UID, and a reused UID keeps the reservation. Failures retry next pass.
func (w *Watcher) cancelRemoved(ctx context.Context, accounts []Account, skips []Skip, r *PassReport) {
	held := map[int]bool{}
	for _, a := range accounts {
		held[a.UID] = true
	}
	for _, s := range skips {
		if s.Reason == SkipBadHome {
			held[s.UID] = true
		}
	}
	uids, err := w.cfg.Engine.ReportUIDs(ctx)
	for _, uid := range uids {
		if !held[uid] {
			err = errors.Join(err, w.cfg.Engine.CancelUnsent(ctx, uid))
		}
	}
	if err != nil {
		r.Skipped[SkipStateUnavailable]++
		r.Unfinished = true
	}
}

func (w *Watcher) pass(ctx context.Context) PassReport {
	w.submitStopped, w.stoppedBy = false, 0
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
	if ctx.Err() != nil || !w.cfg.CanDiscover() {
		r.Unfinished = true
		return r
	}
	w.cancelRemoved(ctx, accounts, skips, &r)
	_, err = GlobalOptIn(w.cfg.GlobalPath)
	if err != nil {
		r.Skipped[SkipOptInUnreadable]++
		r.Unfinished = true
		return r
	}
	slices.SortFunc(accounts, func(a, b Account) int { return cmp.Compare(a.UID, b.UID) })
	var cursor int
	if err = w.cfg.State.View(func(tx StateTx) (e error) { cursor, e = tx.Cursor(); return e }); err != nil {
		r.Skipped[SkipStateUnavailable]++
		r.Unfinished = true
		return r
	}
	start, _ := slices.BinarySearchFunc(accounts, cursor, func(a Account, uid int) int { return cmp.Compare(a.UID, uid) })
	accounts = append(accounts[start:], accounts[:start]...)
	runs := make([]*accountRun, 0, len(accounts))
	for _, a := range accounts {
		run := &accountRun{w: w, a: a, deadline: deadline}
		if cursor != 0 && len(runs) > 0 {
			// Rotation must govern the first attempts too: a small account
			// must not overtake accounts still discovering their mailboxes.
			run.waitFor = runs[len(runs)-1]
		}
		runs = append(runs, run)
	}
	defer func() {
		for _, run := range runs {
			run.close()
		}
	}()
	for active := slices.Clone(runs); len(active) > 0; {
		next := active[:0]
		for _, run := range active {
			if ctx.Err() != nil || !w.cfg.CanDiscover() || !w.cfg.Now().Before(deadline) {
				r.Unfinished = true
				nextUID := nextAfter(runs, w.stoppedBy)
				if nextUID == 0 {
					nextUID = run.a.UID
				}
				w.saveCursor(nextUID, &r)
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
	w.saveCursor(nextAfter(runs, w.stoppedBy), &r)
	w.tally(runs, &r)
	w.prune(runs, &r, len(skips) == 0)
	return r
}

// hostSideFailure reports failures a message cannot cause: cancellation by
// the engine or daemon, a request never sent, a wrong controller peer and
// local learning-state errors.
func hostSideFailure(err error) bool {
	for _, local := range []error{context.Canceled, hostfacts.ErrControllerNotSent, learn.ErrPeer,
		learn.ErrStateIO, learn.ErrStateMismatch, learn.ErrBodyInvalid} {
		if errors.Is(err, local) {
			return true
		}
	}
	return false
}

// nextAfter is the UID of the account after uid in the pass order, so a
// pass stopped by one account's failing entry starts the next pass with
// the others; zero when no account stopped the pass.
func nextAfter(runs []*accountRun, uid int) int {
	if uid == 0 {
		return 0
	}
	for i, run := range runs {
		if run.a.UID == uid {
			return runs[(i+1)%len(runs)].a.UID
		}
	}
	return 0
}

func (w *Watcher) saveCursor(uid int, r *PassReport) {
	var cur int
	err := w.cfg.State.View(func(tx StateTx) (e error) { cur, e = tx.Cursor(); return e })
	if err == nil && cur == uid {
		return
	}
	if err == nil {
		err = w.cfg.State.Update(func(tx StateTx) error { return tx.SetCursor(uid) })
	}
	if err != nil {
		r.Skipped[SkipStateUnavailable]++
		r.Unfinished = true
	}
}

func (w *Watcher) prune(runs []*accountRun, r *PassReport, accountsComplete bool) {
	var folders []FolderKey
	var uncheckedAccounts []int
	var unreadableFolders []FolderKey
	for _, run := range runs {
		if !run.inventoryComplete {
			uncheckedAccounts = append(uncheckedAccounts, run.a.UID)
		}
		for k, done := range run.subsDone {
			if done == len(Subdirs) && !run.subsFailed[k] {
				folders = append(folders, k)
			}
			if run.subsFailed[k] {
				unreadableFolders = append(unreadableFolders, k)
			}
		}
	}
	due := false
	err := w.cfg.State.View(func(tx StateTx) error {
		last, err := tx.LastPrune()
		due = err == nil && tx.now.Sub(last) >= pruneEvery
		return err
	})
	if err == nil && due {
		err = w.cfg.State.Update(func(tx StateTx) error {
			if _, pruneErr := tx.Prune(folders); pruneErr != nil {
				return pruneErr
			}
			// A registry name without a usable UID cannot be distinguished
			// from a deleted account by the UID-keyed persisted state.
			if accountsComplete {
				if _, pruneErr := tx.PruneAbsentFolders(uncheckedAccounts, unreadableFolders); pruneErr != nil {
					return pruneErr
				}
			}
			return tx.SetLastPrune(tx.now)
		})
	}
	if err != nil {
		r.Skipped[SkipStateUnavailable]++
		r.Unfinished = true
	}
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
	preferRetry           bool
}

// accountRun is one account's progress through a pass: discovery walks its
// folders one chunk per turn; candidates alternate fresh and retry queues
// across folders, one attempt per turn, MaxAttempts per pass.
type accountRun struct {
	w        *Watcher
	a        Account
	deadline time.Time

	home          *Home
	started, done bool
	paused        bool
	folders       []FolderKey
	fi, si        int
	cur           *Folder
	curKey        FolderKey
	curSub        string
	curID         DirIdent
	curIncomplete bool
	subsDone      map[FolderKey]int
	subsFailed    map[FolderKey]bool
	cappedFolders map[FolderKey]bool
	queues        []*folderQueue
	qi            int
	attempts      int
	waitFor       *accountRun
	turnOpens     int
	seenCount     int
	capReported   bool

	inventoryComplete bool
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

func (r *accountRun) stateFailed(err error, rep *PassReport) bool {
	if err == nil {
		return false
	}
	rep.Skipped[SkipStateUnavailable]++
	rep.Unfinished = true
	r.done = true
	r.inventoryComplete = false
	return true
}

func (r *accountRun) expired(ctx context.Context) bool {
	return ctx.Err() != nil || !r.w.cfg.Now().Before(r.deadline)
}

func (r *accountRun) turn(ctx context.Context, rep *PassReport) {
	if ctx.Err() != nil || !r.w.cfg.CanDiscover() {
		return
	}
	r.turnOpens = 0
	if !r.started {
		r.started = true
		if !r.start(ctx, rep) {
			r.done = true
			return
		}
	}
	if r.discovering() {
		r.discover(rep)
	}
	if r.expired(ctx) {
		rep.Unfinished = true
		return
	}
	if !r.discovering() && r.attempts == 0 {
		// Persisted attempt times rotate folders across passes even when
		// there are more nonempty folders than the per-account budget.
		slices.SortStableFunc(r.queues, func(a, b *folderQueue) int {
			if order := a.oldestTurn().Compare(b.oldestTurn()); order != 0 {
				return order
			}
			if a.preferRetry == b.preferRetry {
				return 0
			}
			if a.preferRetry {
				return 1
			}
			return -1
		})
	}
	if !r.done && r.canAttempt() {
		for r.waitFor != nil {
			if !r.waitFor.done && r.waitFor.attempts == 0 {
				return
			}
			r.waitFor = r.waitFor.waitFor
		}
		r.attempt(ctx, rep)
	}
	if !r.done && !r.discovering() && !r.canAttempt() {
		r.done = true
	}
}

func (r *accountRun) start(ctx context.Context, rep *PassReport) bool {
	fsAccount := r.a
	fsAccount.UID = ownerUID(r.a)
	home, err := OpenHome(fsAccount)
	if err != nil {
		rep.Skipped[SkipHomeUnavailable]++
		rep.Unfinished = true
		return false
	}
	r.home = home
	if !r.eligible(ctx, rep) {
		return false
	}
	rep.Accounts++
	boxes, skips, err := home.Mailboxes()
	r.inventoryComplete = err == nil && len(skips) == 0
	for _, s := range skips {
		rep.Skipped[s.Reason]++
		if s.Reason == SkipMailboxLimit || s.Reason == SkipMailboxListTooLarge || s.Reason == SkipUnsafePath {
			rep.Unfinished = true
		}
	}
	if err != nil {
		rep.Skipped[SkipFolderUnreadable]++
		rep.Unfinished = true
	}
	for _, m := range boxes {
		for _, f := range Folders {
			r.folders = append(r.folders, FolderKey{UID: r.a.UID, Domain: m.Domain, Box: m.Box, Folder: f})
		}
	}
	r.subsDone, r.subsFailed = map[FolderKey]int{}, map[FolderKey]bool{}
	r.cappedFolders = map[FolderKey]bool{}
	return !r.stateFailed(r.state().View(func(tx StateTx) (e error) { r.seenCount, e = tx.CountSeen(r.a.UID); return e }), rep)
}

// eligible rechecks the Spam Filters switch. An opt-out cancels the
// account's unsent work, the learner's reservations included, and starts
// new baselines on re-entry.
func (r *accountRun) eligible(ctx context.Context, rep *PassReport) bool {
	global, err := GlobalOptIn(r.w.cfg.GlobalPath)
	if err != nil {
		rep.Skipped[SkipOptInUnreadable]++
		rep.Unfinished = true
		return false
	}
	on, reason, err := r.home.Eligible(global)
	if err != nil {
		rep.Skipped[SkipOptInUnreadable]++
		rep.Unfinished = true
		return false
	}
	if on {
		return true
	}
	rep.Skipped[reason]++
	// Asked on every pass, since an explicit disable can drop the folder
	// state of an account the learner still holds work for. A failure is
	// retried by the next pass.
	// The folder baseline must reset even if the learner cannot cancel its
	// reservations. Otherwise re-entry could submit mail from the opt-out.
	r.stateFailed(r.w.cfg.Engine.CancelUnsent(ctx, r.a.UID), rep)
	var has bool
	if r.stateFailed(r.state().View(func(tx StateTx) (e error) { has, e = tx.HasState(r.a.UID); return e }), rep) {
		return false
	}
	if has && r.stateFailed(r.state().Update(func(tx StateTx) error { return tx.ResetOnOptOut(r.a.UID) }), rep) {
		return false
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
	if !r.w.cfg.CanDiscover() {
		return
	}
	names, err := r.cur.Next(r.w.cfg.Chunk)
	r.observe(names, rep)
	if r.done {
		return
	}
	if err == nil && len(names) < r.w.cfg.Chunk {
		// A short batch ends the directory; confirm it in this turn.
		if !r.w.cfg.CanDiscover() {
			return
		}
		names, err = r.cur.Next(r.w.cfg.Chunk)
		r.observe(names, rep)
	}
	if r.done {
		return
	}
	switch {
	case err == io.EOF:
		k, sub, id, incomplete := r.curKey, r.curSub, r.curID, r.curIncomplete
		_ = r.cur.Close()
		r.cur = nil
		if !incomplete && r.stateFailed(r.state().Update(func(tx StateTx) error { return tx.Listed(k, sub, id) }), rep) {
			return
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
	for !r.done && r.cur == nil && r.fi < len(r.folders) && r.w.cfg.CanDiscover() {
		if r.turnOpens >= r.w.cfg.FolderOpens {
			return
		}
		r.turnOpens++
		k, sub := r.folders[r.fi], Subdirs[r.si]
		r.advance()
		turnHook(r.a.UID, "open")
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
		err = r.state().View(func(tx StateTx) (e error) { unchanged, e = tx.Unchanged(k, sub, id); return e })
		if err == nil && !unchanged {
			err = r.state().Update(func(tx StateTx) (e error) { _, unchanged, e = tx.Open(k, sub, id); return e })
		}
		if err != nil {
			_ = f.Close()
			r.stateFailed(err, rep)
			return
		}
		if unchanged {
			_ = f.Close()
			r.subComplete(k, rep)
			continue
		}
		r.cur, r.curKey, r.curSub, r.curID, r.curIncomplete = f, k, sub, id, false
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
		if err != nil {
			r.curIncomplete = true
			r.subsFailed[r.curKey] = true
			rep.Skipped[SkipFolderUnreadable]++
			rep.Unfinished = true
			continue
		}
		if st == ReadGone {
			continue
		}
		batch = append(batch, observed{name: name, base: base, meta: m, status: st})
	}
	if len(batch) == 0 {
		return
	}
	k, sub := r.curKey, r.curSub
	seenCount, capped := r.seenCount, false
	skips := map[string]int{}
	err := r.state().Update(func(tx StateTx) error {
		for _, o := range batch {
			if seenCount >= r.w.cfg.SeenAllowance {
				if _, found, err := tx.Seen(k, o.base); err != nil {
					return err
				} else if !found {
					capped = true
					continue
				}
			}
			cand, created, err := tx.Observe(k, sub, o.name, o.meta)
			if err != nil {
				return err
			}
			if created {
				seenCount++
			}
			if cand && o.status != ReadOK {
				skips[o.status.String()]++
				if err = tx.Mark(k, o.base, SkippedStatus(o.status.String())); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if r.stateFailed(err, rep) {
		return
	}
	r.seenCount = seenCount
	for reason, count := range skips {
		rep.Skipped[reason] += count
	}
	if capped {
		r.capped(rep)
	}
}

// capped records that the account's seen allowance stopped discovery of
// new entries; listing goes on so pending reports are still served.
func (r *accountRun) capped(rep *PassReport) {
	r.curIncomplete = true
	r.cappedFolders[r.curKey] = true
	rep.Unfinished = true
	r.reportCapacity(rep)
}

func (r *accountRun) reportCapacity(rep *PassReport) {
	if !r.capReported {
		r.capReported = true
		rep.Skipped[learn.SkipAccountCapacity]++
	}
}

func (r *accountRun) subFailed(k FolderKey, rep *PassReport) {
	r.subsFailed[k] = true
	rep.Unfinished = true
	r.subComplete(k, rep)
}

// subComplete counts a finished subdirectory; once both are done the
// folder's baseline may finish and its pending reports join the queues.
func (r *accountRun) subComplete(k FolderKey, rep *PassReport) {
	if r.subsDone[k]++; r.subsDone[k] < len(Subdirs) {
		return
	}
	var items []PendingItem
	finish := false
	err := r.state().View(func(tx StateTx) error {
		st, ok, err := tx.Folder(k)
		if err != nil || !ok {
			return err
		}
		finish = !st.BaselineDone && !r.subsFailed[k] && !r.cappedFolders[k]
		items, err = tx.Pending(k)
		return err
	})
	if err == nil && finish {
		err = r.state().Update(func(tx StateTx) error { return tx.FinishBaseline(k) })
	}
	if r.stateFailed(err, rep) || len(items) == 0 {
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
	q.preferRetry = len(q.retry) > 0 && (len(q.fresh) == 0 || q.retry[0].LastAttempt.Before(q.fresh[0].FirstSeen))
	r.queues = append(r.queues, q)
}

func (q *folderQueue) oldestTurn() time.Time {
	if len(q.retry) == 0 {
		return q.fresh[0].FirstSeen
	}
	if len(q.fresh) == 0 || q.retry[0].LastAttempt.Before(q.fresh[0].FirstSeen) {
		return q.retry[0].LastAttempt
	}
	return q.fresh[0].FirstSeen
}

func (r *accountRun) canAttempt() bool {
	// Complete discovery before spending the attempt budget, so a slow
	// later folder gets the same share as the first one.
	if r.discovering() || r.paused || r.w.submitStopped || r.attempts >= MaxAttempts || !r.w.cfg.CanDiscover() || !r.w.cfg.CanSubmit() {
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
		if q.preferRetry {
			first, second = second, first
		}
		for _, list := range []*[]PendingItem{first, second} {
			if len(*list) > 0 {
				it := (*list)[0]
				*list = (*list)[1:]
				q.preferRetry = !q.preferRetry
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
	hold := func() { q.waiting = append(q.waiting, it) }
	k := q.key
	retry := func() {
		hold()
		r.stateFailed(r.state().Update(func(tx StateTx) error { return tx.Retry(k, it.Base) }), rep)
	}
	mark := func(status string) {
		if r.stateFailed(r.state().Update(func(tx StateTx) error { return tx.Mark(k, it.Base, status) }), rep) {
			hold()
		}
	}
	forget := func() {
		if r.stateFailed(r.state().Update(func(tx StateTx) error { return tx.Forget(k, it.Base) }), rep) {
			hold()
		}
	}
	allowed := func() bool {
		if r.expired(ctx) {
			rep.Unfinished = true
			hold()
			return false
		}
		if !r.w.cfg.CanDiscover() || !r.w.cfg.CanSubmit() {
			hold()
			r.paused = true
			return false
		}
		return true
	}
	if !allowed() {
		return
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
	dev, ino, mtime, ctime := f.Identity()
	// Both subdirectories share a baseline. Replacing the sibling also
	// cancels this report, even if its own directory is unchanged.
	ids := map[string]DirIdent{it.Sub: {Dev: dev, Ino: ino, MtimeNs: mtime, CtimeNs: ctime}}
	for _, sub := range Subdirs {
		if sub == it.Sub {
			continue
		}
		sibling, openErr := r.home.OpenFolder(mailboxOf(k), k.Folder, sub)
		if errors.Is(openErr, fs.ErrNotExist) {
			continue
		}
		if openErr != nil {
			_ = f.Close()
			retry()
			return
		}
		dev, ino, mtime, ctime := sibling.Identity()
		ids[sub] = DirIdent{Dev: dev, Ino: ino, MtimeNs: mtime, CtimeNs: ctime}
		_ = sibling.Close()
	}
	var baseline bool
	err = r.state().Update(func(tx StateTx) error {
		for _, sub := range Subdirs {
			id, exists := ids[sub]
			if !exists {
				continue
			}
			b, _, openErr := tx.Open(k, sub, id)
			if openErr != nil {
				return openErr
			}
			baseline = baseline || b
		}
		return nil
	})
	if r.stateFailed(err, rep) {
		_ = f.Close()
		hold()
		return
	}
	if baseline {
		_ = f.Close()
		q.fresh, q.retry, q.waiting = nil, nil, nil
		rep.Unfinished = true
		return
	}
	if !r.eligible(ctx, rep) {
		_ = f.Close()
		if len(r.queues) > 0 {
			hold()
		}
		r.done = true
		return
	}
	if !allowed() {
		_ = f.Close()
		return
	}
	snap, _, st, err := f.ReadMessage(it.Name, ownerUID(r.a))
	_ = f.Close()
	if !allowed() {
		return
	}
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
	if !r.eligible(ctx, rep) {
		if len(r.queues) > 0 {
			hold()
		}
		r.done = true
		return
	}
	if !allowed() {
		return
	}
	turnHook(r.a.UID, "submit")
	out, err := r.w.cfg.Engine.SubmitReport(ctx, learn.Candidate{UID: r.a.UID, Snapshot: snap})
	switch {
	case err != nil || out.Err != nil:
		if err != nil || !errors.Is(out.Err, learn.ErrMessageRejected) {
			r.w.submitStopped, r.w.stoppedBy = true, r.a.UID
		}
		if !allowed() {
			return
		}
		failure := errors.Join(err, out.Err)
		// Fail closed: only failures known to come from the pass, the host or
		// local learning state spare the message's allowance. A message
		// cannot cancel a context or break the ledger; it can cause any
		// other error.
		if ctx.Err() != nil || hostSideFailure(failure) {
			retry()
			return
		}
		// A message can make the backend fail too, so each entry gets
		// MaxEntryErrors tries, and the next pass starts after its account.
		var gaveUp bool
		if r.stateFailed(r.state().Update(func(tx StateTx) (e error) { gaveUp, e = tx.Fail(k, it.Base); return e }), rep) || !gaveUp {
			hold()
		} else {
			rep.Skipped[SkipFailed]++
		}
	case out.Deferred:
		retry()
	case slices.ContainsFunc(out.Skips, func(s learn.Skip) bool { return s.Reason == learn.SkipAccountCapacity }):
		retry()
		r.paused = true
		r.reportCapacity(rep)
	default:
		rep.Submitted++
		rep.Committed += len(out.Committed)
		for _, s := range out.Skips {
			rep.Skipped[s.Reason]++
		}
		mark(StatusSubmitted)
	}
}
