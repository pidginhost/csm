package admissionowner

import (
	"errors"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// dryRunRetention is how long a forecast example is kept (spec 3.6).
const dryRunRetention = 7 * 24 * time.Hour

// maintainEvery spaces the maintenance steps over the example bucket.
const maintainEvery = time.Second

// recordExamples writes one turn's forecast examples and maintainStore runs
// one maintenance step; tests make them fail.
var (
	recordExamples = (*store.DB).RecordDryRunBlocks
	maintainStore  = (*store.DB).MaintainDryRunBlocks
)

// dryRunOutput is what an executable owner's dry runs leave outside their
// session (spec 3.6, 3.8): the turn's examples, the maintenance pass over
// the example bucket, the purge the last change to live asked for, and
// process counters a mode change never resets. Only the owner goroutine
// uses it.
type dryRunOutput struct {
	batch []store.DryRunBlock
	// cursor is where the maintenance pass resumes, nil to start one; keep
	// is the session a purging pass keeps. maintainAt is the next step, on
	// the monotonic clock.
	cursor     []byte
	keep       string
	purging    bool
	maintainAt time.Time
	// stale is set from a purge request until a purge pass completes.
	stale bool
	// examplesLost counts examples not written; recordErrors counts failed
	// writes and maintenance steps; summariesLost counts summaries a stop
	// discarded or a full count could not carry.
	examplesLost, recordErrors, summariesLost uint64
	// last is the session status shows once none runs; restarted is set
	// when an earlier process opened the ledger.
	last      sessionInfo
	restarted bool
}

// sessionInfo identifies a forecast session for status.
type sessionInfo struct {
	id    string
	since time.Time
	reset resetReason
}

// noteExample adds p's committed capacity admission to the turn's
// examples.
func (o *Owner) noteExample(p execPick, change *shadowChange) {
	o.out.batch = append(o.out.batch, store.DryRunBlock{
		At: o.now, IP: change.ip, Check: registeredCheck(p.c.Check), Candidate: p.pick.ID,
		Session: o.shadow.id, Kind: change.entry.kind, ExpiresAt: change.entry.expires,
	})
}

// flushExamples writes the turn's examples once, after its endings. A
// failed write loses them: the endings and the forecast stand, and nothing
// retries them. A bucket above its cap discards them without an error.
func (o *Owner) flushExamples() {
	batch := o.out.batch
	o.out.batch = o.out.batch[:0]
	if len(batch) == 0 {
		return
	}
	err := recordExamples(o.opts.DB, batch)
	if err == nil {
		return
	}
	saturatingAdd(&o.out.examplesLost, uint64(len(batch)))
	if !errors.Is(err, store.ErrDryRunBlocksFull) {
		saturating(&o.out.recordErrors)
	}
}

// requestPurge asks the maintenance pass to remove every example but the
// active session's, starting over from the first key.
func (o *Owner) requestPurge() {
	o.out.stale, o.out.purging, o.out.cursor = true, false, nil
}

// maintainExamples runs one bounded maintenance step a second at most: it
// trims a bucket above its cap, removes examples older than a week and,
// while a purge is pending, those of every session but the active one. A
// purge pass starts over when the active session changes, so no session
// it should remove is passed over. A failed step is counted and retried.
func (o *Owner) maintainExamples() {
	if !o.executable() || !o.started || monoNow().Before(o.out.maintainAt) {
		return
	}
	o.out.maintainAt = monoNow().Add(maintainEvery)
	keep := ""
	if o.shadow != nil {
		keep = o.shadow.id
	}
	if o.out.stale && (!o.out.purging || keep != o.out.keep) {
		o.out.cursor, o.out.purging, o.out.keep = nil, true, keep
	}
	res, err := maintainStore(o.opts.DB, store.DryRunMaintenance{
		Cursor: o.out.cursor, Cutoff: o.now.Add(-dryRunRetention), Purge: o.out.purging, Keep: keep,
	})
	if err != nil {
		saturating(&o.out.recordErrors)
		return
	}
	o.out.cursor = res.Next
	if res.Done {
		o.out.stale = o.out.stale && !o.out.purging
		o.out.cursor, o.out.purging = nil, false
	}
}

// OwnsDryRunExamples reports whether the owner alone writes, prunes and
// purges its forecast examples: an owner that runs blocks does (spec 3.6).
func (o *Owner) OwnsDryRunExamples() bool { return o.executable() }

func saturatingAdd(n *uint64, d uint64) {
	*n += min(d, ^uint64(0)-*n)
}
