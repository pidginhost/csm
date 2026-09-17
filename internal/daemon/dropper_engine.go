package daemon

import (
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// maxDropperProbeAttempts bounds how many times an inconclusive probe (a
// permission or transient I/O failure, not a confirmed absence) is retried
// before the candidate is dropped. Dropping is detection-coverage loss, so
// the engine counts it, but retrying forever would pin a permanently
// unreadable path into every probe tick.
const maxDropperProbeAttempts = 5

// dropperFSProber resolves a tracked candidate against the live filesystem.
// The real implementation is platform-specific (statx birth time, quarantine
// ledger); tests inject a fake so the engine's orchestration is verifiable
// without a kernel.
type dropperFSProber interface {
	probe(c dropperCandidate) dropperProbe
}

// dropperEmitFn delivers a finding. In production it is bound to
// FileMonitor.sendAlertWithPath; tests capture the arguments.
type dropperEmitFn func(sev alert.Severity, check, msg, details, path string)

const dropperCheckName = "self_deleting_dropper_realtime"

type dropperEngineConfig struct {
	ttl     time.Duration
	selfPID int32
	// ignorePath reports whether a path is covered by
	// suppressions.ignore_paths. Nil means nothing is suppressed.
	ignorePath func(string) bool
}

// dropperEngine owns the tracker and drives the observe -> probe -> hold ->
// flush lifecycle. admit is called from the analyzer worker pool (via the
// tracker's own locking); probeStep is called only from the single probe
// goroutine, so its attempt bookkeeping needs no lock.
type dropperEngine struct {
	tr       *dropperTracker
	ttl      time.Duration
	selfPID  int32
	emit     dropperEmitFn
	attempts map[queuehealth.Ticket]int
	// ignorePath mirrors the suppression every other content check already
	// honours. Applied at admit so a suppressed path never consumes tracker
	// capacity a real candidate could have used.
	ignorePath func(string) bool
}

func newDropperEngine(cfg dropperEngineConfig) *dropperEngine {
	return &dropperEngine{
		tr:         newDropperTracker(cfg.ttl),
		ttl:        cfg.ttl,
		selfPID:    cfg.selfPID,
		attempts:   make(map[queuehealth.Ticket]int),
		ignorePath: cfg.ignorePath,
	}
}

// admit records a candidate if it passes the freshness/type gate. Returns
// false when the candidate was rejected by the gate or dropped by the
// tracker capacity bound (the caller surfaces the latter as coverage loss).
func (e *dropperEngine) admit(c dropperCandidate) bool {
	if e.ignorePath != nil && e.ignorePath(c.Path) {
		return false
	}
	if !shouldTrackDropper(c, e.selfPID, e.ttl) {
		return false
	}
	// A file whose whole content carries no executable statement cannot be a
	// dropper payload. ContentSuspicious wins: a realtime content or signature
	// hit already found structure, and no later heuristic may demote that.
	if !c.WritePending && !c.ContentSuspicious && !c.ContentMayExecute && dropperCandidateIsInert(c) {
		return false
	}
	return e.tr.Observe(c)
}

// probeStep resolves every candidate whose TTL elapsed at probeNow, then
// flushes any held findings whose grace window closed at flushNow. Callers
// pass the same clock for both; the two parameters exist so tests can drive
// the grace window independently of the TTL.
func (e *dropperEngine) probeStep(probeNow time.Time, prober dropperFSProber, flushNow time.Time) {
	for _, c := range e.tr.Due(probeNow) {
		// A close-write can strengthen the filesystem identity while queued.
		// The work ticket survives that change and owns its attempt budget.
		key := c.ticket
		if e.ignorePath != nil && e.ignorePath(c.Path) {
			delete(e.attempts, key)
			c.ticket.Finish(e.tr.now())
			continue
		}
		verdict := assessDropper(c, prober.probe(c))
		if verdict == dropperInconclusive {
			if e.attempts[key]+1 >= maxDropperProbeAttempts {
				delete(e.attempts, key)
				c.ticket.Reject(e.tr.now())
				continue
			}
			attempts := e.attempts[key] + 1
			delete(e.attempts, key)
			if retained, ok := e.tr.Retry(c); ok {
				e.attempts[retained] = max(e.attempts[retained], attempts)
			}
			continue
		}
		delete(e.attempts, key)
		c.ticket.Finish(e.tr.now())
		e.tr.HoldGone(c, verdict, flushNow)
	}
	for _, f := range e.tr.FlushDue(flushNow) {
		e.flushFinding(f)
	}
}

func (e *dropperEngine) flushFinding(f dropperFinding) {
	defer func() {
		for _, item := range f.Items {
			item.ticket.Finish(e.tr.now())
		}
	}()
	items := make([]dropperGone, 0, len(f.Items))
	for _, item := range f.Items {
		if e.ignorePath == nil || !e.ignorePath(item.Cand.Path) {
			items = append(items, item)
		}
	}
	// Suppress before deciding burst severity. Otherwise excluded files
	// can turn a remaining solitary dropper into a lower-severity burst.
	if len(items) >= dropperBurstThreshold {
		e.emitFinding(dropperFinding{Aggregate: true, Docroot: f.Docroot, Items: items})
	} else {
		for _, item := range items {
			e.emitFinding(dropperFinding{Docroot: f.Docroot, Items: []dropperGone{item}})
		}
	}
}

func (e *dropperEngine) emitFinding(f dropperFinding) {
	if e.emit != nil {
		sev, msg, details, path := dropperAlertParams(f)
		e.emit(sev, dropperCheckName, msg, details, path)
	}
}
