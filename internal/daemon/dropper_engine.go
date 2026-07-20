package daemon

import (
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
	attempts map[dropperCandidateKey]int
}

func newDropperEngine(cfg dropperEngineConfig) *dropperEngine {
	return &dropperEngine{
		tr:       newDropperTracker(cfg.ttl),
		ttl:      cfg.ttl,
		selfPID:  cfg.selfPID,
		attempts: make(map[dropperCandidateKey]int),
	}
}

// admit records a candidate if it passes the freshness/type gate. Returns
// false when the candidate was rejected by the gate or dropped by the
// tracker capacity bound (the caller surfaces the latter as coverage loss).
func (e *dropperEngine) admit(c dropperCandidate) bool {
	if !shouldTrackDropper(c, e.selfPID, e.ttl) {
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
		key := candidateKey(c)
		verdict := assessDropper(c, prober.probe(c))
		if verdict == dropperInconclusive {
			if e.attempts[key]+1 >= maxDropperProbeAttempts {
				delete(e.attempts, key)
				continue
			}
			e.attempts[key]++
			e.tr.Observe(c) // requeue; Observe keeps the earliest Observed time
			continue
		}
		delete(e.attempts, key)
		e.tr.HoldGone(c, verdict, flushNow)
	}
	for _, f := range e.tr.FlushDue(flushNow) {
		sev, msg, details, path := dropperAlertParams(f)
		if e.emit != nil {
			e.emit(sev, dropperCheckName, msg, details, path)
		}
	}
}
