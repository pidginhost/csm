package yaraworker

import (
	"sync"
	"time"
)

// scanErrLog writes a scan failure at most once per scanErrLogWindow per
// distinct message, reporting how many identical failures were folded into
// the gap so the volume stays visible. A worker that cannot load its rules
// fails identically for every file, so the same message would otherwise be
// written once per scanned file. Tracking is per message rather than per
// most-recent, so two failures alternating cannot defeat suppression.
type scanErrLog struct {
	mu       sync.Mutex
	seen     map[string]*scanErrRecord
	overflow scanErrRecord
}

// scanErrRecord tracks one distinct failure message: when it was last
// written, and how many identical failures happened since.
type scanErrRecord struct {
	at         time.Time
	suppressed int
}

// scanErrMaxTracked bounds the distinct-message table so a failure carrying
// unique text (a path, an offset) cannot grow it without limit.
const scanErrMaxTracked = 32

// scanErrLogWindow bounds how often one recurring scan failure is written.
// Long enough that a broken rules directory cannot flood the journal, short
// enough that a persistent fault keeps reappearing.
const scanErrLogWindow = time.Minute

func (l *scanErrLog) log(logf func(string, ...any), err error) {
	msg := err.Error()
	now := time.Now()

	l.mu.Lock()
	if l.seen == nil {
		l.seen = make(map[string]*scanErrRecord)
	}
	rec, ok := l.seen[msg]
	overflow := !ok && len(l.seen) >= scanErrMaxTracked
	if overflow {
		// Preserve known recurring failures. Resetting the table lets a stream
		// of unique offsets or paths disable throttling for every message.
		rec = &l.overflow
		ok = !rec.at.IsZero()
	}
	if ok && now.Sub(rec.at) < scanErrLogWindow {
		rec.suppressed++
		l.mu.Unlock()
		return
	}
	if !ok && !overflow {
		rec = &scanErrRecord{}
		l.seen[msg] = rec
	}
	suppressed := rec.suppressed
	rec.at = now
	rec.suppressed = 0
	l.mu.Unlock()

	switch {
	case overflow:
		logf("scan: %v (%d additional scan failures suppressed)", err, suppressed)
	case suppressed > 0:
		logf("scan: %v (%d identical failures suppressed)", err, suppressed)
	default:
		logf("scan: %v", err)
	}
}
