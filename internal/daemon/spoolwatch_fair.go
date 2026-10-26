//go:build linux

package daemon

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/emailspool"
	"github.com/pidginhost/csm/internal/obs"
)

// maxSourceWaiting bounds how many messages may wait behind one source's
// running scans. Real senders stay far below it; past it, messages are
// scanned at once without waiting their turn.
const maxSourceWaiting = 32

// sourceGate lets one source scan on at most limit slots at a time, so one
// sender cannot take every scan slot. limit is half the slots, not one: a
// single key can stand for a filtering gateway, unauthenticated mail from
// localhost, or the bounces Exim writes itself. Messages parked behind a
// source hold no slot; the goroutines scanning that source handle them next.
type sourceGate struct {
	mu    sync.Mutex
	limit int
	busy  map[string]*sourceScans
}

type sourceScans struct {
	running int
	waiting []spoolEvent
}

// setLimit sets the scans one source may run at once to half of slots, at
// least one.
func (g *sourceGate) setLimit(slots int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.limit = max(1, slots/2)
}

// enter claims a scan of src for evt. run means scan evt now; otherwise evt
// is parked, unless overflow says the source already has maxSourceWaiting
// waiting.
func (g *sourceGate) enter(src string, evt spoolEvent) (run, overflow bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy == nil {
		g.busy = make(map[string]*sourceScans)
	}
	scans := g.busy[src]
	if scans == nil {
		scans = &sourceScans{}
		g.busy[src] = scans
	}
	if scans.running < max(1, g.limit) {
		scans.running++
		return true, false
	}
	if len(scans.waiting) >= maxSourceWaiting {
		return false, true
	}
	scans.waiting = append(scans.waiting, evt)
	return false, false
}

// leave hands over the next parked message of src to the scan that just
// ended, or ends that scan when none is waiting.
func (g *sourceGate) leave(src string) (spoolEvent, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	scans := g.busy[src]
	if scans == nil {
		return spoolEvent{}, false
	}
	if len(scans.waiting) > 0 {
		next := scans.waiting[0]
		scans.waiting[0] = spoolEvent{}
		scans.waiting = scans.waiting[1:]
		return next, true
	}
	scans.running--
	if scans.running <= 0 {
		delete(g.busy, src)
	}
	return spoolEvent{}, false
}

// readSpoolSource is a seam for tests.
var readSpoolSource = emailspool.ReadSource

// safeSpoolSource is spoolSource behind a panic guard: it parses
// attacker-influenced bytes before handleSpoolEventSafe's own guard, and a
// parser bug must not crash the daemon on every redelivery. A message whose
// source cannot be read is scanned without the gate.
func (sw *SpoolWatcher) safeSpoolSource(evt spoolEvent) (src string) {
	defer func() {
		if r := recover(); r != nil {
			obs.CaptureMsg("spool-scanner", fmt.Sprintf("panic reading the source of %s: %v", evt.path, r))
			fmt.Fprintf(os.Stderr, "[%s] spool watcher: recovered panic reading the source of %s: %v\n%s", ts(), evt.path, r, debug.Stack())
			src = ""
		}
	}()
	return sw.spoolSource(evt)
}

// spoolSource reads the source key of the event's message from its -H file,
// with the same refusals as extraction. It returns "" when the -H cannot be
// read, which includes the reception open before Exim writes it (MAIL-03).
func (sw *SpoolWatcher) spoolSource(evt spoolEvent) string {
	if !strings.HasSuffix(evt.path, "-D") {
		return ""
	}
	header, err := openSpoolHeader(strings.TrimSuffix(evt.path, "-D")+"-H", evt.fd)
	if err != nil {
		return ""
	}
	defer func() { _ = header.Close() }()
	src, err := readSpoolSource(header)
	if err != nil {
		return ""
	}
	return src
}

// handleFair scans evt on slot, at most the gate's limit of scans per
// source at a time. Messages parked behind a source are handled by one of
// that source's scanning goroutines, on its slot, once a scan finishes.
func (sw *SpoolWatcher) handleFair(slot int, evt spoolEvent) {
	evt.slot = slot
	evt.guard.setStage(holdScanning)
	src := sw.safeSpoolSource(evt)
	if src == "" {
		sw.handleSpoolEventSafe(evt)
		return
	}
	evt.source = src
	// Mark the hold as waiting before parking: once parked, the source's
	// goroutine may take the event and mark it scanning at any time. A hold
	// that expires while waiting follows fail_mode without counting toward
	// the bypass.
	evt.guard.setStage(holdWaiting)
	run, overflow := sw.sources.enter(src, evt)
	switch {
	case overflow:
		sw.sourceOverflow(evt)
		evt.guard.setStage(holdScanning)
		sw.handleSpoolEventSafe(evt)
		return
	case !run:
		if spoolSourceWaitsTotal != nil {
			spoolSourceWaitsTotal.With("waited").Inc()
		}
		return
	}
	evt.guard.setStage(holdScanning)
	for more := true; more; {
		func() {
			// A panic must not leave the source busy.
			defer func() { evt, more = sw.sources.leave(src) }()
			sw.handleSpoolEventSafe(evt)
		}()
		if more {
			evt.slot = slot
			evt.guard.setStage(holdScanning)
		}
	}
}

// sourceOverflow reports an event whose source already has the maximum
// number of messages waiting. The event is then scanned at once, outside the
// gate: a source key can stand for many senders, so answering it unscanned
// would deliver their mail unchecked.
func (sw *SpoolWatcher) sourceOverflow(evt spoolEvent) {
	if spoolSourceWaitsTotal != nil {
		spoolSourceWaitsTotal.With("overflow").Inc()
	}
	sw.emitLimited("email_av_source_backlog", alert.Warning, time.Minute,
		fmt.Sprintf("More than %d messages from source %q are waiting to be scanned. Further messages from it are scanned without waiting their turn and can take every scan slot until the backlog clears. Block the source if it should not send this much mail.", maxSourceWaiting, evt.source))
}
