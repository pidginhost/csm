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
// running scan. Real senders stay far below it; past it, messages are
// answered under fail_mode at once instead of growing the backlog.
const maxSourceWaiting = 32

// sourceGate lets one message per source scan at a time, so one sender
// cannot take every scan slot. A key present in busy means a scan of that
// source is running; its value is the messages parked behind it, which the
// running scan's goroutine handles next. Parked messages hold no slot.
type sourceGate struct {
	mu   sync.Mutex
	busy map[string][]spoolEvent
}

// enter claims src for evt. run means scan evt now; otherwise evt is parked,
// unless overflow says the source already has maxSourceWaiting waiting.
func (g *sourceGate) enter(src string, evt spoolEvent) (run, overflow bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	waiting, ok := g.busy[src]
	if !ok {
		if g.busy == nil {
			g.busy = make(map[string][]spoolEvent)
		}
		g.busy[src] = nil
		return true, false
	}
	if len(waiting) >= maxSourceWaiting {
		return false, true
	}
	g.busy[src] = append(waiting, evt)
	return false, false
}

// leave hands over the next parked message of src, keeping the source busy,
// or frees the source when none is waiting.
func (g *sourceGate) leave(src string) (spoolEvent, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	waiting := g.busy[src]
	if len(waiting) == 0 {
		delete(g.busy, src)
		return spoolEvent{}, false
	}
	next := waiting[0]
	waiting[0] = spoolEvent{}
	g.busy[src] = waiting[1:]
	return next, true
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

// handleFair scans evt on slot, one message per source at a time. Messages
// parked behind a running scan of their source are handled by that scan's
// goroutine, on the same slot, once it finishes.
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

// sourceOverflow answers an event whose source already has the maximum
// number of messages waiting. It is not a capacity problem, so it does not
// count toward the hold bypass.
func (sw *SpoolWatcher) sourceOverflow(evt spoolEvent) {
	evt.queueTicket.Reject(time.Now())
	evt.finish(sw, sw.timeoutResponse())
	if spoolSourceWaitsTotal != nil {
		spoolSourceWaitsTotal.With("overflow").Inc()
	}
	sw.emitLimited("email_av_source_backlog", alert.Warning, time.Minute,
		fmt.Sprintf("More than %d messages from source %q are waiting to be scanned. Further messages from it are answered under email_av.fail_mode without a scan until the backlog clears. Block the source if it should not send this much mail.", maxSourceWaiting, evt.source))
}
