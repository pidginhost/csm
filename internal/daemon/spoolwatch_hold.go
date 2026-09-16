//go:build linux

package daemon

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
)

// spoolHoldBudget bounds how long one mail open may stay suspended waiting for
// a scan verdict. The kernel keeps the opening process frozen until we answer,
// so an unbounded wait turns slow scanning into frozen mail: a saturated
// scanner once held 167 Exim processes and stalled outbound mail host-wide.
// The scan continues after the deadline and can still quarantine.
var spoolHoldBudget = 5 * time.Second

const (
	// spoolHoldExpiryWindow and spoolHoldExpiryThreshold define the burst that
	// means the scanner cannot keep up with mail rather than one slow message.
	spoolHoldExpiryWindow    = time.Minute
	spoolHoldExpiryThreshold = 10

	// spoolBypassCooldown is how long opens are released unheld after a burst.
	spoolBypassCooldown = 5 * time.Minute
)

// spoolWriteResponse is the seam to the kernel verdict write. Var so tests can
// observe verdicts without a live fanotify descriptor.
var spoolWriteResponse = (*SpoolWatcher).writeResponse

// holdGuard owns the verdict for one suspended open. Whoever gets there first
// wins -- the scan, or the budget timer -- and the kernel is answered once.
type holdGuard struct {
	sw             *SpoolWatcher
	fd             int32
	needResp       bool
	once           sync.Once
	closeOnce      sync.Once
	timer          *time.Timer
	expired        atomic.Bool
	timeoutVerdict uint32 // read only after respond has joined once
}

// newHoldGuard arms the budget timer for a suspended open. Outside permission
// mode nothing is suspended, so there is no verdict to write and no timer.
func (sw *SpoolWatcher) newHoldGuard(fd int32, needResp bool) *holdGuard {
	g := &holdGuard{sw: sw, fd: fd, needResp: needResp && sw.permissionMode}
	if g.needResp {
		g.timer = time.AfterFunc(spoolHoldBudget, g.expire)
	}
	return g
}

// timeoutResponse is the verdict used when the budget runs out. fail_mode
// tempfail means the operator chose never to deliver unscanned mail, so defer
// and let Exim retry; otherwise release the message and keep scanning.
func (sw *SpoolWatcher) timeoutResponse() uint32 {
	if sw.cfg.EmailAV.FailMode == "tempfail" {
		return FAN_DENY
	}
	return FAN_ALLOW
}

func (g *holdGuard) expire() {
	if !g.needResp {
		return
	}
	g.once.Do(func() {
		g.timeoutVerdict = g.sw.timeoutResponse()
		g.expired.Store(true)
		spoolWriteResponse(g.sw, g.fd, g.timeoutVerdict)
		// Keep all callback work inside once so finishing an event also joins
		// its timer before the watcher or test hooks can be torn down.
		g.sw.noteHoldExpiry(time.Now())
	})
}

// respond hands the kernel the scan's verdict, unless the budget already
// answered for this event.
func (g *holdGuard) respond(response uint32) {
	if g.timer != nil {
		g.timer.Stop()
	}
	if !g.needResp {
		return
	}
	g.once.Do(func() {
		spoolWriteResponse(g.sw, g.fd, response)
	})
}

func (g *holdGuard) finish(response uint32) {
	g.closeOnce.Do(func() {
		// once waits for a timer's in-progress write before the fd can be
		// closed and recycled. Panic cleanup may finish the same event again.
		g.respond(response)
		_ = unix.Close(int(g.fd))
	})
}

// timedOut reports whether the budget answered before the scan did.
func (g *holdGuard) timedOut() bool { return g.expired.Load() }

// holdWatchdog tracks budget expiries. A burst of them means scanning cannot
// keep up with mail, and holding every further message for the full budget
// only spreads the delay, so the watcher stops holding for a cooldown.
type holdWatchdog struct {
	mu          sync.Mutex
	expiries    []time.Time
	bypassUntil time.Time
}

// recordExpiry notes one expiry and reports whether it started a bypass.
func (w *holdWatchdog) recordExpiry(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	cutoff := now.Add(-spoolHoldExpiryWindow)
	kept := w.expiries[:0]
	for _, at := range w.expiries {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	w.expiries = kept

	if len(w.expiries) < spoolHoldExpiryThreshold || now.Before(w.bypassUntil) {
		return false
	}
	w.bypassUntil = now.Add(spoolBypassCooldown)
	w.expiries = w.expiries[:0]
	return true
}

func (w *holdWatchdog) bypassing(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return now.Before(w.bypassUntil)
}

// noteHoldExpiry records an exhausted deadline or admission capacity and
// reports the first transition into bypass.
func (sw *SpoolWatcher) noteHoldExpiry(now time.Time) {
	if !sw.holds.recordExpiry(now) {
		return
	}
	action := "allowed without scanning"
	if sw.timeoutResponse() == FAN_DENY {
		action = "deferred without scanning (tempfail mode)"
	}
	fmt.Fprintf(os.Stderr, "[%s] spool watcher: scan capacity or hold budget repeatedly exhausted - mail %s for %s\n", ts(), action, spoolBypassCooldown)
	sw.emitFinding("email_av_hold_bypass", alert.Critical,
		fmt.Sprintf("Email AV scanning fell behind mail delivery: scan capacity or the %s hold budget was exhausted %d times within %s. New messages are %s for the next %s; these messages are not queued for a later scan. Scans already running continue. Investigate scanner load.",
			spoolHoldBudget, spoolHoldExpiryThreshold, spoolHoldExpiryWindow, action, spoolBypassCooldown))
}

// dispatchBypass answers an open immediately while bypassing, without
// queueing it. Queueing is what left Exim waiting behind a saturated scanner.
// Reports whether it handled the event.
func (sw *SpoolWatcher) dispatchBypass(fd int32, needResp bool) bool {
	if !sw.holds.bypassing(time.Now()) {
		return false
	}
	if needResp && sw.permissionMode {
		spoolWriteResponse(sw, fd, sw.timeoutResponse())
	}
	_ = unix.Close(int(fd))
	sw.initQueueHealth()
	sw.scannerHealth.Lose(time.Now(), 1)
	return true
}
