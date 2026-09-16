//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// recordedResponse is one fanotify verdict the watcher handed the kernel.
type recordedResponse struct {
	fd       int32
	response uint32
}

// captureResponses replaces the kernel write with a recorder for the test's
// duration and returns an accessor for what was written.
func captureResponses(t *testing.T) func() []recordedResponse {
	t.Helper()
	var mu sync.Mutex
	var got []recordedResponse
	orig := spoolWriteResponse
	spoolWriteResponse = func(_ *SpoolWatcher, fd int32, response uint32) {
		mu.Lock()
		got = append(got, recordedResponse{fd: fd, response: response})
		mu.Unlock()
	}
	t.Cleanup(func() { spoolWriteResponse = orig })
	return func() []recordedResponse {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedResponse(nil), got...)
	}
}

func shortHoldBudget(t *testing.T, d time.Duration) {
	t.Helper()
	orig := spoolHoldBudget
	spoolHoldBudget = d
	t.Cleanup(func() { spoolHoldBudget = orig })
}

func testHoldWatcher(t *testing.T) (*SpoolWatcher, chan alert.Finding) {
	t.Helper()
	alertCh := make(chan alert.Finding, 16)
	sw := &SpoolWatcher{
		cfg:            &config.Config{},
		alertCh:        alertCh,
		scanCh:         make(chan spoolEvent, 1),
		stopCh:         make(chan struct{}),
		permissionMode: true,
	}
	sw.initQueueHealth()
	return sw, alertCh
}

func waitForResponses(t *testing.T, get func() []recordedResponse, want int, within time.Duration) []recordedResponse {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if got := get(); len(got) >= want {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	return get()
}

// A scan that outruns the hold budget must not keep Exim suspended. The
// kernel gets its verdict at the deadline; the scan finishes out of band.
func TestHoldGuardRespondsWhenScanExceedsBudget(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, 40*time.Millisecond)
	sw, _ := testHoldWatcher(t)

	guard := sw.newHoldGuard(7, true)
	defer guard.respond(FAN_ALLOW)

	got := waitForResponses(t, responses, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("responses = %+v, want exactly one at the deadline", got)
	}
	if got[0].fd != 7 || got[0].response != FAN_ALLOW {
		t.Errorf("response = %+v, want fd 7 allowed", got[0])
	}
	if !guard.timedOut() {
		t.Error("guard did not record that the budget expired")
	}
}

// fail_mode=tempfail means the operator chose "never deliver unscanned".
// Honour that on expiry by deferring instead of delivering.
func TestHoldGuardDefersOnExpiryInTempfailMode(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, 40*time.Millisecond)
	sw, _ := testHoldWatcher(t)
	sw.cfg.EmailAV.FailMode = "tempfail"

	guard := sw.newHoldGuard(9, true)
	defer guard.respond(FAN_ALLOW)

	got := waitForResponses(t, responses, 1, 2*time.Second)
	if len(got) != 1 || got[0].response != FAN_DENY {
		t.Fatalf("responses = %+v, want a single deferral", got)
	}
}

// A scan that finishes inside the budget owns the verdict, and the expiry
// timer must not add a second, contradictory response.
func TestHoldGuardScanVerdictWinsAndIsAnsweredOnce(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, 60*time.Millisecond)
	sw, _ := testHoldWatcher(t)

	guard := sw.newHoldGuard(11, true)
	guard.respond(FAN_DENY)
	time.Sleep(150 * time.Millisecond)

	got := responses()
	if len(got) != 1 {
		t.Fatalf("responses = %+v, want exactly one", got)
	}
	if got[0].response != FAN_DENY {
		t.Errorf("response = %+v, want the scan verdict to stand", got[0])
	}
	if guard.timedOut() {
		t.Error("guard reported a timeout although the scan answered in time")
	}
}

// Without permission mode there is nothing suspended, so the guard must stay
// silent rather than write verdicts for events the kernel never asked about.
func TestHoldGuardSilentWithoutPermissionMode(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, 30*time.Millisecond)
	sw, _ := testHoldWatcher(t)
	sw.permissionMode = false

	guard := sw.newHoldGuard(13, false)
	time.Sleep(120 * time.Millisecond)
	guard.respond(FAN_ALLOW)

	if got := responses(); len(got) != 0 {
		t.Fatalf("responses = %+v, want none outside permission mode", got)
	}
}

// Repeated expiries mean the scanner cannot keep up. Rather than hold every
// message for the full budget, stop holding until the pressure passes.
func TestHoldWatchdogEntersBypassAfterRepeatedExpiries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var w holdWatchdog

	for i := 0; i < spoolHoldExpiryThreshold-1; i++ {
		if entered := w.recordExpiry(now); entered {
			t.Fatalf("entered bypass after %d expiries, want %d", i+1, spoolHoldExpiryThreshold)
		}
	}
	if entered := w.recordExpiry(now); !entered {
		t.Fatalf("did not enter bypass at %d expiries", spoolHoldExpiryThreshold)
	}
	if !w.bypassing(now) {
		t.Error("watchdog is not bypassing right after entering bypass")
	}
}

// Expiries spread thinly over time are normal wear, not an emergency.
func TestHoldWatchdogIgnoresExpiriesOutsideWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var w holdWatchdog

	for i := 0; i < spoolHoldExpiryThreshold*2; i++ {
		at := now.Add(time.Duration(i) * spoolHoldExpiryWindow)
		if entered := w.recordExpiry(at); entered {
			t.Fatalf("entered bypass on expiry %d spread across separate windows", i+1)
		}
	}
}

func TestHoldWatchdogLeavesBypassAfterCooldown(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var w holdWatchdog
	for i := 0; i < spoolHoldExpiryThreshold; i++ {
		w.recordExpiry(now)
	}
	if !w.bypassing(now.Add(spoolBypassCooldown - time.Second)) {
		t.Error("left bypass before the cooldown elapsed")
	}
	if w.bypassing(now.Add(spoolBypassCooldown + time.Second)) {
		t.Error("still bypassing after the cooldown elapsed")
	}
	after := now.Add(spoolBypassCooldown + 2*time.Second)
	var reentered bool
	for i := 0; i < spoolHoldExpiryThreshold; i++ {
		reentered = w.recordExpiry(after) || reentered
	}
	if !reentered {
		t.Error("a fresh expiry burst after recovery did not re-enter bypass")
	}
}

// While bypassing, an open is released immediately and never queued: queueing
// it is what kept Exim waiting behind a saturated scanner.
func TestDispatchInBypassAnswersWithoutQueueing(t *testing.T) {
	responses := captureResponses(t)
	sw, _ := testHoldWatcher(t)
	now := time.Now()
	for i := 0; i < spoolHoldExpiryThreshold; i++ {
		sw.holds.recordExpiry(now)
	}

	if handled := sw.dispatchBypass(21, true); !handled {
		t.Fatal("dispatchBypass did not handle the event while bypassing")
	}
	got := responses()
	if len(got) != 1 || got[0].fd != 21 || got[0].response != FAN_ALLOW {
		t.Fatalf("responses = %+v, want fd 21 allowed immediately", got)
	}
	if len(sw.scanCh) != 0 {
		t.Fatalf("event was queued while bypassing: depth %d", len(sw.scanCh))
	}
}

// Entering bypass is a security-relevant degradation: mail flows unscanned,
// so it has to be visible to an operator, not just in a log line.
func TestBypassEmitsCriticalFinding(t *testing.T) {
	captureResponses(t)
	sw, alertCh := testHoldWatcher(t)
	now := time.Now()
	for i := 0; i < spoolHoldExpiryThreshold-1; i++ {
		sw.holds.recordExpiry(now)
	}
	sw.noteHoldExpiry(now)

	select {
	case f := <-alertCh:
		if f.Severity != alert.Critical {
			t.Errorf("severity = %v, want Critical", f.Severity)
		}
		if f.Check != "email_av_hold_bypass" {
			t.Errorf("check = %q, want email_av_hold_bypass", f.Check)
		}
	default:
		t.Fatal("entering bypass emitted no finding")
	}
}

// openSpoolFD returns a live fd whose /proc path ends in -D, as a spool body
// open would, so dispatchEvent takes its scanning path.
func openSpoolFD(t *testing.T) int32 {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "1xTEST-0000000000-0000-D"))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return int32(fd) // #nosec G115 -- test fd fits in int32.
}

// The outage: every scan worker busy, so dispatch blocked while the kernel
// kept Exim suspended. Dispatch must give the kernel its verdict within the
// budget instead of waiting for a free worker.
func TestDispatchReleasesOpenWhenAllWorkersStayBusy(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, 60*time.Millisecond)
	sw, _ := testHoldWatcher(t)
	sw.scanCh <- spoolEvent{path: "/spool/busy-D", fd: -1} // fill the queue

	start := time.Now()
	sw.dispatchEvent(openSpoolFD(t), int32(os.Getpid()+1))
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("dispatch blocked for %s, want release near the %s budget", elapsed, spoolHoldBudget)
	}
	got := responses()
	if len(got) != 1 || got[0].response != FAN_ALLOW {
		t.Fatalf("responses = %+v, want one release", got)
	}
	if len(sw.scanCh) != 1 {
		t.Errorf("queue depth = %d, want the event dropped rather than queued", len(sw.scanCh))
	}
}

// A scan slower than the budget must not extend the suspension: the kernel is
// answered at the deadline while the scan keeps running.
func TestSlowScanDoesNotHoldMailPastBudget(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, 60*time.Millisecond)
	sw, _ := testHoldWatcher(t)

	orig := spoolEventHandler
	t.Cleanup(func() { spoolEventHandler = orig })
	scanning := make(chan struct{})
	spoolEventHandler = func(_ *SpoolWatcher, evt spoolEvent) {
		time.Sleep(600 * time.Millisecond)
		evt.finish(sw, FAN_ALLOW)
		close(scanning)
	}

	sw.wg.Add(1)
	go sw.scanWorker()
	t.Cleanup(func() { close(sw.stopCh); sw.wg.Wait() })

	start := time.Now()
	sw.dispatchEvent(openSpoolFD(t), int32(os.Getpid()+1))
	got := waitForResponses(t, responses, 1, 2*time.Second)
	released := time.Since(start)

	if len(got) != 1 || got[0].response != FAN_ALLOW {
		t.Fatalf("responses = %+v, want one release", got)
	}
	if released > 400*time.Millisecond {
		t.Fatalf("mail stayed suspended %s, want release near the %s budget", released, spoolHoldBudget)
	}
	select {
	case <-scanning:
	case <-time.After(3 * time.Second):
		t.Fatal("scan did not continue after the release")
	}
	if got := responses(); len(got) != 1 {
		t.Fatalf("responses = %+v, want the late verdict suppressed", got)
	}
}
