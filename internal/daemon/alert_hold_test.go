package daemon

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// alertHoldTestBudget is the budget for one phase of these tests, not for a
// whole test. Pushing thousands of findings through a held dispatcher takes
// far longer under the race detector and coverage instrumentation than it
// does locally, and a single deadline spanning both the enqueue and the
// assertion lets a slow runner consume the budget before the assertion loop
// runs even once -- which reads as "nothing was dispatched" rather than as
// the timeout it is. Each phase restarts the clock.
const alertHoldTestBudget = 60 * time.Second

// Realtime producers send to the alert channel non-blocking from the moment
// the watchers start, but the dispatcher used to start only after the
// synchronous baseline scan, so every finding past the channel buffer during
// those minutes was dropped without a trace. The dispatcher now starts first
// and keeps draining while it holds its batch until the baseline releases it.
func TestAlertDispatcherHoldsBatchWithoutDroppingUntilReleased(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	prevInterval := alertBatchInterval
	alertBatchInterval = 50 * time.Millisecond
	t.Cleanup(func() { alertBatchInterval = prevInterval })

	previousHook := alert.CentralHook
	var dispatched atomic.Int64
	alert.SetCentralHook(func(alert.Finding) { dispatched.Add(1) })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })

	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.holdAlertDispatch()
	d.wg.Add(1)
	go d.alertDispatcher()
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})

	produced := 3 * cap(d.alertCh)
	deadline := time.Now().Add(alertHoldTestBudget)
	for i := 0; i < produced; i++ {
		f := alert.Finding{
			Severity:  alert.Critical,
			Check:     "webshell_realtime",
			FilePath:  fmt.Sprintf("/home/acct/public_html/%d.php", i),
			Message:   fmt.Sprintf("hold test %d", i),
			Timestamp: time.Now(),
		}
		for {
			select {
			case d.alertCh <- f:
			default:
				if time.Now().After(deadline) {
					t.Fatalf("finding %d could not be enqueued: nothing drains the channel while dispatch is held", i)
				}
				time.Sleep(time.Millisecond)
				continue
			}
			break
		}
	}

	time.Sleep(4 * alertBatchInterval)
	if n := dispatched.Load(); n != 0 {
		t.Fatalf("%d findings dispatched while the baseline hold was in place", n)
	}

	d.releaseAlertDispatch()
	deadline = time.Now().Add(alertHoldTestBudget)
	for time.Now().Before(deadline) {
		if int(dispatched.Load()) == produced {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dispatched %d of %d findings after release", dispatched.Load(), produced)
}

func TestAlertDispatcherCountsHeldBatchOverflow(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	prevInterval := alertBatchInterval
	alertBatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { alertBatchInterval = prevInterval })

	previousHook := alert.CentralHook
	var dispatched atomic.Int64
	alert.SetCentralHook(func(alert.Finding) { dispatched.Add(1) })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })

	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.holdAlertDispatch()
	d.wg.Add(1)
	go d.alertDispatcher()
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})

	produced := alertHoldMaxBatch + 3
	deadline := time.Now().Add(alertHoldTestBudget)
	for i := 0; i < produced; i++ {
		f := alert.Finding{
			Severity: alert.Critical, Check: "webshell_realtime",
			FilePath: fmt.Sprintf("/home/acct/public_html/overflow-%d.php", i),
			Message:  fmt.Sprintf("overflow test %d", i), Timestamp: time.Now(),
		}
		for {
			select {
			case d.alertCh <- f:
			default:
				if time.Now().After(deadline) {
					t.Fatalf("finding %d could not be enqueued", i)
				}
				time.Sleep(time.Millisecond)
				continue
			}
			break
		}
	}

	deadline = time.Now().Add(alertHoldTestBudget)
	for time.Now().Before(deadline) && d.DroppedAlerts() != 3 {
		time.Sleep(time.Millisecond)
	}
	if got := d.DroppedAlerts(); got != 3 {
		t.Fatalf("held overflow was not drained before release: dropped = %d", got)
	}
	d.releaseAlertDispatch()
	deadline = time.Now().Add(alertHoldTestBudget)
	for time.Now().Before(deadline) {
		if dispatched.Load() == alertHoldMaxBatch {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := dispatched.Load(); got != alertHoldMaxBatch {
		t.Fatalf("dispatched = %d, want bounded batch %d", got, alertHoldMaxBatch)
	}
	if got := d.DroppedAlerts(); got != 3 {
		t.Fatalf("dropped alerts = %d, want 3", got)
	}
}

func TestAlertDispatcherPersistsHeldBatchOnShutdown(t *testing.T) {
	dir := t.TempDir()
	sdb, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.holdAlertDispatch()
	queued := []alert.Finding{{
		Severity: alert.Critical, Check: "held_shutdown",
		Message: "persist before release", Timestamp: time.Now(),
	}}
	d.alertCh <- queued[0]
	d.wg.Add(1)
	go d.alertDispatcher()
	close(d.stopCh)
	d.wg.Wait()

	assertHistoryContainsChecks(t, sdb, queued)
}
