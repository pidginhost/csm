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
	deadline := time.Now().Add(10 * time.Second)
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
	for time.Now().Before(deadline) {
		if int(dispatched.Load()) == produced {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dispatched %d of %d findings after release", dispatched.Load(), produced)
}
