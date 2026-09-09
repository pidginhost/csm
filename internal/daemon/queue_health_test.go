package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/state"
)

func TestQueueHealthNotificationBypassesFullFindingChannel(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	}()
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.alertCh = make(chan alert.Finding, 1)
	d.alertCh <- alert.Finding{Check: "test_alert"}
	d.alertQueue = queuehealth.New(1, time.Minute)
	now := time.Now()
	d.alertQueue.Lose(now, 3)
	previousHook := alert.CentralHook
	var delivered []alert.Finding
	alert.SetCentralHook(func(f alert.Finding) { delivered = append(delivered, f) })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	previousScan := st.LatestScanTime()
	var reporter queuehealth.Reporter
	d.reportQueueHealth(now, &reporter)
	d.reportQueueHealth(now.Add(time.Second), &reporter)
	if len(delivered) != 1 || delivered[0].Check != "protection_queue_degraded" || !strings.Contains(delivered[0].Details, "findings.ingest") {
		t.Fatalf("full ingest channel hid or repeated health notification: %+v", delivered)
	}
	d.reportQueueHealth(now.Add(time.Minute), &reporter)
	d.reportQueueHealth(now.Add(2*time.Minute), &reporter)
	if len(delivered) != 2 || delivered[1].Check != "protection_queue_recovered" {
		t.Fatalf("recovery was lost or repeated: %+v", delivered)
	}
	history, total := st.ReadHistory(10, 0)
	if total != 2 || len(history) != 2 {
		t.Fatalf("health transitions missing from history: total=%d entries=%+v", total, history)
	}
	if !st.LatestScanTime().Equal(previousScan) {
		t.Fatal("health polling advanced the scan completion time")
	}
	if len(d.alertCh) != 1 {
		t.Fatal("health reporter consumed the blocked finding")
	}
}

func queueLifecycleDaemon(t *testing.T, capacity int) *Daemon {
	t.Helper()
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	t.Cleanup(restore)
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	})
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.alertCh = make(chan alert.Finding, capacity)
	d.alertQueue = queuehealth.New(capacity, time.Minute)
	t.Cleanup(alert.RegisterQueue(d.alertCh, d.alertQueue))
	return d
}

func TestQueueHealthReleasesDuplicatesAndPreviouslySentFindings(t *testing.T) {
	d := queueLifecycleDaemon(t, 3)
	finding := alert.Finding{Check: "queue_lifecycle", Severity: alert.Warning, Message: "duplicate finding"}
	for round := 0; round < 2; round++ {
		for i := 0; i < 3; i++ {
			if !alert.TryEnqueue(d.alertCh, finding) {
				t.Fatal("queue rejected a finding within its capacity")
			}
		}
		batch := d.drainAlertChannel(nil)
		if q := d.alertQueue.Snapshot(time.Now()); q.Depth != 0 || q.InFlight != 3 {
			t.Fatalf("batch was not claimed: %+v", q)
		}
		d.dispatchBatch(batch)
		if q := d.alertQueue.Snapshot(time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
			t.Fatalf("round %d leaked filtered or duplicate tickets: %+v", round, q)
		}
	}
	history, total := d.store.ReadHistory(10, 0)
	if total != 1 || len(history) != 1 || history[0].Check != finding.Check {
		t.Fatalf("duplicate or previously sent finding was recorded again: total=%d history=%+v", total, history)
	}
}

func TestQueueHealthHeldOverflowAndShutdownAccounting(t *testing.T) {
	d := queueLifecycleDaemon(t, alertHoldMaxBatch+3)
	d.holdAlertDispatch()
	for i := 0; i < alertHoldMaxBatch+3; i++ {
		if !alert.TryEnqueue(d.alertCh, alert.Finding{
			Check: "queue_lifecycle", Severity: alert.Warning, Message: fmt.Sprintf("held finding %d", i),
		}) {
			t.Fatalf("queue rejected finding %d before the dispatcher started", i)
		}
	}
	d.wg.Add(1)
	go d.alertDispatcher()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			close(d.stopCh)
			d.wg.Wait()
		}
	})
	deadline := time.Now().Add(alertHoldTestBudget)
	for d.DroppedAlerts() != 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	q := d.alertQueue.Snapshot(time.Now())
	if q.Depth != 0 || q.InFlight != alertHoldMaxBatch || q.DroppedTotal != 3 || q.Status != "degraded" {
		t.Fatalf("held overflow lost accounting: %+v", q)
	}
	close(d.stopCh)
	d.wg.Wait()
	stopped = true
	if q := d.alertQueue.Snapshot(time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 {
		t.Fatalf("shutdown did not release the held batch: %+v", q)
	}
	_, total := d.store.ReadHistory(1, 0)
	if total != alertHoldMaxBatch {
		t.Fatalf("shutdown persisted %d findings, want %d", total, alertHoldMaxBatch)
	}
}
