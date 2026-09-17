package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
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
	var ingestEvents []alert.Finding
	alert.SetCentralHook(func(f alert.Finding) {
		delivered = append(delivered, f)
		// Other tests can leave valid health evidence in shared queue owners.
		// This test verifies the ingest queue without hiding their delivery.
		if strings.HasPrefix(f.Details, "queue=findings.ingest ") {
			ingestEvents = append(ingestEvents, f)
		}
	})
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	previousScan := st.LatestScanTime()
	var reporter queuehealth.Reporter
	d.reportQueueHealth(now, &reporter)
	d.reportQueueHealth(now.Add(time.Second), &reporter)
	if len(ingestEvents) != 1 || ingestEvents[0].Check != "protection_queue_degraded" {
		t.Fatalf("full ingest channel hid or repeated health notification: %+v", delivered)
	}
	d.reportQueueHealth(now.Add(time.Minute), &reporter)
	d.reportQueueHealth(now.Add(2*time.Minute), &reporter)
	if len(ingestEvents) != 2 || ingestEvents[1].Check != "protection_queue_recovered" {
		t.Fatalf("recovery was lost or repeated: %+v", delivered)
	}
	history, total := st.ReadHistory(len(delivered), 0)
	if total != len(delivered) || len(history) != len(delivered) {
		t.Fatalf("health transitions missing from history: total=%d entries=%+v", total, history)
	}
	ingestHistory := 0
	for _, f := range history {
		if strings.HasPrefix(f.Details, "queue=findings.ingest ") {
			ingestHistory++
		}
	}
	if ingestHistory != 2 {
		t.Fatalf("ingest transitions missing from history: %+v", history)
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

func TestQueueHealthCanceledBatchesCountEveryAbandonedFinding(t *testing.T) {
	findings := []alert.Finding{
		{Check: "first", Severity: alert.Critical},
		{Check: "second", Severity: alert.High},
		{Check: "third", Severity: alert.Critical},
	}
	for _, producer := range []string{"scan", "pam", "mail", "auth_backend"} {
		for _, accepted := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/accepted_%d", producer, accepted), func(t *testing.T) {
				d := queueLifecycleDaemon(t, 0)
				var consumed chan struct{}
				if accepted == 0 {
					close(d.stopCh)
				} else {
					consumed = make(chan struct{})
					go func() {
						defer close(consumed)
						f := <-d.alertCh
						alert.StartQueued(f)
						alert.FinishQueued([]alert.Finding{f})
						close(d.stopCh)
					}()
				}
				batchSize := 3
				switch producer {
				case "scan":
					batch := append([]alert.Finding{findings[0], {Check: "perf_wp_cron", Severity: alert.Warning}}, findings[1:]...)
					d.enqueueScanAlertsWithin(batch, "canceled test scan", time.Hour)
				case "pam":
					p := &PAMListener{alertCh: d.alertCh, stopCh: d.stopCh}
					p.emit(findings)
				case "mail":
					if d.dispatchMailLogLine(maillog.Line{}, func(string, *config.Config) []alert.Finding { return findings }) {
						t.Fatal("canceled mail batch reported success")
					}
				case "auth_backend":
					fixture := newHealthFixture(t, true, 0, time.Minute, 1)
					fixture.healthy = false
					d.authBackend = fixture.h
					if d.emitAuthBackendFindings() {
						t.Fatal("canceled auth backend batch reported success")
					}
					if fixture.restarts != 1 {
						t.Fatalf("expected a degradation and a restart finding, restarts=%d", fixture.restarts)
					}
					batchSize = 2
				}
				if consumed != nil {
					<-consumed
				}
				wantDropped := batchSize - accepted
				got := d.alertQueue.Snapshot(time.Now())
				if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != uint64(wantDropped) || got.RecentDrops != uint64(wantDropped) {
					t.Fatalf("canceled batch accounting = %+v; want no pending work and %d abandoned findings", got, wantDropped)
				}
			})
		}
	}
}

func TestQueueHealthStartupHoldIsNotDelay(t *testing.T) {
	d := queueLifecycleDaemon(t, 4)
	prevInterval := alertBatchInterval
	alertBatchInterval = time.Hour
	t.Cleanup(func() { alertBatchInterval = prevInterval })
	previousHook := alert.CentralHook
	var ingestEvents []alert.Finding
	alert.SetCentralHook(func(f alert.Finding) {
		if strings.Contains(f.Details, "queue=findings.ingest") {
			ingestEvents = append(ingestEvents, f)
		}
	})
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	d.holdAlertDispatch()
	if !alert.TryEnqueue(d.alertCh, alert.Finding{Check: "queue_lifecycle", Severity: alert.Warning, Message: "held finding"}) {
		t.Fatal("queue rejected a finding within its capacity")
	}
	d.wg.Add(1)
	go d.alertDispatcher()
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})
	deadline := time.Now().Add(alertHoldTestBudget)
	for d.alertQueue.Snapshot(time.Now()).InFlight != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var reporter queuehealth.Reporter
	d.reportQueueHealth(time.Now().Add(2*time.Minute), &reporter)
	if len(ingestEvents) != 0 {
		t.Fatalf("startup hold reported as a stalled ingest queue: %+v", ingestEvents)
	}
	release := time.Now()
	d.releaseAlertDispatch()
	s := d.alertQueue.Snapshot(release.Add(30 * time.Second))
	if s.Status != "ok" || s.InFlight != 1 || s.ProcessingSeconds <= 29 || s.ProcessingSeconds > 30 {
		t.Fatalf("held work did not resume processing from the release: %+v", s)
	}
	d.reportQueueHealth(release.Add(30*time.Second), &reporter)
	if len(ingestEvents) != 0 {
		t.Fatalf("released hold reported as a stalled ingest queue: %+v", ingestEvents)
	}
}
