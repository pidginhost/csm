package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/reporting"
)

func TestAbuseQueuePublishedBeforeWorkerStarts(t *testing.T) {
	previous := alert.ReportHook
	t.Cleanup(func() { alert.SetReportHook(previous) })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSM_TEST_ABUSE_QUEUE_KEY", hex.EncodeToString(key))
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.Report.Enabled = true
	cfg.Reputation.Report.Classes = []string{"bruteforce"}
	cfg.Reputation.Report.Targets = []reportTargetConfig{{
		Name: "collector", URL: "https://collector.example/report", Transport: "ed25519",
		NodeID: "node", KeyID: "key", KeyEnv: "CSM_TEST_ABUSE_QUEUE_KEY",
	}}
	d := New(cfg, nil, nil, "")
	loop := d.startAbuseReporting()
	if loop == nil {
		t.Fatal("configured abuse reporter did not start")
	}
	t.Cleanup(func() {
		go loop()
		d.stopAbuseReporting()
	})
	got, exists := d.QueueStatuses()["abuse_reporting.ingress"]
	if !exists || got.Capacity != 10000 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
		t.Fatalf("abuse report queue is missing before publication: exists=%v status=%+v", exists, got)
	}
	got, exists = d.QueueStatuses()["abuse_reporting.spool"]
	if !exists || got.Capacity != 10000 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" || got.LagBasis != "observed_age" {
		t.Fatalf("durable abuse queue is missing before publication: exists=%v status=%+v", exists, got)
	}
}

func TestAbuseQueueShutdownPersistsEveryAcceptedReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop, release := make(chan struct{}), make(chan struct{})
		stopLoop := sync.OnceFunc(func() { close(stop) })
		releaseWrite := sync.OnceFunc(func() { close(release) })
		var persisted []string
		consumer := newAbuseReportConsumer(stop, 3, time.Hour, func(r reporting.Report) error {
			<-release
			persisted = append(persisted, r.IP)
			return nil
		}, func(context.Context) {})
		done := make(chan struct{})
		go func() { defer close(done); consumer.run() }()
		defer func() { stopLoop(); releaseWrite(); <-done }()
		if !consumer.enqueue(reporting.Report{IP: "192.0.2.1"}) {
			t.Fatal("first report refused")
		}
		synctest.Wait()
		for _, ip := range []string{"192.0.2.2", "192.0.2.3", "192.0.2.4"} {
			if !consumer.enqueue(reporting.Report{IP: ip}) {
				t.Fatal("waiting report refused")
			}
		}
		if consumer.enqueue(reporting.Report{IP: "192.0.2.5"}) {
			t.Fatal("full queue accepted excess report")
		}
		time.Sleep(61 * time.Second)
		got := consumer.QueueStatuses(time.Now())["ingress"]
		if got.Depth != 3 || got.Capacity != 3 || got.InFlight != 1 || got.DroppedTotal != 1 || got.LagSeconds != 61 || got.ProcessingSeconds != 61 || got.Status != "degraded" {
			t.Fatalf("blocked persistence concealed report backlog: %+v", got)
		}
		captured := consumer.enqueue
		stopLoop()
		if captured(reporting.Report{IP: "192.0.2.6"}) {
			t.Fatal("captured hook accepted report during shutdown")
		}
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("shutdown returned before accepted reports persisted")
		default:
		}
		releaseWrite()
		<-done
		got = consumer.QueueStatuses(time.Now())["ingress"]
		if !reflect.DeepEqual(persisted, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}) || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 2 {
			t.Fatalf("shutdown lost or repeated accepted reports: persisted=%v status=%+v", persisted, got)
		}
		if captured(reporting.Report{IP: "192.0.2.7"}) {
			t.Fatal("captured hook accepted report after shutdown")
		}
		if got = consumer.QueueStatuses(time.Now())["ingress"]; got.DroppedTotal != 3 || got.Depth != 0 {
			t.Fatalf("late report loss missing: %+v", got)
		}
	})
}

func TestAbuseQueueRetainsReportsDuringDeliveryAndCancelsOnStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop := make(chan struct{})
		var persisted []string
		var deliveries int
		consumer := newAbuseReportConsumer(stop, 2, time.Minute, func(r reporting.Report) error {
			persisted = append(persisted, r.IP)
			return nil
		}, func(ctx context.Context) { deliveries++; <-ctx.Done() })
		done := make(chan struct{})
		go func() { defer close(done); consumer.run() }()
		synctest.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
			if !consumer.enqueue(reporting.Report{IP: ip}) {
				t.Fatal("queued report refused")
			}
		}
		time.Sleep(61 * time.Second)
		got := consumer.QueueStatuses(time.Now())["ingress"]
		if got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 0 || got.LagSeconds != 61 || got.Status != "degraded" {
			t.Fatalf("outbound delivery concealed unpersisted reports: %+v", got)
		}
		close(stop)
		<-done
		got = consumer.QueueStatuses(time.Now())["ingress"]
		if deliveries != 1 || !reflect.DeepEqual(persisted, []string{"192.0.2.1", "192.0.2.2"}) || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("canceled delivery prevented durable shutdown: deliveries=%d persisted=%v status=%+v", deliveries, persisted, got)
		}
	})
}

func TestAbuseQueuePersistenceFailureContinuesShutdownDrain(t *testing.T) {
	stop := make(chan struct{})
	var attempted []string
	consumer := newAbuseReportConsumer(stop, 3, time.Hour, func(r reporting.Report) error {
		attempted = append(attempted, r.IP)
		if r.IP == "192.0.2.2" {
			return errors.New("spool write failed")
		}
		return nil
	}, func(context.Context) {})
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if !consumer.enqueue(reporting.Report{IP: ip}) {
			t.Fatal("initial report refused")
		}
	}
	close(stop)
	consumer.run()
	got := consumer.QueueStatuses(time.Now())["ingress"]
	if !reflect.DeepEqual(attempted, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
		t.Fatalf("one failed write lost unrelated reports or its loss evidence: attempted=%v status=%+v", attempted, got)
	}
}

func TestAbuseQueuePanicAccountsForUnpersistedReports(t *testing.T) {
	for _, at := range []string{"running", "shutdown"} {
		t.Run(at, func(t *testing.T) {
			stop := make(chan struct{})
			consumer := newAbuseReportConsumer(stop, 3, time.Hour, func(reporting.Report) error { panic("spool failed") }, func(context.Context) {})
			for range 3 {
				if !consumer.enqueue(reporting.Report{IP: "192.0.2.1"}) {
					t.Fatal("initial report refused")
				}
			}
			if at == "shutdown" {
				close(stop)
			}
			var caught any
			func() { defer func() { caught = recover() }(); consumer.run() }()
			if caught != "spool failed" {
				t.Fatalf("persistence panic was concealed: %v", caught)
			}
			got := consumer.QueueStatuses(time.Now())["ingress"]
			if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 {
				t.Fatalf("panic lost abandoned reports: %+v", got)
			}
			if consumer.enqueue(reporting.Report{IP: "192.0.2.2"}) {
				t.Fatal("failed worker accepted report")
			}
		})
	}
}

func TestAbuseQueueConcurrentShutdownConservesReports(t *testing.T) {
	stop, done := make(chan struct{}), make(chan struct{})
	var accepted, refused atomic.Uint64
	var failed uint64
	attempts := make(map[int]int)
	consumer := newAbuseReportConsumer(stop, 4, time.Hour, func(r reporting.Report) error {
		attempts[r.Count]++
		if r.Count%3 == 0 {
			failed++
			return errors.New("spool write failed")
		}
		return nil
	}, func(context.Context) {})
	go func() { defer close(done); consumer.run() }()
	start := make(chan struct{})
	var producers sync.WaitGroup
	for p := range 4 {
		producers.Go(func() {
			<-start
			for n := range 64 {
				if consumer.enqueue(reporting.Report{IP: "192.0.2.1", Count: p*64 + n}) {
					accepted.Add(1)
				} else {
					refused.Add(1)
				}
			}
		})
	}
	producers.Go(func() { <-start; close(stop) })
	close(start)
	producers.Wait()
	<-done
	got := consumer.QueueStatuses(time.Now())["ingress"]
	if accepted.Load()+refused.Load() != 256 || uint64(len(attempts)) != accepted.Load() || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != refused.Load()+failed {
		t.Fatalf("concurrent drain lost reports: accepted=%d refused=%d attempted=%d failed=%d status=%+v", accepted.Load(), refused.Load(), len(attempts), failed, got)
	}
	for id, count := range attempts {
		if count != 1 {
			t.Fatalf("report %d persisted %d times", id, count)
		}
	}
}
