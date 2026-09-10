package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type testQueueSource struct{ q *queuehealth.Tracker }

type testQueueBackend struct{ testQueueSource }

func (testQueueBackend) Mode() string        { return "bpf" }
func (testQueueBackend) EventCount() uint64  { return 0 }
func (testQueueBackend) Run(context.Context) {}

func TestQueueSourcesBackendRegistration(t *testing.T) {
	d := &Daemon{}
	q := queuehealth.New(4, time.Minute)
	q.Lose(time.Now(), 3)
	d.registerBackendQueues("bpf.execution", testQueueBackend{testQueueSource{q}})
	got, ok := d.QueueStatuses()["bpf.execution.output"]
	if !ok || got.DroppedTotal != 3 || got.Status != "degraded" {
		t.Fatalf("backend queue source was not published: found=%v status=%+v", ok, got)
	}
}

func (s testQueueSource) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"output": s.q.Snapshot(now)}
}

func TestQueueSourcesAppearInDaemonHealth(t *testing.T) {
	now := time.Unix(1000, 0)
	d := &Daemon{}
	q := queuehealth.New(4, time.Minute)
	q.Lose(now, 3)
	d.registerQueueSource("bpf.execution", testQueueSource{q})
	got, ok := d.queueStatuses(now)["bpf.execution.output"]
	if !ok || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Status != "degraded" {
		t.Fatalf("registered backend loss did not reach daemon health: found=%v status=%+v", ok, got)
	}
	if got := d.queueStatuses(now.Add(time.Minute))["bpf.execution.output"]; got.Status != "ok" || got.DroppedTotal != 3 {
		t.Fatalf("backend queue did not recover while retaining evidence: %+v", got)
	}
}

type registrationQueueSource struct {
	d *Daemon
	q *queuehealth.Tracker
}

func (s registrationQueueSource) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	s.d.registerQueueSource("late", testQueueSource{s.q})
	return map[string]queuehealth.Status{"output": s.q.Snapshot(now)}
}

func TestQueueSourcesDoNotHoldRegistryLockDuringSnapshot(t *testing.T) {
	previous := incidentCorrelator
	incidentCorrelator = nil
	t.Cleanup(func() { incidentCorrelator = previous })
	resetProcessCtxForTest()
	t.Cleanup(resetProcessCtxForTest)
	d := &Daemon{}
	q := queuehealth.New(4, time.Minute)
	d.registerQueueSource("first", registrationQueueSource{d, q})
	done := make(chan struct{})
	go func() { defer close(done); d.QueueStatuses() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot held the registry lock while calling a source")
	}
	if got := d.QueueStatuses(); len(got) != 14 || got["late.output"].Capacity != 4 || got["first.output"].Capacity != 4 || got["actionlog.writes"].Capacity != 64 || got["phpanel.spool"].Status != "ok" || got["smtp_rdns.resolves"].Capacity != 64 || got["email_password.hashes"].Capacity != 3 || !got["email_password.waiting"].CapacityUnavailable || !got["email_password.mailboxes"].CapacityUnavailable || !got["checks.executions"].CapacityUnavailable || !got["checks.dispatch"].CapacityUnavailable || !got["checks.plugin_inventory"].CapacityUnavailable || !got["checks.reputation_queries"].CapacityUnavailable || !got["checks.file_index.waiting"].CapacityUnavailable || got["checks.file_index.active"].Capacity != 1 {
		t.Fatalf("late registration was lost: %+v", got)
	}
}

func TestQueueSourcesRegistrationAndPollingAreConcurrent(t *testing.T) {
	previous := incidentCorrelator
	incidentCorrelator = nil
	t.Cleanup(func() { incidentCorrelator = previous })
	resetProcessCtxForTest()
	t.Cleanup(resetProcessCtxForTest)
	d := &Daemon{}
	q := queuehealth.New(4, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				d.registerQueueSource("backend", testQueueSource{q})
				d.QueueStatuses()
			}
		})
	}
	wg.Wait()
	if got := d.QueueStatuses(); len(got) != 13 || got["backend.output"].Capacity != 4 || got["actionlog.writes"].Capacity != 64 || got["phpanel.spool"].Status != "ok" || got["smtp_rdns.resolves"].Capacity != 64 || got["email_password.hashes"].Capacity != 3 || !got["email_password.waiting"].CapacityUnavailable || !got["email_password.mailboxes"].CapacityUnavailable || !got["checks.executions"].CapacityUnavailable || !got["checks.dispatch"].CapacityUnavailable || !got["checks.plugin_inventory"].CapacityUnavailable || !got["checks.reputation_queries"].CapacityUnavailable || !got["checks.file_index.waiting"].CapacityUnavailable || got["checks.file_index.active"].Capacity != 1 {
		t.Fatalf("concurrent publication lost or duplicated a source: %+v", got)
	}
}
