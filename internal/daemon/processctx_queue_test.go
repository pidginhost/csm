package daemon

import (
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/processctx"
)

func TestProcessContextQueueHealthDoesNotStartThePool(t *testing.T) {
	resetProcessCtxForTest()
	t.Cleanup(resetProcessCtxForTest)
	d := &Daemon{}
	if _, exists := d.QueueStatuses()["processctx.enrichment"]; exists {
		t.Fatal("uninitialized process-context pool was reported as active")
	}
	if processCtxCache != nil || processCtxEnr != nil {
		t.Fatal("health polling created process-context workers")
	}
	_, enr := ProcessCtx()
	got, exists := d.QueueStatuses()["processctx.enrichment"]
	if !exists || got.Capacity != 1024 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
		t.Fatalf("initialized process-context pool is missing from health: exists=%v status=%+v", exists, got)
	}
	enr.Stop()
	got, exists = d.QueueStatuses()["processctx.enrichment"]
	if !exists || got.Depth != 0 || got.InFlight != 0 {
		t.Fatalf("stopped pool lost its final health evidence: exists=%v status=%+v", exists, got)
	}
}

func TestProcessContextQueuePublishesSafelyDuringHealthReads(t *testing.T) {
	resetProcessCtxForTest()
	t.Cleanup(resetProcessCtxForTest)
	d := &Daemon{}
	start := make(chan struct{})
	var callers sync.WaitGroup
	for range 4 {
		callers.Go(func() {
			<-start
			ProcessCtx()
		})
		callers.Go(func() {
			<-start
			for range 32 {
				if got, exists := d.QueueStatuses()["processctx.enrichment"]; exists && (got.Capacity != 1024 || got.Status != "ok") {
					t.Errorf("partially initialized process-context pool was published: %+v", got)
				}
			}
		})
	}
	close(start)
	callers.Wait()
	if _, exists := d.QueueStatuses()["processctx.enrichment"]; !exists {
		t.Fatal("completed initialization did not publish process-context health")
	}
}

func TestProcessContextQueueStopRetainsEvidenceWithoutInitializing(t *testing.T) {
	resetProcessCtxForTest()
	t.Cleanup(resetProcessCtxForTest)
	stopProcessCtx()
	if processCtxCache != nil || processCtxEnr != nil {
		t.Fatal("shutdown initialized a process-context pool")
	}
	_, enr := ProcessCtx()
	stopProcessCtx()
	if enr.Enqueue(processctx.EnrichRequest{PID: 1}) {
		t.Fatal("daemon shutdown left the process-context pool accepting requests")
	}
	d := &Daemon{}
	got, exists := d.QueueStatuses()["processctx.enrichment"]
	if !exists || got.DroppedTotal != 1 || got.Depth != 0 || got.InFlight != 0 {
		t.Fatalf("daemon shutdown discarded process-context evidence: exists=%v status=%+v", exists, got)
	}
	stopProcessCtx()
	if got = d.QueueStatuses()["processctx.enrichment"]; got.DroppedTotal != 1 {
		t.Fatalf("repeated daemon shutdown changed prior loss: %+v", got)
	}
}
