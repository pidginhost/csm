package daemon

import (
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/processctx"
)

// TestMain pins the initial registry seam to a private registry for this
// package. resetProcessCtxForTest also installs a fresh private registry before
// each singleton rebuild, so repeated ProcessCtx() calls in tests never register
// csm_process_context_* metrics on metrics.Default or on a reused registry.
func TestMain(m *testing.M) {
	processCtxRegistry = metrics.NewRegistry
	os.Exit(m.Run())
}

func TestProcessCtxSingletonReturnsSameInstance(t *testing.T) {
	resetProcessCtxForTest()
	c1, e1 := ProcessCtx()
	c2, e2 := ProcessCtx()
	if c1 != c2 || e1 != e2 {
		t.Fatal("expected singleton instances")
	}
}

func TestProcessCtxSingletonStartsEnricher(t *testing.T) {
	resetProcessCtxForTest()
	cache, enr := ProcessCtx()
	if enr == nil || cache == nil {
		t.Fatal("nil singleton")
	}
	// Enqueue a PID for current process and confirm a worker eventually picks
	// it up. We don't assert the exact contents - just that Reads counter
	// advances, proving a worker is alive.
	if !enr.Enqueue(processctx.EnrichRequest{PID: 1}) {
		t.Fatal("Enqueue(1) refused")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if enr.Stats().Reads > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("worker never advanced Reads counter; stats=%+v", enr.Stats())
}
