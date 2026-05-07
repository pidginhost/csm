package daemon

import (
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/processctx"
)

// TestMain pins both registry seams (process-context from Phase 1 +
// incidents from Phase 2) to private registries for this package, so
// tests never register csm_process_context_* or csm_incidents_* on
// metrics.Default. resetProcessCtxForTest and resetIncidentForTest
// re-pin on every reset.
func TestMain(m *testing.M) {
	processCtxRegistry = metrics.NewRegistry
	incidentRegistry = metrics.NewRegistry
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
