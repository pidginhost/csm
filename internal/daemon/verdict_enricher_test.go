package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/verdict"
)

func testEnricher(t *testing.T, ask verdictAskFunc) *verdictEnricher {
	t.Helper()
	e := newVerdictEnricher(verdictEnricherOpts{
		Ask:     ask,
		Workers: 2,
		Queue:   4,
		TTL:     time.Minute,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		e.wait()
	})
	e.start(ctx)
	return e
}

// The ring buffer holds 256 events. A verdict callback that blocks the consumer
// for its whole timeout costs real security events, so enrichment must never be
// on the path that reads them.
func TestVerdictEnricher_DoesNotBlockOnMiss(t *testing.T) {
	release := make(chan struct{})
	var asked atomic.Int32
	e := testEnricher(t, func(ctx context.Context, req verdict.Request) (verdict.Response, error) {
		asked.Add(1)
		<-release
		return verdict.Response{Verdict: "block"}, nil
	})
	t.Cleanup(func() { close(release) })

	f := alert.Finding{Check: "bpf_egress"}
	done := make(chan struct{})
	go func() {
		e.annotate(&f, "198.51.100.7", "bpf_enforcement:bpf_egress:443", "Critical")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("annotate blocked on an in-flight callback")
	}
}

// A burst to one destination is the common case; it must cost one callback,
// not one per packet.
func TestVerdictEnricher_CachesPerDestinationAndReason(t *testing.T) {
	var asked atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	e := testEnricher(t, func(ctx context.Context, req verdict.Request) (verdict.Response, error) {
		if asked.Add(1) == 1 {
			defer wg.Done()
		}
		return verdict.Response{Verdict: "block", TenantID: "acct42"}, nil
	})

	const ip, reason = "198.51.100.9", "bpf_enforcement:bpf_egress:443"
	first := alert.Finding{Check: "bpf_egress"}
	e.annotate(&first, ip, reason, "Critical")
	wg.Wait()

	// A later event for the same destination is served from the cache.
	var second alert.Finding
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		second = alert.Finding{Check: "bpf_egress"}
		if e.annotate(&second, ip, reason, "Critical") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if second.TenantID != "acct42" {
		t.Errorf("cached verdict not applied: TenantID = %q", second.TenantID)
	}
	for i := 0; i < 20; i++ {
		f := alert.Finding{Check: "bpf_egress"}
		e.annotate(&f, ip, reason, "Critical")
	}
	if got := asked.Load(); got != 1 {
		t.Errorf("callbacks issued = %d, want 1 for one destination", got)
	}
}

// When enrichment cannot keep up the enrichment is what gets dropped, and it is
// counted. The finding itself is never the thing sacrificed.
func TestVerdictEnricher_DropsEnrichmentNotFindings(t *testing.T) {
	block := make(chan struct{})
	e := testEnricher(t, func(ctx context.Context, req verdict.Request) (verdict.Response, error) {
		<-block
		return verdict.Response{}, nil
	})
	t.Cleanup(func() { close(block) })

	// Distinct destinations: one destination is collapsed to a single job by
	// the in-flight guard, so saturation comes from a scan touching many.
	for i := 0; i < 64; i++ {
		f := alert.Finding{Check: "bpf_egress"}
		e.annotate(&f, fmt.Sprintf("198.51.100.%d", i), "reason", "Critical")
	}
	if e.droppedEnrichments() == 0 {
		t.Error("a saturated queue did not record a dropped enrichment")
	}
}

// A failed callback must not be cached as an answer: the next event should try
// again rather than inherit a permanent blank.
func TestVerdictEnricher_DoesNotCacheFailures(t *testing.T) {
	var asked atomic.Int32
	e := testEnricher(t, func(ctx context.Context, req verdict.Request) (verdict.Response, error) {
		asked.Add(1)
		return verdict.Response{}, errors.New("callback unreachable")
	})

	const ip, reason = "198.51.100.13", "reason"
	for i := 0; i < 3; i++ {
		f := alert.Finding{Check: "bpf_egress"}
		e.annotate(&f, ip, reason, "Critical")
		time.Sleep(30 * time.Millisecond)
	}
	if asked.Load() < 2 {
		t.Errorf("callbacks issued = %d, want a retry after failure", asked.Load())
	}
}
