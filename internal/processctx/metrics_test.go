package processctx

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/metrics"
)

func TestRegisterMetricsExposesAllExpectedNames(t *testing.T) {
	cache := NewCache(8, time.Minute)
	enr := NewEnricher(cache, &fakeReader{}, EnricherConfig{Workers: 1, QueueCap: 2})
	reg := metrics.NewRegistry()
	RegisterMetrics(reg, cache, enr)

	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := sb.String()

	for _, name := range []string{
		"csm_process_context_cache_entries",
		"csm_process_context_cache_evictions_total",
		"csm_process_context_cache_ttl_purges_total",
		"csm_process_context_cache_misses_total",
		"csm_process_context_enrich_queue_drops_total",
		"csm_process_context_enrich_reads_total",
		"csm_process_context_enrich_errors_total",
		"csm_process_context_enrich_stale_total",
		"csm_process_context_enrich_latency_seconds",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("expected metric %q in output:\n%s", name, out)
		}
	}
}
