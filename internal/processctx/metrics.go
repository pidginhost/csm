package processctx

import "github.com/pidginhost/csm/internal/metrics"

// RegisterMetrics binds cache and enricher counters/gauges to reg. The
// registry argument allows tests to use a private registry. Production
// callers should pass metrics.Default().
func RegisterMetrics(reg *metrics.Registry, cache *Cache, enr *Enricher) {
	reg.RegisterGaugeFunc(
		"csm_process_context_cache_entries",
		"Live process-context cache entries.",
		func() float64 { return float64(cache.Stats().Entries) },
	)
	reg.RegisterCounterFunc(
		"csm_process_context_cache_evictions_total",
		"Process-context cache LRU evictions (cap exceeded).",
		func() float64 { return float64(cache.Stats().Evictions) },
	)
	reg.RegisterCounterFunc(
		"csm_process_context_cache_ttl_purges_total",
		"Process-context cache entries dropped because TTL expired on lookup.",
		func() float64 { return float64(cache.Stats().TTLPurges) },
	)
	reg.RegisterCounterFunc(
		"csm_process_context_cache_misses_total",
		"Process-context cache lookup misses (includes TTL purges).",
		func() float64 { return float64(cache.Stats().Misses) },
	)
	reg.RegisterCounterFunc(
		"csm_process_context_enrich_queue_drops_total",
		"Process-context enrichment requests dropped because queue was full.",
		func() float64 { return float64(enr.Stats().Drops) },
	)
	reg.RegisterCounterFunc(
		"csm_process_context_enrich_reads_total",
		"Process-context /proc reads attempted by enricher workers.",
		func() float64 { return float64(enr.Stats().Reads) },
	)
	reg.RegisterCounterFunc(
		"csm_process_context_enrich_errors_total",
		"Process-context /proc read errors (excluding ProcessGone).",
		func() float64 { return float64(enr.Stats().Errors) },
	)
	reg.RegisterCounterFunc(
		"csm_process_context_enrich_stale_total",
		"Process-context enrichment results rejected as stale PID reuse.",
		func() float64 { return float64(enr.Stats().Stale) },
	)
	latency := metrics.NewHistogram(
		"csm_process_context_enrich_latency_seconds",
		"Process-context enrichment worker latency in seconds.",
		[]float64{0.001, 0.005, 0.01, 0.05, 0.1, 1},
	)
	reg.MustRegister("csm_process_context_enrich_latency_seconds", latency)
	enr.SetLatencyObserver(latency.Observe)
}
