package threatintel

import (
	"sync"

	"github.com/pidginhost/csm/internal/metrics"
)

var upstreamMetricsOnce sync.Once

// RegisterUpstreamMetrics binds the upstream source's counters to reg
// so operators can observe cache effectiveness and upstream health.
// Production callers pass metrics.Default(); tests pass an isolated
// registry. Source must outlive the registry. Idempotent: subsequent
// calls in the same process are no-ops, mirroring how the daemon
// rebuilds the aggregator on every reputation check.
func RegisterUpstreamMetrics(reg *metrics.Registry, src *UpstreamSource) {
	if reg == nil || src == nil {
		return
	}
	upstreamMetricsOnce.Do(func() {
		registerUpstreamMetricsLocked(reg, src)
	})
}

func registerUpstreamMetricsLocked(reg *metrics.Registry, src *UpstreamSource) {
	reg.RegisterCounterFunc(
		"csm_threatintel_cache_hits_total",
		"Upstream threat-intel cache hits.",
		func() float64 {
			h, _, _ := src.MetricsSnapshot()
			return float64(h)
		},
	)
	reg.RegisterCounterFunc(
		"csm_threatintel_cache_misses_total",
		"Upstream threat-intel cache misses (a real HTTP request followed).",
		func() float64 {
			_, m, _ := src.MetricsSnapshot()
			return float64(m)
		},
	)
	reg.RegisterCounterFunc(
		"csm_threatintel_backend_failures_total",
		"Upstream threat-intel backend failures (network, 4xx, 5xx, malformed body).",
		func() float64 {
			_, _, f := src.MetricsSnapshot()
			return float64(f)
		},
	)
	reg.RegisterGaugeFunc(
		"csm_threatintel_breaker_open",
		"Circuit breaker for the upstream source; 1 when open (calls refused), 0 when closed or half-open.",
		func() float64 {
			if src.BreakerOpen() {
				return 1
			}
			return 0
		},
	)
}
