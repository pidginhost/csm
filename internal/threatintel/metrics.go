package threatintel

import (
	"sync"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/metrics"
)

var upstreamMetrics = struct {
	mu         sync.Mutex
	registered map[*metrics.Registry]struct{}
	active     atomic.Pointer[UpstreamSource]

	cacheHitsTotal       atomic.Int64
	cacheMissesTotal     atomic.Int64
	backendFailuresTotal atomic.Int64
}{
	registered: make(map[*metrics.Registry]struct{}),
}

// RegisterUpstreamMetrics binds upstream counters to reg so operators
// can observe cache effectiveness and upstream health.
// Production callers pass metrics.Default(); tests pass an isolated
// registry. Idempotent per registry because reputation checks rebuild
// the upstream source every cycle.
func RegisterUpstreamMetrics(reg *metrics.Registry, src *UpstreamSource) {
	if reg == nil || src == nil {
		return
	}
	upstreamMetrics.active.Store(src)
	upstreamMetrics.mu.Lock()
	if _, ok := upstreamMetrics.registered[reg]; ok {
		upstreamMetrics.mu.Unlock()
		return
	}
	upstreamMetrics.registered[reg] = struct{}{}
	upstreamMetrics.mu.Unlock()
	registerUpstreamMetricsLocked(reg)
}

// ClearUpstreamMetricsSource clears the source used by the breaker
// gauge when upstream reputation is disabled by a hot-reloaded config.
func ClearUpstreamMetricsSource() {
	upstreamMetrics.active.Store(nil)
}

func registerUpstreamMetricsLocked(reg *metrics.Registry) {
	reg.RegisterCounterFunc(
		"csm_threatintel_cache_hits_total",
		"Upstream threat-intel cache hits.",
		func() float64 {
			return float64(upstreamMetrics.cacheHitsTotal.Load())
		},
	)
	reg.RegisterCounterFunc(
		"csm_threatintel_cache_misses_total",
		"Upstream threat-intel lookups not served from the local cache.",
		func() float64 {
			return float64(upstreamMetrics.cacheMissesTotal.Load())
		},
	)
	reg.RegisterCounterFunc(
		"csm_threatintel_backend_failures_total",
		"Upstream threat-intel backend failures (network, 4xx, 5xx, malformed body).",
		func() float64 {
			return float64(upstreamMetrics.backendFailuresTotal.Load())
		},
	)
	reg.RegisterGaugeFunc(
		"csm_threatintel_breaker_open",
		"Circuit breaker for the upstream source; 1 when open (calls refused), 0 when closed or half-open.",
		func() float64 {
			src := activeUpstreamMetricsSource()
			if src != nil && src.BreakerOpen() {
				return 1
			}
			return 0
		},
	)
}

func activeUpstreamMetricsSource() *UpstreamSource {
	return upstreamMetrics.active.Load()
}

func resetUpstreamMetricsForTest() {
	upstreamMetrics.active.Store(nil)
	upstreamMetrics.cacheHitsTotal.Store(0)
	upstreamMetrics.cacheMissesTotal.Store(0)
	upstreamMetrics.backendFailuresTotal.Store(0)
}
