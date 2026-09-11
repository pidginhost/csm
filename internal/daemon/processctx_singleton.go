package daemon

import (
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/processctx"
)

const (
	processCtxCacheCap         = 16384
	processCtxCacheTTL         = 30 * time.Minute
	processCtxEnrichWorkers    = 2
	processCtxEnrichQueueCap   = 1024
	processCtxProcRoot         = "/proc"
	processCtxProcReadDeadline = 10 * time.Millisecond
)

var (
	processCtxOnce      sync.Once
	processCtxCache     *processctx.Cache
	processCtxEnr       *processctx.Enricher
	processCtxPublished atomic.Pointer[processctx.Enricher]
	processCtxRegistry  = metrics.Default
)

var processCtxReadStartedAt = defaultProcessCtxReadStartedAt

func defaultProcessCtxReadStartedAt(pid int) (time.Time, bool) {
	return processctx.NewProcReader(processCtxProcRoot, processCtxProcReadDeadline).ReadStartedAt(pid)
}

func processCtxStartedAt(pid int) time.Time {
	t, ok := processCtxReadStartedAt(pid)
	if !ok {
		return time.Time{}
	}
	return t
}

// ProcessCtx returns the daemon-wide process-context cache and enricher,
// constructing them on first call and registering metrics on the default
// registry. Safe for concurrent callers.
func ProcessCtx() (*processctx.Cache, *processctx.Enricher) {
	processCtxOnce.Do(func() {
		processCtxCache = processctx.NewCache(processCtxCacheCap, processCtxCacheTTL)
		reader := processctx.NewProcReader(processCtxProcRoot, processCtxProcReadDeadline)
		processCtxEnr = processctx.NewEnricher(processCtxCache, reader, processctx.EnricherConfig{
			Workers:  processCtxEnrichWorkers,
			QueueCap: processCtxEnrichQueueCap,
			Resolver: daemonProcessIdentityResolver{},
		})
		processctx.RegisterMetrics(processCtxRegistry(), processCtxCache, processCtxEnr)
		processCtxPublished.Store(processCtxEnr)
		processCtxEnr.Start()
		wireAncestryProbeIfAvailable(processCtxCache)
	})
	return processCtxCache, processCtxEnr
}

func stopProcessCtx() {
	if enr := processCtxPublished.Load(); enr != nil {
		enr.Stop()
	}
}

type daemonProcessIdentityResolver struct{}

func (daemonProcessIdentityResolver) Resolve(uid int) (string, string) {
	if uid < 0 || uid > math.MaxUint32 {
		return "", ""
	}
	user := checks.LookupUser(uint32(uid))
	account := resolveLocalAccountForUID(uid, user)
	return user, account
}

func resolveLocalAccountForUID(uid int, user string) string {
	// First phase: for normal hosted account UIDs, the username is the account
	// on cPanel and plain Linux fallback hosts. Later phases can replace this
	// helper with a platform-backed account enumerator without changing the
	// processctx package.
	if uid >= 1000 && user != "" && !strings.HasPrefix(user, "uid:") {
		return user
	}
	return ""
}

// resetProcessCtxForTest is a test seam. Callers in tests must run with
// t.Setenv or similar isolation; production code never invokes this.
func resetProcessCtxForTest() {
	if processCtxEnr != nil {
		processCtxEnr.Stop()
	}
	processCtxPublished.Store(nil)
	processCtxOnce = sync.Once{}
	processCtxCache = nil
	processCtxEnr = nil
	processCtxRegistry = metrics.NewRegistry
	processCtxReadStartedAt = defaultProcessCtxReadStartedAt
}
