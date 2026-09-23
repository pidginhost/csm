package webui

import (
	"sort"
	"sync/atomic"
	"time"
)

// apiRateLimitMaxIPs caps how many source addresses the unauthenticated
// per-IP rate-limit maps hold. The five-minute prune bounded them over time
// but not between prunes: a scan from many addresses grew them without
// limit in the meantime.
const apiRateLimitMaxIPs = 10000

// rateLimitSweeps counts full passes over a rate-limit map; tests read it.
var rateLimitSweeps atomic.Int64

// boundRateLimitMap keeps m under apiRateLimitMaxIPs before a new address
// is inserted. Caller holds the map's mutex. A full map is swept once down
// to nine tenths of the ceiling: stale entries (no hit after cutoff) go
// first, then the addresses with the oldest last hit. Sweeping one address
// at a time scanned the whole map for every new address, so a flood of new
// sources cost a full scan per request under the lock.
func boundRateLimitMap(m map[string][]time.Time, cutoff time.Time) {
	if len(m) < apiRateLimitMaxIPs {
		return
	}
	rateLimitSweeps.Add(1)
	type lastHit struct {
		ip   string
		last time.Time
	}
	live := make([]lastHit, 0, len(m))
	for ip, hits := range m {
		if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
			delete(m, ip)
			continue
		}
		live = append(live, lastHit{ip, hits[len(hits)-1]})
	}
	keep := apiRateLimitMaxIPs - apiRateLimitMaxIPs/10
	if len(live) <= keep {
		return
	}
	sort.Slice(live, func(i, j int) bool { return live[i].last.Before(live[j].last) })
	for _, h := range live[:len(live)-keep] {
		delete(m, h.ip)
	}
}
