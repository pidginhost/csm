package webui

import "time"

// apiRateLimitMaxIPs caps how many source addresses the unauthenticated
// per-IP rate-limit maps hold. The five-minute prune bounded them over time
// but not between prunes: a scan from many addresses grew them without
// limit in the meantime.
const apiRateLimitMaxIPs = 10000

// boundRateLimitMap keeps m under apiRateLimitMaxIPs before a new address
// is inserted. Caller holds the map's mutex. Stale entries (no hit after
// cutoff) go first; if the map is still full, the address with the oldest
// last hit is evicted so a new source can always be tracked.
func boundRateLimitMap(m map[string][]time.Time, cutoff time.Time) {
	if len(m) < apiRateLimitMaxIPs {
		return
	}
	for ip, hits := range m {
		if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
			delete(m, ip)
		}
	}
	for len(m) >= apiRateLimitMaxIPs {
		oldestIP := ""
		var oldest time.Time
		for ip, hits := range m {
			last := hits[len(hits)-1]
			if oldestIP == "" || last.Before(oldest) {
				oldestIP, oldest = ip, last
			}
		}
		delete(m, oldestIP)
	}
}
