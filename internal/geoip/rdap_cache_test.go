package geoip

import (
	"strconv"
	"testing"
	"time"
)

// The RDAP cache must stay bounded even when every entry is fresh (a burst of
// distinct lookups within the 24h TTL). The old eviction only dropped expired
// entries, so an all-fresh map could grow past the cap without limit.
func TestRDAPCacheBoundedWhenAllFresh(t *testing.T) {
	db := &DB{rdapTTL: make(map[string]rdapCacheEntry)}

	now := time.Now()
	for i := 0; i < maxRDAPCacheEntries+50; i++ {
		db.rdapTTL[strconv.Itoa(i)] = rdapCacheEntry{fetched: now}
	}
	db.evictRDAPLocked()

	if len(db.rdapTTL) > maxRDAPCacheEntries {
		t.Fatalf("cache size %d exceeded cap %d with all-fresh entries", len(db.rdapTTL), maxRDAPCacheEntries)
	}
}
