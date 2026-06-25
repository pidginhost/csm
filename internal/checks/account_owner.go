package checks

import (
	"strings"
	"sync"
	"time"
)

// Domain->owner is read from cPanel's /etc/userdomains ("domain: user").
// Cached for ownerCacheTTL so a busy host does not re-read it per scan.
const ownerCacheTTL = 60 * time.Second

var (
	ownerMu       sync.Mutex
	ownerMap      map[string]string
	ownerLoadedAt time.Time
)

// resetDomainOwnerCache clears the cache. Test-only seam.
func resetDomainOwnerCache() {
	ownerMu.Lock()
	ownerMap = nil
	ownerLoadedAt = time.Time{}
	ownerMu.Unlock()
}

// domainAccountOwner returns the cPanel account that owns domain, or "" when
// the map is unavailable (non-cPanel) or the domain is not present. The
// wildcard "*: nobody" line and any non "domain: user" line are ignored.
func domainAccountOwner(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	ownerMu.Lock()
	defer ownerMu.Unlock()
	if ownerMap == nil || time.Since(ownerLoadedAt) > ownerCacheTTL {
		ownerMap = loadDomainOwners()
		ownerLoadedAt = time.Now()
	}
	return ownerMap[domain]
}

func loadDomainOwners() map[string]string {
	out := make(map[string]string)
	data, err := osFS.ReadFile("/etc/userdomains")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.LastIndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		dom := strings.ToLower(strings.TrimSpace(line[:idx]))
		owner := strings.TrimSpace(line[idx+1:])
		if dom == "" || dom == "*" || owner == "" || owner == "nobody" {
			continue
		}
		out[dom] = owner
	}
	return out
}
