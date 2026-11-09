package daemon

import (
	"os"
	"strings"
	"sync"
	"time"
)

// phpRelayIsLocalDomain reports whether domain is one of this host's mail
// domains. known is false when neither domain file could be read, so callers
// that tell outbound from local mail can stay quiet instead of guessing.
var phpRelayIsLocalDomain = phpRelayLocalDomains.has

var phpRelayLocalDomains = &localDomainCache{ttl: time.Minute}

// localDomainCache rereads the host's domain files at most once per ttl, so a
// per-message check does not read them for every log line.
type localDomainCache struct {
	mu       sync.Mutex
	ttl      time.Duration
	loadedAt time.Time
	domains  map[string]bool
	known    bool
}

func (c *localDomainCache) has(domain string) (local, known bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loadedAt.IsZero() || time.Since(c.loadedAt) >= c.ttl {
		c.domains, c.known = readLocalDomains()
		c.loadedAt = time.Now()
	}
	return c.domains[strings.ToLower(domain)], c.known
}

// readLocalDomains reads /etc/localdomains and /etc/virtualdomains. ok is
// true when at least one of them was readable.
func readLocalDomains() (domains map[string]bool, ok bool) {
	domains = make(map[string]bool)
	for _, path := range []string{"/etc/localdomains", "/etc/virtualdomains"} {
		// #nosec G304 -- path iterates a literal slice of cPanel system files.
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		ok = true
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if idx := strings.IndexByte(line, ':'); idx > 0 {
				line = strings.TrimSpace(line[:idx])
			}
			domains[strings.ToLower(line)] = true
		}
	}
	return domains, ok
}
