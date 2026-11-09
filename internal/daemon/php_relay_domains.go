package daemon

import (
	"os"
	"strings"
	"sync"
	"time"
)

// phpRelayIsLocalDomain reports whether domain is one of this host's mail
// domains. known is false when the domain inventory could not be read, so callers
// that tell outbound from local mail can stay quiet instead of guessing.
var phpRelayIsLocalDomain = phpRelayLocalDomains.has

var phpRelayLocalDomains = &localDomainCache{ttl: time.Minute}

// Tests redirect these system files into a temporary directory.
var localDomainPaths = []string{"/etc/localdomains", "/etc/virtualdomains"}

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

// readLocalDomains reads /etc/localdomains and /etc/virtualdomains. Missing
// optional files are normal, but a read failure can hide local domains.
// ok requires at least one readable file and no failures on present files.
func readLocalDomains() (domains map[string]bool, ok bool) {
	domains = make(map[string]bool)
	failed := false
	for _, path := range localDomainPaths {
		// #nosec G304 -- paths are fixed system files, redirected only by tests.
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				failed = true
			}
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
	return domains, ok && !failed
}
