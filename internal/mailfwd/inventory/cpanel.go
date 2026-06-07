package inventory

import (
	"path/filepath"
	"sort"
	"strings"
)

// FS is the minimal filesystem surface the enumerator needs. Injected so the
// cPanel source can be tested against fixture directories without root.
type FS interface {
	Glob(pattern string) ([]string, error)
	ReadFile(name string) ([]byte, error)
}

// Source enumerates the forwarders configured on a host.
type Source interface {
	Forwarders() ([]Forwarder, error)
}

// CPanelSource reads forwarders from cPanel's /etc/valiases directory, with
// local domains from /etc/localdomains and owners from /etc/userdomains.
type CPanelSource struct {
	fs               FS
	valiasGlob       string
	localDomainsPath string
	userDomainsPath  string
}

// NewCPanelSource returns a source reading the standard cPanel locations.
func NewCPanelSource() *CPanelSource {
	return &CPanelSource{
		fs:               osFS{},
		valiasGlob:       "/etc/valiases/*",
		localDomainsPath: "/etc/localdomains",
		userDomainsPath:  "/etc/userdomains",
	}
}

// Forwarders enumerates every forwarder across all hosted domains. A missing
// or unreadable valias file is skipped, not fatal: partial inventory beats no
// inventory on a server with thousands of domains.
func (s *CPanelSource) Forwarders() ([]Forwarder, error) {
	localDomains := s.loadLocalDomains()
	owners := s.loadOwners()

	files, err := s.fs.Glob(s.valiasGlob)
	if err != nil {
		return nil, err
	}

	var out []Forwarder
	for _, path := range files {
		domain := strings.ToLower(filepath.Base(path))
		content, err := s.fs.ReadFile(path)
		if err != nil {
			continue
		}
		owner := owners[domain]
		for _, line := range strings.Split(string(content), "\n") {
			fwd, ok := parseForwarderLine(domain, line, localDomains)
			if !ok {
				continue
			}
			fwd.Owner = owner
			out = append(out, fwd)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, nil
}

// loadLocalDomains reads /etc/localdomains (one domain per line) into a
// lowercased set. Returns an empty set when the file is unavailable, which
// makes every destination classify as external -- the safe direction for a
// reputation tool (over-report external, never hide it).
func (s *CPanelSource) loadLocalDomains() map[string]bool {
	domains := make(map[string]bool)
	content, err := s.fs.ReadFile(s.localDomainsPath)
	if err != nil {
		return domains
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Tolerate "domain: user" form as well as a bare domain.
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		domains[strings.ToLower(line)] = true
	}
	return domains
}

// loadOwners reads /etc/userdomains ("domain: user") into a domain->owner map.
func (s *CPanelSource) loadOwners() map[string]string {
	owners := make(map[string]string)
	content, err := s.fs.ReadFile(s.userDomainsPath)
	if err != nil {
		return owners
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(line[:idx]))
		owner := strings.TrimSpace(line[idx+1:])
		if domain != "" && owner != "" {
			owners[domain] = owner
		}
	}
	return owners
}
