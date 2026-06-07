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

// EmptySource reports no forwarders. It stands in on platforms whose
// enumeration is not wired yet (non-cPanel), so callers always hold a usable
// Source instead of a nil.
type EmptySource struct{}

func (EmptySource) Forwarders() ([]Forwarder, error) { return []Forwarder{}, nil }

// CPanelSource reads forwarders from cPanel's /etc/valiases directory, with
// local domains from /etc/localdomains and /etc/virtualdomains and owners from
// /etc/userdomains.
type CPanelSource struct {
	fs                 FS
	valiasGlob         string
	localDomainsPath   string
	virtualDomainsPath string
	userDomainsPath    string
}

// NewCPanelSource returns a source reading the standard cPanel locations.
func NewCPanelSource() *CPanelSource {
	return &CPanelSource{
		fs:                 osFS{},
		valiasGlob:         "/etc/valiases/*",
		localDomainsPath:   "/etc/localdomains",
		virtualDomainsPath: "/etc/virtualdomains",
		userDomainsPath:    "/etc/userdomains",
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
		domain := normalizeDomain(filepath.Base(path))
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

// loadLocalDomains reads cPanel's local-domain files into a normalized set.
// Returns an empty set when the files are unavailable, which makes every
// destination classify as external -- the safe direction for a reputation tool
// (over-report external, never hide it).
func (s *CPanelSource) loadLocalDomains() map[string]bool {
	domains := make(map[string]bool)
	for _, path := range []string{s.localDomainsPath, s.virtualDomainsPath} {
		if path == "" {
			continue
		}
		content, err := s.fs.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			domain := configDomain(line)
			if domain != "" {
				domains[domain] = true
			}
		}
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
		domain := configDomain(line[:idx])
		owner := strings.TrimSpace(line[idx+1:])
		if domain != "" && owner != "" {
			owners[domain] = owner
		}
	}
	return owners
}

func configDomain(line string) string {
	line = strings.TrimSpace(line)
	if idx := strings.IndexByte(line, ':'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	domain := normalizeDomain(line)
	if domain == "" || strings.ContainsAny(domain, " \t\r\n/:\\") {
		return ""
	}
	return domain
}
