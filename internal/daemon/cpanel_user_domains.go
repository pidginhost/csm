package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/emailspool"
	"gopkg.in/yaml.v3"
)

// userDomainsResolver resolves a cPanel user to the lowercased, IDN-normalised
// set of domains the account owns. TTL-based cache; safe for concurrent use.
type userDomainsResolver struct {
	root string
	ttl  time.Duration

	mu    sync.Mutex
	cache map[string]userDomainsCacheEntry
}

type userDomainsCacheEntry struct {
	domains map[string]struct{}
	fetched time.Time
	err     error
}

// newUserDomainsResolver returns a resolver reading from /var/cpanel/userdata/.
// Wired by daemon startup in O2; kept now so that future call sites compile.
//
//nolint:unused // consumed by daemon wiring (Task O2)
func newUserDomainsResolver() *userDomainsResolver {
	return newUserDomainsResolverWithRoot("/var/cpanel/userdata", 5*time.Minute)
}

func newUserDomainsResolverWithRoot(root string, ttl time.Duration) *userDomainsResolver {
	return &userDomainsResolver{
		root:  root,
		ttl:   ttl,
		cache: make(map[string]userDomainsCacheEntry),
	}
}

// Domains returns the cPanel user's authorised domain set. Returns the
// (possibly cached) error if the user's userdata is unreadable; callers
// must treat an error result as "skip the From-mismatch signal" rather than
// falsely amplifying.
func (r *userDomainsResolver) Domains(user string) (map[string]struct{}, error) {
	if user == "" {
		return nil, errors.New("empty user")
	}
	r.mu.Lock()
	if e, ok := r.cache[user]; ok && time.Since(e.fetched) < r.ttl {
		r.mu.Unlock()
		return e.domains, e.err
	}
	r.mu.Unlock()

	set, err := r.read(user)
	r.mu.Lock()
	r.cache[user] = userDomainsCacheEntry{domains: set, fetched: time.Now(), err: err}
	r.mu.Unlock()
	return set, err
}

// Invalidate removes the cached entry for user. Callers wire this to
// inotify on /var/cpanel/userdata/<user>/.
func (r *userDomainsResolver) Invalidate(user string) {
	r.mu.Lock()
	delete(r.cache, user)
	r.mu.Unlock()
}

func (r *userDomainsResolver) read(user string) (map[string]struct{}, error) {
	path := filepath.Join(r.root, user, "main")
	// #nosec G304 -- r.root is fixed at /var/cpanel/userdata/, user is a
	// cPanel-managed account name validated by the resolver's caller; the
	// resulting path is constrained to the cpanel userdata tree.
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]struct{}{}, fmt.Errorf("read %s: %w", path, err)
	}
	var raw struct {
		MainDomain    string            `yaml:"main_domain"`
		AddonDomains  map[string]string `yaml:"addon_domains"`
		ParkedDomains []string          `yaml:"parked_domains"`
		SubDomains    []string          `yaml:"sub_domains"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return map[string]struct{}{}, fmt.Errorf("parse %s: %w", path, err)
	}
	set := make(map[string]struct{}, 8)
	add := func(d string) {
		d = strings.TrimSpace(d)
		if d == "" {
			return
		}
		// ExtractDomain handles IDN normalisation and lowercasing for free.
		// It expects an addr-style input but happily round-trips bare hosts.
		norm := emailspool.ExtractDomain("anyone@" + d)
		if norm == "" {
			norm = strings.ToLower(d)
		}
		set[norm] = struct{}{}
	}
	add(raw.MainDomain)
	for k := range raw.AddonDomains {
		add(k)
	}
	for _, d := range raw.ParkedDomains {
		add(d)
	}
	for _, d := range raw.SubDomains {
		add(d)
	}
	return set, nil
}

// IsAuthorisedFromDomain reports whether fromDomain is one of the user's
// domains, accounting for subdomain inclusion (a sub.example.com From is
// authorised if example.com is in the set, but the reverse is NOT true).
func IsAuthorisedFromDomain(fromDomain string, authSet map[string]struct{}) bool {
	if fromDomain == "" || len(authSet) == 0 {
		return false
	}
	for base := range authSet {
		if emailspool.IsSubdomainOrEqual(fromDomain, base) {
			return true
		}
	}
	return false
}
