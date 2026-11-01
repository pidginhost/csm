// Package sharedsenders keeps mail services that many unrelated senders share
// from being reported as spam sources. Each provider's sending hosts come from
// its published SPF tree: prefixes, and ptr: domains whose hosts must pass
// forward-confirmed reverse DNS. Every doubt counts as shared, so a guard that
// is not ready or a DNS failure never turns into a report.
package sharedsenders

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/mailranges"
)

// providers maps each shared mail service to the SPF root that lists all of
// its sending hosts.
var providers = map[string]string{
	"amazonses": "amazonses.com",
	"brevo":     "spf.brevo.com",
	"google":    "_spf.google.com",
	"icloud":    "icloud.com",
	"mailgun":   "mailgun.org",
	"microsoft": "spf.protection.outlook.com",
	"sendgrid":  "sendgrid.net",
	"yahoo":     "yahoo.com",
}

const (
	cacheVersion  = 1
	maxCacheBytes = 1 << 20
	maxNets       = 4096
	maxPTRDomains = 128
	// maxAge is how long a provider's last good policy keeps the guard ready.
	maxAge = 7 * 24 * time.Hour
	// lookupBudget bounds all DNS work of one Shared call.
	lookupBudget = 5 * time.Second
	// maxPTRNames bounds the forward lookups one address can cost. No mail
	// host needs more reverse names, so a longer answer fails closed.
	maxPTRNames = 10
)

// Resolver is the DNS the guard uses. *net.Resolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type cacheFile struct {
	Version   int                      `json:"version"`
	Providers map[string]cacheProvider `json:"providers"`
}

type cacheProvider struct {
	Root       string   `json:"root"`
	ResolvedAt int64    `json:"resolved_at"`
	Nets       []string `json:"nets"`
	PTR        []string `json:"ptr"`
}

// provider is one provider's last good policy, as cached and as parsed.
// Published snapshots share it, so it is never modified.
type provider struct {
	cache cacheProvider
	nets  []netip.Prefix
}

type snapshot map[string]provider

// Guard answers whether an address belongs to a shared mail service. Covers
// and Shared read an immutable snapshot, so they never wait for a refresh.
type Guard struct {
	path string
	// mu serialises Load and Refresh so the cache file and the published
	// snapshot cannot be left from different runs.
	mu   sync.Mutex
	snap atomic.Pointer[snapshot]
}

// New returns a guard that is not ready until Load or Refresh publishes every
// provider. cachePath is where Refresh persists policies and Load reads them.
func New(cachePath string) *Guard {
	return &Guard{path: cachePath}
}

// NewForTest returns a guard holding policies, keyed by provider name, all
// resolved at resolvedAt. It has no cache file, so Refresh on it fails. It
// panics on an unknown provider name or a policy Load would reject.
func NewForTest(policies map[string]mailranges.Policy, resolvedAt time.Time) *Guard {
	s := make(snapshot, len(policies))
	for name, pol := range policies {
		if _, ok := providers[name]; !ok {
			panic(fmt.Sprintf("sharedsenders: unknown provider %q", name))
		}
		p, err := fromPolicy(name, pol, resolvedAt)
		if err != nil {
			panic(fmt.Sprintf("sharedsenders: provider %s: %v", name, err))
		}
		s[name] = p
	}
	g := &Guard{}
	g.snap.Store(&s)
	return g
}

// Load publishes the cache file. A missing file leaves the guard as it was.
// One bad entry fails the whole load, because skipping it would publish a
// provider with fewer senders than it has. Load ignores its time: Ready judges
// each provider's age, so a clock stepped back since the last refresh does not
// drop the cache.
func (g *Guard) Load(_ time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	f, err := os.Open(g.path) // #nosec G304 -- daemon-owned state path
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("sharedsenders: read cache: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCacheBytes+1))
	if err != nil {
		return fmt.Errorf("sharedsenders: read cache: %w", err)
	}
	s, err := parseCache(data)
	if err != nil {
		return err
	}
	g.snap.Store(&s)
	return nil
}

// Refresh resolves every provider's SPF tree. A provider that fails keeps its
// last good policy and resolve time, and the error names it. The cache is
// written before the snapshot is published, and nothing is published when the
// write fails, so a restart never loads an older policy than one in use.
func (g *Guard) Refresh(ctx context.Context, r Resolver, now time.Time) error {
	if g.path == "" {
		return errors.New("sharedsenders: guard has no cache file")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	next := make(snapshot, len(providers))
	maps.Copy(next, g.current())
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(providers)) {
		pol, err := mailranges.ResolveSPFPolicy(ctx, r, providers[name])
		var p provider
		if err == nil {
			p, err = fromPolicy(name, pol, now)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("sharedsenders: provider %s: %w", name, err))
			continue
		}
		next[name] = p
	}
	data, err := encodeCache(next)
	if err == nil {
		err = atomicio.AtomicWrite(g.path, 0o600, data)
	}
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("sharedsenders: write cache: %w", err))...)
	}
	g.snap.Store(&next)
	return errors.Join(errs...)
}

// Ready reports whether every provider resolved within the last 7 days.
func (g *Guard) Ready(now time.Time) bool {
	return g.current().ready(now)
}

// Covers reports whether ip must not be reported without asking DNS: the
// guard is not ready, or ip is in a provider prefix.
func (g *Guard) Covers(ip netip.Addr, now time.Time) bool {
	return g.current().covers(ip.Unmap(), now)
}

// Shared reports whether ip belongs to a shared mail service: Covers is true,
// or a reverse name of ip is a provider ptr domain or under one and resolves
// back to ip. No PTR, or no matching name that resolves back, is not shared.
// Any other DNS failure, or more reverse names than it checks, is shared.
func (g *Guard) Shared(ctx context.Context, r Resolver, ip netip.Addr, now time.Time) bool {
	s := g.current()
	ip = ip.Unmap()
	if s.covers(ip, now) {
		return true
	}
	var domains []string
	for _, p := range s {
		domains = append(domains, p.cache.PTR...)
	}
	// No reverse name could match, so a DNS failure must not hide the sender.
	if len(domains) == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, lookupBudget)
	defer cancel()
	names, err := r.LookupAddr(ctx, ip.String())
	if err != nil {
		return !notFound(err)
	}
	// One forward lookup per name at most, so this also caps forward lookups.
	if len(names) > maxPTRNames {
		return true
	}
	for _, name := range names {
		host, ok := ptrHost(name, domains)
		if !ok {
			continue
		}
		// Rooted, so the resolver does not also try the host's search domains.
		addrs, lookupErr := r.LookupIP(ctx, "ip", host+".")
		if lookupErr != nil {
			if notFound(lookupErr) {
				continue
			}
			return true
		}
		for _, a := range addrs {
			if fwd, valid := netip.AddrFromSlice(a); valid && fwd.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

func (g *Guard) current() snapshot {
	if s := g.snap.Load(); s != nil {
		return *s
	}
	return nil
}

func (s snapshot) ready(now time.Time) bool {
	for name := range providers {
		p, ok := s[name]
		at := time.Unix(p.cache.ResolvedAt, 0)
		if !ok || at.After(now) || now.Sub(at) > maxAge {
			return false
		}
	}
	return true
}

func (s snapshot) covers(ip netip.Addr, now time.Time) bool {
	if !ip.IsValid() || !s.ready(now) {
		return true
	}
	for _, p := range s {
		for _, n := range p.nets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// notFound reports whether err says the name does not exist. A not-found that
// is also temporary or a timeout is not a final answer, so it fails closed.
func notFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound && !dnsErr.IsTemporary && !dnsErr.IsTimeout
}

// ptrHost returns name in lower case without its root dot when that is one of
// domains or a name under one. DNS ignores case only in ASCII, and Unicode
// case folding would map other bytes onto ASCII letters, so a name with any
// non-ASCII byte never matches.
func ptrHost(name string, domains []string) (string, bool) {
	for i := 0; i < len(name); i++ {
		if name[i] >= utf8.RuneSelf {
			return "", false
		}
	}
	host := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return host, true
		}
	}
	return "", false
}

func fromPolicy(name string, pol mailranges.Policy, at time.Time) (provider, error) {
	c := cacheProvider{Root: providers[name], ResolvedAt: at.Unix(), PTR: pol.PTRDomains}
	for _, n := range pol.Nets {
		c.Nets = append(c.Nets, n.String())
	}
	return parseProvider(name, c)
}

// parseProvider checks a provider entry against what Refresh writes. Prefixes
// are not checked for public address space: mailranges did that before the
// write, and an extra prefix can only stop a report, never cause one.
func parseProvider(name string, c cacheProvider) (provider, error) {
	switch {
	case c.Root != providers[name]:
		return provider{}, fmt.Errorf("root %q, want %q", c.Root, providers[name])
	case len(c.Nets) > maxNets:
		return provider{}, fmt.Errorf("%d prefixes, over %d", len(c.Nets), maxNets)
	case len(c.PTR) > maxPTRDomains:
		return provider{}, fmt.Errorf("%d ptr domains, over %d", len(c.PTR), maxPTRDomains)
	}
	// Copies, so a published provider shares no slice with the caller, and
	// never nil, so an empty list is written as [] rather than null.
	c.Nets, c.PTR = append([]string{}, c.Nets...), append([]string{}, c.PTR...)
	p := provider{cache: c, nets: make([]netip.Prefix, 0, len(c.Nets))}
	for _, s := range c.Nets {
		n, err := netip.ParsePrefix(s)
		if err != nil || n != n.Masked() || n.Addr().Is4In6() {
			return provider{}, fmt.Errorf("bad prefix %q", s)
		}
		p.nets = append(p.nets, n)
	}
	for _, d := range c.PTR {
		if !validPTRDomain(d) {
			return provider{}, fmt.Errorf("bad ptr domain %q", d)
		}
	}
	return p, nil
}

// validPTRDomain reports whether d has the shape mailranges gives a ptr
// domain: a lower-case ASCII host name without a trailing dot whose top label
// is not all digits.
func validPTRDomain(d string) bool {
	labels := strings.Split(d, ".")
	if len(d) > 253 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return false
		}
	}
	return true
}

func parseCache(data []byte) (snapshot, error) {
	if len(data) > maxCacheBytes {
		return nil, fmt.Errorf("sharedsenders: cache over %d bytes", maxCacheBytes)
	}
	var c cacheFile
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("sharedsenders: cache: %w", err)
	}
	if c.Version != cacheVersion {
		return nil, fmt.Errorf("sharedsenders: cache version %d, want %d", c.Version, cacheVersion)
	}
	s := make(snapshot, len(providers))
	for name, cp := range c.Providers {
		if _, ok := providers[name]; !ok {
			continue
		}
		p, err := parseProvider(name, cp)
		if err != nil {
			return nil, fmt.Errorf("sharedsenders: provider %s: %w", name, err)
		}
		s[name] = p
	}
	return s, nil
}

func encodeCache(s snapshot) ([]byte, error) {
	c := cacheFile{Version: cacheVersion, Providers: make(map[string]cacheProvider, len(s))}
	for name, p := range s {
		c.Providers[name] = p.cache
	}
	data, err := json.Marshal(c)
	if err == nil && len(data) > maxCacheBytes {
		err = fmt.Errorf("cache of %d bytes, over %d", len(data), maxCacheBytes)
	}
	return data, err
}
