package challenge

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// crawlerSuffix names a verified-crawler family along with the PTR
// record suffixes that legitimate hosts in that family use.
type crawlerSuffix struct {
	name    string
	domains []string
}

// builtinCrawlers lists the known canonical reverse-DNS suffixes for
// the supported crawler families. Adding a new family means appending
// to this list and documenting the name in csm.yaml's
// challenge.verified_crawlers.providers.
var builtinCrawlers = map[string]crawlerSuffix{
	"googlebot": {name: "googlebot", domains: []string{".googlebot.com.", ".google.com."}},
	"bingbot":   {name: "bingbot", domains: []string{".search.msn.com."}},
}

// Resolver matches the subset of net.Resolver that CrawlerVerifier
// uses, so tests can swap in a fake without spinning up a real DNS
// server.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) (names []string, err error)
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

// CrawlerVerifier classifies an IP as a verified search crawler iff
// the IP's reverse-DNS PTR matches one of the configured suffixes AND
// the PTR forward-resolves back to the same IP. The verifier caches
// both positive and negative results; positive cache TTL is the
// configured cacheTTL, negative is one-fifth of that to keep a
// transiently-broken resolver from locking out a legitimate crawler.
type CrawlerVerifier struct {
	suffixes []crawlerSuffix
	resolver Resolver
	posTTL   time.Duration
	negTTL   time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	verified bool
	expires  time.Time
}

// NewCrawlerVerifier builds a verifier with the named crawler families
// enabled. Unknown names are ignored (operators may have configured a
// family this binary does not know about; that is harmless).
func NewCrawlerVerifier(providers []string, cacheTTL time.Duration, resolver Resolver) *CrawlerVerifier {
	if cacheTTL <= 0 {
		cacheTTL = 15 * time.Minute
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	enabled := make([]crawlerSuffix, 0, len(providers))
	for _, name := range providers {
		if c, ok := builtinCrawlers[strings.ToLower(strings.TrimSpace(name))]; ok {
			enabled = append(enabled, c)
		}
	}
	return &CrawlerVerifier{
		suffixes: enabled,
		resolver: resolver,
		posTTL:   cacheTTL,
		negTTL:   cacheTTL / 5,
		cache:    make(map[string]cacheEntry),
	}
}

// Enabled reports whether at least one crawler family is configured;
// the server uses this to skip the verifier entirely (no DNS round
// trip) when the operator has not opted in.
func (v *CrawlerVerifier) Enabled() bool {
	return v != nil && len(v.suffixes) > 0
}

// Verified does the reverse-DNS + forward-confirm dance for ip and
// caches the result. Returns true only when the PTR ends in one of the
// allowed suffixes AND a forward lookup of the PTR includes ip in the
// result set.
func (v *CrawlerVerifier) Verified(ctx context.Context, ip string) bool {
	if !v.Enabled() {
		return false
	}
	if hit, ok := v.cacheGet(ip); ok {
		return hit
	}

	verified := v.probe(ctx, ip)
	v.cachePut(ip, verified)
	return verified
}

func (v *CrawlerVerifier) probe(ctx context.Context, ip string) bool {
	names, err := v.resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return false
	}
	for _, name := range names {
		// LookupAddr returns FQDNs with a trailing dot. The suffix
		// list also has trailing dots so HasSuffix is unambiguous.
		lower := strings.ToLower(name)
		if !v.suffixMatches(lower) {
			continue
		}
		addrs, err := v.resolver.LookupHost(ctx, strings.TrimSuffix(lower, "."))
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr == ip {
				return true
			}
		}
	}
	return false
}

func (v *CrawlerVerifier) suffixMatches(name string) bool {
	for _, s := range v.suffixes {
		for _, d := range s.domains {
			if strings.HasSuffix(name, d) {
				return true
			}
		}
	}
	return false
}

func (v *CrawlerVerifier) cacheGet(ip string) (bool, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[ip]
	if !ok {
		return false, false
	}
	if time.Now().After(e.expires) {
		delete(v.cache, ip)
		return false, false
	}
	return e.verified, true
}

func (v *CrawlerVerifier) cachePut(ip string, verified bool) {
	ttl := v.negTTL
	if verified {
		ttl = v.posTTL
	}
	v.mu.Lock()
	v.cache[ip] = cacheEntry{verified: verified, expires: time.Now().Add(ttl)}
	v.mu.Unlock()
}

// cleanExpired drops every entry whose TTL has lapsed. Without this,
// a scan from many IPs leaves the cache full of stale entries until
// each individual IP is queried again. Called from Server.CleanExpired
// on the daemon's 60-second ticker. now is passed in so the caller can
// share a single timestamp across multiple cleanup paths.
func (v *CrawlerVerifier) cleanExpired(now time.Time) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for ip, e := range v.cache {
		if now.After(e.expires) {
			delete(v.cache, ip)
		}
	}
}
