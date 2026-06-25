// Package checks: http_asn_crawl detector — single-ASN distributed crawl of
// uncacheable URLs saturating one account's PHP pool. See
// docs/superpowers/specs/2026-06-24-http-asn-crawl-detector-design.md.
package checks

import (
	"net"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// httpASNCrawlStaticExts are path extensions whose responses are cacheable
// static assets; requests for them never reach PHP, so they are not
// "expensive" for this detector.
var httpASNCrawlStaticExts = map[string]struct{}{
	"jpg": {}, "jpeg": {}, "png": {}, "gif": {}, "webp": {}, "svg": {}, "ico": {},
	"bmp": {}, "css": {}, "js": {}, "mjs": {}, "map": {}, "woff": {}, "woff2": {},
	"ttf": {}, "eot": {}, "otf": {}, "mp4": {}, "webm": {}, "ogg": {}, "mp3": {},
	"pdf": {}, "zip": {}, "gz": {}, "avif": {},
}

// httpASNCrawlExpensive reports whether a request is a dynamic, uncacheable
// hit that reaches PHP: a GET or HEAD with a query string whose path extension
// is not a static asset.
func httpASNCrawlExpensive(rec accessLogRecord) bool {
	if rec.Method != "GET" && rec.Method != "HEAD" {
		return false
	}
	q := strings.IndexByte(rec.URI, '?')
	if q < 0 || q == len(rec.URI)-1 {
		return false
	}
	p := rec.URI[:q]
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))
	if ext == "" {
		return true
	}
	_, isStatic := httpASNCrawlStaticExts[ext]
	return !isStatic
}

// httpASNCrawlAmplifyKeys are query parameter names that signal an
// expensive layered-nav/search request; their presence raises severity.
var httpASNCrawlAmplifyKeys = map[string]struct{}{
	"orderby": {}, "add-to-cart": {}, "s": {}, "paged": {}, "product-page": {},
}

// httpASNCrawlAmplified reports whether the URI's query carries a known
// expensive layered-nav/search parameter. Key names are matched
// case-insensitively; values alone never match.
func httpASNCrawlAmplified(uri string) bool {
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return false
	}
	vals, err := url.ParseQuery(uri[q+1:])
	if err != nil {
		return false
	}
	for k := range vals {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "filter_") || strings.HasPrefix(lk, "query_type_") {
			return true
		}
		if _, ok := httpASNCrawlAmplifyKeys[lk]; ok {
			return true
		}
	}
	return false
}

// asnCrawlASN accumulates one ASN's footprint within one scope.
type asnCrawlASN struct {
	org       string
	expensive int
	total     int
	amplified int
	domains   map[string]struct{}
	samples   []string            // up to 5 distinct expensive URIs (<=200 bytes)
	ips       map[string]struct{} // distinct source IPs, capped
	ipsCapped bool
	cidr24    map[string]int // observed /24 (v4) or /64 (v6) -> count
}

func (a *asnCrawlASN) distinctIPs() int {
	// saturated at cap; callers may render as ">=cap" at emit
	return len(a.ips)
}

// asnCrawlScope is one account-or-domain scope's per-ASN map plus the
// scope-wide expensive denominator (excludes reverse-proxy traffic).
type asnCrawlScope struct {
	byASN          map[uint]*asnCrawlASN
	scopeExpensive int
}

func (s *domlogStats) observeASNCrawl(ip string, rec accessLogRecord, cfg *config.Config) {
	if cfg == nil || cfg.Thresholds.HTTPASNCrawlMinIPs <= 0 {
		return // detector disabled
	}
	if !httpASNCrawlExpensive(rec) {
		return
	}
	lookup := CurrentASNLookup()
	if lookup == nil {
		return
	}
	asn, org := lookup(ip)
	if asn == 0 {
		// Unknown ASN: still counts in the scope denominator so known-ASN
		// share is not inflated, but cannot form its own fingerprint.
		s.asnCrawlScopeFor(rec).scopeExpensive++
		return
	}
	if uintInSlice(asn, cfg.Thresholds.HTTPASNCrawlReverseProxyASNs) {
		return // reverse-proxy: dropped from numerator AND denominator
	}
	scope := s.asnCrawlScopeFor(rec)
	scope.scopeExpensive++
	a := scope.byASN[asn]
	if a == nil {
		a = &asnCrawlASN{
			org:     org,
			domains: map[string]struct{}{},
			ips:     map[string]struct{}{},
			cidr24:  map[string]int{},
		}
		scope.byASN[asn] = a
	}
	a.total++
	a.expensive++
	if httpASNCrawlAmplified(rec.URI) {
		a.amplified++
	}
	if rec.Domain != "" {
		a.domains[rec.Domain] = struct{}{}
	}
	if len(a.samples) < 5 {
		a.samples = append(a.samples, truncate(rec.URI, 200))
	}
	if _, ok := a.ips[ip]; !ok {
		maxIPs := cfg.Thresholds.HTTPASNCrawlMaxTrackedIPs
		if maxIPs <= 0 {
			maxIPs = config.DefaultHTTPASNCrawlMaxTrackedIPs
		}
		if len(a.ips) < maxIPs {
			a.ips[ip] = struct{}{}
			if g := asnCrawlGroupCIDR(ip); g != "" {
				a.cidr24[g]++
			}
		} else {
			a.ipsCapped = true
		}
	}
}

func (s *domlogStats) asnCrawlScopeFor(rec accessLogRecord) *asnCrawlScope {
	if s.asnCrawl == nil {
		s.asnCrawl = map[string]*asnCrawlScope{}
	}
	key := rec.Account
	if key == "" {
		key = "domain:" + rec.Domain
	}
	sc := s.asnCrawl[key]
	if sc == nil {
		sc = &asnCrawlScope{byASN: map[uint]*asnCrawlASN{}}
		s.asnCrawl[key] = sc
	}
	return sc
}

func uintInSlice(v uint, list []uint) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// asnCrawlGroupCIDR returns the /24 (IPv4) or /64 (IPv6) the ip belongs to.
func asnCrawlGroupCIDR(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return net.IP(v4.Mask(net.CIDRMask(24, 32))).String() + "/24"
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// asnCrawlWithinWindow gates a record to the detector's own lookback window
// (thresholds.http_asn_crawl_window_min). A zero/absent timestamp is excluded.
func asnCrawlWithinWindow(ts time.Time, cfg *config.Config, now time.Time) bool {
	if ts.IsZero() || cfg == nil {
		return false
	}
	win := cfg.Thresholds.HTTPASNCrawlWindowMin
	if win <= 0 {
		win = config.DefaultHTTPASNCrawlWindowMin
	}
	return !ts.Before(now.Add(-time.Duration(win) * time.Minute))
}
