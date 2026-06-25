// Package checks: http_asn_crawl detector — single-ASN distributed crawl of
// uncacheable URLs saturating one account's PHP pool. See
// docs/superpowers/specs/2026-06-24-http-asn-crawl-detector-design.md.
package checks

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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

// emitASNCrawl produces Warning/High findings for each (scope, ASN) pair that
// passes all stage-1 gates. Critical escalation is handled by Task 8.
func (s *domlogStats) emitASNCrawl(cfg *config.Config) []alert.Finding {
	if cfg == nil || cfg.Thresholds.HTTPASNCrawlMinIPs <= 0 || s.asnCrawl == nil {
		return nil
	}
	th := cfg.Thresholds
	minIPs := th.HTTPASNCrawlMinIPs
	minExpensive := th.HTTPASNCrawlMinExpensive
	if minExpensive <= 0 {
		minExpensive = config.DefaultHTTPASNCrawlMinExpensive
	}
	minSharePct := th.HTTPASNCrawlMinSharePct
	if minSharePct <= 0 {
		minSharePct = config.DefaultHTTPASNCrawlMinSharePct
	}
	highAmpPct := th.HTTPASNCrawlHighAmpPct
	if highAmpPct <= 0 {
		highAmpPct = config.DefaultHTTPASNCrawlHighAmpPct
	}
	highVolMult := th.HTTPASNCrawlHighVolumeMult
	if highVolMult <= 0 {
		highVolMult = config.DefaultHTTPASNCrawlHighVolMult
	}

	var out []alert.Finding
	for scopeKey, scope := range s.asnCrawl {
		for asn, a := range scope.byASN {
			if uintInSlice(asn, th.HTTPASNCrawlAllowlistASNs) ||
				uintInSlice(asn, th.HTTPASNCrawlReverseProxyASNs) {
				continue
			}
			if a.distinctIPs() < minIPs {
				continue
			}
			if a.expensive < minExpensive {
				continue
			}
			if scope.scopeExpensive == 0 ||
				a.expensive*100 < minSharePct*scope.scopeExpensive {
				continue
			}
			sev := alert.Warning
			ampHigh := a.expensive > 0 && a.amplified*100 >= highAmpPct*a.expensive
			volHigh := a.expensive >= highVolMult*minExpensive
			if ampHigh || volHigh {
				sev = alert.High
			}
			account, domain := asnCrawlScopeParts(scopeKey, a)
			cidrs := collapseASNCrawlCIDRs(a, cfg)
			out = append(out, alert.Finding{
				Severity:  sev,
				Check:     "http_asn_crawl",
				TenantID:  account,
				Domain:    domain,
				Message:   fmt.Sprintf("Distributed crawl from AS%d (%s) against %s", asn, a.org, asnCrawlScopeLabel(scopeKey)),
				Details:   asnCrawlDetails(asn, a, scope, cfg, cidrs),
				CIDRs:     cidrs,
				Timestamp: time.Now(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Message < out[j].Message })
	return out
}

// asnCrawlScopeParts returns (account, domain) for a finding. account is the
// scope key unless it is a domain-scoped fallback ("domain:<d>"); domain is set
// only when exactly one domain was observed.
func asnCrawlScopeParts(scopeKey string, a *asnCrawlASN) (account, domain string) {
	if !strings.HasPrefix(scopeKey, "domain:") {
		account = scopeKey
	}
	if len(a.domains) == 1 {
		for d := range a.domains {
			domain = d
		}
	}
	return account, domain
}

func asnCrawlScopeLabel(scopeKey string) string {
	return strings.TrimPrefix(scopeKey, "domain:")
}

func asnCrawlDetails(asn uint, a *asnCrawlASN, scope *asnCrawlScope, cfg *config.Config, cidrs []string) string {
	maxTracked := cfg.Thresholds.HTTPASNCrawlMaxTrackedIPs
	if maxTracked <= 0 {
		maxTracked = config.DefaultHTTPASNCrawlMaxTrackedIPs
	}
	ipCount := fmt.Sprintf("%d", a.distinctIPs())
	if a.ipsCapped {
		ipCount = fmt.Sprintf(">=%d", maxTracked)
	}
	share := 0
	if scope.scopeExpensive > 0 {
		share = a.expensive * 100 / scope.scopeExpensive
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ASN: AS%d (%s)\n", asn, a.org)
	fmt.Fprintf(&b, "Distinct source IPs: %s\n", ipCount)
	fmt.Fprintf(&b, "Expensive/total reqs: %d/%d (%d%% of scope expensive)\n", a.expensive, a.total, share)
	fmt.Fprintf(&b, "Amplified (layered-nav/search) reqs: %d\n", a.amplified)
	if len(a.samples) > 0 {
		fmt.Fprintf(&b, "Sample URIs: %s\n", strings.Join(a.samples, " | "))
	}
	if len(cidrs) > 0 {
		fmt.Fprintf(&b, "Suggested subnets: %s\n", strings.Join(cidrs, ", "))
	}
	return b.String()
}

// collapseASNCrawlCIDRs reduces an ASN's observed IPs to a sorted, capped set
// of /24 (IPv4) / /64 (IPv6) subnets. When a single /16 covers >=
// http_asn_crawl_16_pref_pct of the IPv4 IPs across >= 4 distinct /24s, that
// /16 replaces its member /24s. Remaining /24s and any /64s are kept as-is.
// The result is sorted and capped to http_asn_crawl_max_prefix entries.
func collapseASNCrawlCIDRs(a *asnCrawlASN, cfg *config.Config) []string {
	if len(a.cidr24) == 0 {
		return nil
	}
	th := cfg.Thresholds
	pct16 := th.HTTPASNCrawl16PrefPct
	if pct16 <= 0 {
		pct16 = config.DefaultHTTPASNCrawl16PrefPct
	}

	// Count total IPv4 IPs and group /24s by their /16 parent.
	totalV4 := 0
	bySixteen := map[string][]string{} // "x.y.0.0/16" -> member /24 CIDRs
	for cidr, n := range a.cidr24 {
		if strings.HasSuffix(cidr, "/24") {
			totalV4 += n
			sl := strings.SplitN(cidr, ".", 4)
			s16 := sl[0] + "." + sl[1] + ".0.0/16"
			bySixteen[s16] = append(bySixteen[s16], cidr)
		}
	}

	chosen := map[string]struct{}{}
	covered := map[string]struct{}{} // /24s replaced by their /16

	// Promote a /16 when >= 4 member /24s cover >= pct16% of all IPv4 IPs.
	for s16, members := range bySixteen {
		if len(members) < 4 {
			continue
		}
		count := 0
		for _, m := range members {
			count += a.cidr24[m]
		}
		if totalV4 > 0 && count*100 >= pct16*totalV4 {
			chosen[s16] = struct{}{}
			for _, m := range members {
				covered[m] = struct{}{}
			}
		}
	}

	// Add uncovered /24s and all /64s.
	for cidr := range a.cidr24 {
		if _, done := covered[cidr]; done {
			continue
		}
		chosen[cidr] = struct{}{}
	}

	out := make([]string, 0, len(chosen))
	for c := range chosen {
		out = append(out, c)
	}
	sort.Strings(out)

	maxPrefix := th.HTTPASNCrawlMaxPrefix
	if maxPrefix <= 0 {
		maxPrefix = config.DefaultHTTPASNCrawlMaxPrefix
	}
	if len(out) > maxPrefix {
		out = out[:maxPrefix]
	}
	return out
}
