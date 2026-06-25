package checks

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// configWithASNCrawlDefaults returns a config with all HTTPASNCrawl* thresholds
// at their defaults (min_ips=25, etc.).
func configWithASNCrawlDefaults(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.LoadBytes([]byte("thresholds: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// mustTime parses an RFC3339 timestamp and panics on error.
func mustTime(s string) time.Time {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return ts
}

func TestObserveASNCrawlAggregates(t *testing.T) {
	prev := CurrentASNLookup
	_ = prev
	SetASNLookup(func(ip string) (uint, string) {
		switch {
		case strings.HasPrefix(ip, "203.0.113."):
			return 45102, "Alibaba"
		case strings.HasPrefix(ip, "198.51.100."):
			return 45102, "Alibaba"
		case strings.HasPrefix(ip, "192.0.2."):
			return 64500, "OtherNet"
		}
		return 0, ""
	})
	t.Cleanup(func() { SetASNLookup(nil) })

	cfg := configWithASNCrawlDefaults(t) // helper: Thresholds.HTTPASNCrawl* at defaults
	s := newDomlogStatsAt(mustTime("2026-06-24T12:30:00Z"))

	// 30 Alibaba IPs, each one expensive amplified request to radiusro.
	for i := 1; i <= 30; i++ {
		rec := accessLogRecord{
			RemoteIP: fmt.Sprintf("203.0.113.%d", i), Method: "GET",
			URI: "/categorie/coliere/?filter_x=1&query_type_x=or", Status: 200,
			Time: mustTime("2026-06-24T12:29:00Z"), Domain: "radius.ro", Account: "radiusro",
		}
		s.observeASNCrawl(normalizeHTTPClientIP(rec.RemoteIP), rec, cfg)
	}
	// One OtherNet expensive request to same account (denominator only).
	recOther := accessLogRecord{RemoteIP: "192.0.2.5", Method: "GET", URI: "/shop/?q=1", Status: 200,
		Time: mustTime("2026-06-24T12:29:00Z"), Domain: "radius.ro", Account: "radiusro"}
	s.observeASNCrawl("192.0.2.5", recOther, cfg)

	sc := s.asnCrawl["radiusro"]
	if sc == nil {
		t.Fatal("no scope accumulated for radiusro")
	}
	a := sc.byASN[45102]
	if a == nil || a.distinctIPs() != 30 || a.expensive != 30 || a.amplified != 30 {
		t.Fatalf("Alibaba agg wrong: %+v", a)
	}
	if sc.scopeExpensive != 31 {
		t.Fatalf("scope expensive denominator = %d want 31", sc.scopeExpensive)
	}
}

func TestObserveASNCrawlReverseProxyDropped(t *testing.T) {
	SetASNLookup(func(ip string) (uint, string) { return 13335, "Cloudflare" })
	t.Cleanup(func() { SetASNLookup(nil) })
	cfg := configWithASNCrawlDefaults(t)
	s := newDomlogStatsAt(mustTime("2026-06-24T12:30:00Z"))
	for i := 1; i <= 40; i++ {
		rec := accessLogRecord{RemoteIP: fmt.Sprintf("203.0.113.%d", i), Method: "GET",
			URI: "/c/?filter_x=1", Status: 200, Time: mustTime("2026-06-24T12:29:00Z"),
			Domain: "radius.ro", Account: "radiusro"}
		s.observeASNCrawl(normalizeHTTPClientIP(rec.RemoteIP), rec, cfg)
	}
	sc := s.asnCrawl["radiusro"]
	if sc != nil && sc.byASN[13335] != nil {
		t.Fatal("reverse-proxy ASN 13335 must not be accumulated")
	}
	if sc != nil && sc.scopeExpensive != 0 {
		t.Fatalf("reverse-proxy expensive must be excluded from denominator, got %d", sc.scopeExpensive)
	}
}

func TestHTTPASNCrawlExpensive(t *testing.T) {
	cases := []struct {
		name string
		rec  accessLogRecord
		want bool
	}{
		{"dynamic GET with query", accessLogRecord{Method: "GET", URI: "/categorie/coliere/?filter_x=1"}, true},
		{"dynamic HEAD with query", accessLogRecord{Method: "HEAD", URI: "/shop/?orderby=price"}, true},
		{"no query string", accessLogRecord{Method: "GET", URI: "/categorie/coliere/"}, false},
		{"POST excluded", accessLogRecord{Method: "POST", URI: "/cart/?add=1"}, false},
		{"static jpg with query", accessLogRecord{Method: "GET", URI: "/img/a.jpg?v=2"}, false},
		{"static CSS uppercase ext with query", accessLogRecord{Method: "GET", URI: "/a.CSS?v=2"}, false},
		{"dot only in query, no ext", accessLogRecord{Method: "GET", URI: "/path?file=a.css"}, true},
		{"woff2 font with query", accessLogRecord{Method: "GET", URI: "/f.woff2?d=1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := httpASNCrawlExpensive(c.rec); got != c.want {
				t.Fatalf("httpASNCrawlExpensive(%q %q)=%v want %v", c.rec.Method, c.rec.URI, got, c.want)
			}
		})
	}
}

func TestHTTPASNCrawlAmplified(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"/c/?filter_color=red", true},
		{"/c/?query_type_x=or", true},
		{"/shop/?orderby=price", true},
		{"/?s=ring", true},
		{"/?add-to-cart=42", true},
		{"/c/?paged=3", true},
		{"/c/?product-page=2", true},
		{"/c/?color=red", false},       // value not key
		{"/c/?ORDERBY=price", true},    // case-insensitive key
		{"/c/?x=orderby", false},       // orderby only as value
		{"/c/", false},                 // no query
		{"/c/?%zz", false},             // malformed query, no match
	}
	for _, c := range cases {
		t.Run(c.uri, func(t *testing.T) {
			if got := httpASNCrawlAmplified(c.uri); got != c.want {
				t.Fatalf("httpASNCrawlAmplified(%q)=%v want %v", c.uri, got, c.want)
			}
		})
	}
}

// asnCrawlStatsWith builds a *domlogStats with one scope/ASN pre-populated
// for emitASNCrawl unit tests. IPs are synthesised from RFC 5737/3849 ranges.
func asnCrawlStatsWith(t *testing.T, cfg *config.Config, account string, asn uint, org string,
	distinctIPs, expensive, amplified, scopeExpensive int) *domlogStats {
	t.Helper()
	s := newDomlogStatsAt(mustTime("2026-06-24T12:30:00Z"))
	a := &asnCrawlASN{
		org:       org,
		expensive: expensive,
		total:     expensive,
		amplified: amplified,
		domains:   map[string]struct{}{},
		ips:       map[string]struct{}{},
		cidr24:    map[string]int{},
	}
	// Populate distinct IPs from RFC 5737 (203.0.113.x) and RFC 3849 (198.51.100.x).
	for i := 0; i < distinctIPs; i++ {
		var ip string
		if i < 256 {
			ip = fmt.Sprintf("203.0.113.%d", i%256)
		} else {
			ip = fmt.Sprintf("198.51.100.%d", (i-256)%256)
		}
		a.ips[ip] = struct{}{}
		if g := asnCrawlGroupCIDR(ip); g != "" {
			a.cidr24[g]++
		}
	}
	s.asnCrawl = map[string]*asnCrawlScope{
		account: {
			byASN:          map[uint]*asnCrawlASN{asn: a},
			scopeExpensive: scopeExpensive,
		},
	}
	return s
}

func TestEmitASNCrawlStage1Fires(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	s := asnCrawlStatsWith(t, cfg, "radiusro", 45102, "Alibaba",
		/*distinctIPs*/ 30, /*expensive*/ 600, /*amplified*/ 600, /*scopeExpensive*/ 600)

	out := s.emitASNCrawl(cfg)
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.Check != "http_asn_crawl" || f.Severity != alert.High || f.TenantID != "radiusro" || f.SourceIP != "" {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

func TestEmitASNCrawlStage1Gates(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	// Below min_ips (25): no finding.
	s1 := asnCrawlStatsWith(t, cfg, "radiusro", 45102, "Alibaba", 10, 600, 600, 600)
	if len(s1.emitASNCrawl(cfg)) != 0 {
		t.Fatal("min_ips gate failed")
	}
	// Below share (ASN 600 of 2000 scope = 30% < 50%): no finding.
	s2 := asnCrawlStatsWith(t, cfg, "radiusro", 45102, "Alibaba", 30, 600, 600, 2000)
	if len(s2.emitASNCrawl(cfg)) != 0 {
		t.Fatal("share gate failed")
	}
	// Allowlisted ASN: no finding.
	cfgAllow := configWithASNCrawlDefaults(t)
	cfgAllow.Thresholds.HTTPASNCrawlAllowlistASNs = []uint{45102}
	s3 := asnCrawlStatsWith(t, cfgAllow, "radiusro", 45102, "Alibaba", 30, 600, 600, 600)
	if len(s3.emitASNCrawl(cfgAllow)) != 0 {
		t.Fatal("allowlist gate failed")
	}
}

func TestEmitASNCrawlSeverityWarningWhenLowAmp(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	// Meets min_expensive (250) but not high-volume (4x=1000) and amp 0%.
	s := asnCrawlStatsWith(t, cfg, "radiusro", 45102, "Alibaba", 30, 300, 0, 300)
	out := s.emitASNCrawl(cfg)
	if len(out) != 1 || out[0].Severity != alert.Warning {
		t.Fatalf("want one Warning, got %+v", out)
	}
}

// ipsIn returns a slice of IP strings "prefix+i" for i in [lo, hi].
func ipsIn(prefix string, lo, hi int) []string {
	out := make([]string, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		out = append(out, prefix+strconv.Itoa(i))
	}
	return out
}

// newAggWithIPs builds an *asnCrawlASN whose ips set and cidr24 map reflect
// the given IPs (via asnCrawlGroupCIDR).
func newAggWithIPs(t *testing.T, ips []string) *asnCrawlASN {
	t.Helper()
	a := &asnCrawlASN{
		ips:    map[string]struct{}{},
		cidr24: map[string]int{},
	}
	for _, ip := range ips {
		a.ips[ip] = struct{}{}
		if g := asnCrawlGroupCIDR(ip); g != "" {
			a.cidr24[g]++
		}
	}
	return a
}

func TestCollapseASNCrawlCIDRs(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)

	// Spread across two /24s, neither dominating a /16: expect two /24s.
	a := newAggWithIPs(t, append(ipsIn("203.0.113.", 1, 20), ipsIn("198.51.100.", 1, 20)...))
	got := collapseASNCrawlCIDRs(a, cfg)
	wantTwo := map[string]bool{"203.0.113.0/24": true, "198.51.100.0/24": true}
	if len(got) != 2 || !wantTwo[got[0]] || !wantTwo[got[1]] {
		t.Fatalf("two-/24 collapse = %v", got)
	}

	// All within one /16 across >=4 /24s, >=60%: expect the /16.
	var many []string
	for blk := 0; blk < 5; blk++ {
		many = append(many, ipsIn(fmt.Sprintf("203.0.%d.", blk), 1, 10)...)
	}
	a16 := newAggWithIPs(t, many)
	got16 := collapseASNCrawlCIDRs(a16, cfg)
	if len(got16) != 1 || got16[0] != "203.0.0.0/16" {
		t.Fatalf("/16 collapse = %v want [203.0.0.0/16]", got16)
	}

	// max_prefix cap.
	cfgCap := configWithASNCrawlDefaults(t)
	cfgCap.Thresholds.HTTPASNCrawlMaxPrefix = 1
	if got := collapseASNCrawlCIDRs(a, cfgCap); len(got) != 1 {
		t.Fatalf("max_prefix cap not applied: %v", got)
	}
}
