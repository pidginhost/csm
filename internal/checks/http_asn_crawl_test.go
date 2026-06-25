package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"

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
