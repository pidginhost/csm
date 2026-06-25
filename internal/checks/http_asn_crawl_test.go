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
		{"/c/?color=red", false},    // value not key
		{"/c/?ORDERBY=price", true}, // case-insensitive key
		{"/c/?x=orderby", false},    // orderby only as value
		{"/c/", false},              // no query
		{"/c/?%zz", false},          // malformed query, no match
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
	// Populate distinct IPs from RFC 5737 ranges (203.0.113.x and 198.51.100.x).
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
		/*distinctIPs*/ 30 /*expensive*/, 600 /*amplified*/, 600 /*scopeExpensive*/, 600)

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

// withPHPWorkers swaps phpWorkersByUserFn with a stub that returns worker slices
// of the given lengths and restores the original on cleanup.
func withPHPWorkers(t *testing.T, counts map[string]int) {
	t.Helper()
	orig := phpWorkersByUserFn
	phpWorkersByUserFn = func() map[string][]string {
		m := make(map[string][]string, len(counts))
		for user, n := range counts {
			m[user] = make([]string, n)
		}
		return m
	}
	t.Cleanup(func() { phpWorkersByUserFn = orig })
}

func TestEmitASNCrawlStage2Escalates(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	cfg.Performance.PHPProcessWarnPerUser = 40
	// account "radiusro" saturated at 50 lsphp.
	withPHPWorkers(t, map[string]int{"radiusro": 50})

	s := asnCrawlStatsWith(t, cfg, "radiusro", 45102, "Alibaba", 30, 600, 600, 600)
	out := s.emitASNCrawl(cfg)
	if len(out) != 1 || out[0].Severity != alert.Critical || len(out[0].CIDRs) == 0 {
		t.Fatalf("want one Critical with CIDRs, got %+v", out)
	}
}

func TestEmitASNCrawlStage2NoEscalationWhenNotSaturated(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	cfg.Performance.PHPProcessWarnPerUser = 40
	withPHPWorkers(t, map[string]int{"radiusro": 5})
	s := asnCrawlStatsWith(t, cfg, "radiusro", 45102, "Alibaba", 30, 600, 600, 600)
	out := s.emitASNCrawl(cfg)
	if len(out) != 1 || out[0].Severity == alert.Critical {
		t.Fatalf("must stay High/Warning, got %+v", out)
	}
}

func TestEmitASNCrawlStage2NoEscalationWhenAccountless(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	withPHPWorkers(t, map[string]int{"radiusro": 50})
	// domain-scoped (no account): cannot escalate.
	s := asnCrawlStatsWith(t, cfg, "domain:radius.ro", 45102, "Alibaba", 30, 600, 600, 600)
	out := s.emitASNCrawl(cfg)
	if len(out) != 1 || out[0].Severity == alert.Critical {
		t.Fatalf("accountless must not escalate, got %+v", out)
	}
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

// TestScanFeedsASNCrawlOutsideFloodWindow drives records through scan() and
// asserts the detector's own 60-min window governs accumulation, not the
// 5-min flood window. Records 30 min old (inside asn window, outside flood)
// must accumulate; a 90-min-old record must not. See spec section 4.1.
func TestScanFeedsASNCrawlOutsideFloodWindow(t *testing.T) {
	SetASNLookup(func(ip string) (uint, string) { return 45102, "Alibaba" })
	t.Cleanup(func() { SetASNLookup(nil) })
	cfg := configWithASNCrawlDefaults(t)
	scanTime := mustTime("2026-06-24T12:30:00Z")
	s := newDomlogStatsAt(scanTime)

	// 30 expensive records 30 min old: inside the 60-min asn window but
	// well outside the default 5-min flood window.
	inWindow := scanTime.Add(-30 * time.Minute)
	for i := 1; i <= 30; i++ {
		rec := accessLogRecord{
			RemoteIP: fmt.Sprintf("203.0.113.%d", i), Method: "GET",
			URI: "/categorie/coliere/?filter_x=1", Status: 200,
			Time: inWindow, Domain: "radius.ro", Account: "radiusro",
		}
		s.scan(rec, cfg, nopBotClassifier{})
	}
	sc := s.asnCrawl["radiusro"]
	if sc == nil || sc.byASN[45102] == nil {
		t.Fatal("scan() must accumulate asn-crawl records 30 min old (inside 60-min window)")
	}
	if got := sc.byASN[45102].expensive; got != 30 {
		t.Fatalf("expensive=%d want 30 (records inside asn window dropped by flood gate?)", got)
	}

	// A 90-min-old record is outside the 60-min window and must not accumulate.
	old := scanTime.Add(-90 * time.Minute)
	recOld := accessLogRecord{
		RemoteIP: "198.51.100.7", Method: "GET", URI: "/c/?filter_y=2", Status: 200,
		Time: old, Domain: "radius.ro", Account: "radiusro",
	}
	s.scan(recOld, cfg, nopBotClassifier{})
	if got := s.asnCrawl["radiusro"].byASN[45102].expensive; got != 30 {
		t.Fatalf("90-min-old record must not accumulate; expensive=%d want 30", got)
	}
}

// TestObserveASNCrawlSkipsEmptyDomain asserts central-log records (empty
// Domain) feed no scope or accumulation. See spec section 4.
func TestObserveASNCrawlSkipsEmptyDomain(t *testing.T) {
	SetASNLookup(func(ip string) (uint, string) { return 45102, "Alibaba" })
	t.Cleanup(func() { SetASNLookup(nil) })
	cfg := configWithASNCrawlDefaults(t)
	s := newDomlogStatsAt(mustTime("2026-06-24T12:30:00Z"))
	rec := accessLogRecord{
		RemoteIP: "203.0.113.9", Method: "GET", URI: "/c/?filter_x=1", Status: 200,
		Time: mustTime("2026-06-24T12:29:00Z"), Domain: "", Account: "",
	}
	s.observeASNCrawl("203.0.113.9", rec, cfg)
	if len(s.asnCrawl) != 0 {
		t.Fatalf("empty-Domain record must not create any scope, got %v", s.asnCrawl)
	}
}

// allowFake implements both IPBlocker and allowChecker so emitASNCrawl can
// drop candidate CIDRs containing a firewall-allowed observed IP. It is a
// SEPARATE type from recordingIPBlocker so existing autoblock tests, which
// rely on recordingIPBlocker NOT implementing allowChecker, are unaffected.
type allowFake struct {
	allowed map[string]bool
}

func (f *allowFake) BlockIP(string, string, time.Duration) error { return nil }
func (f *allowFake) UnblockIP(string) error                      { return nil }
func (f *allowFake) IsBlocked(string) bool                       { return false }
func (f *allowFake) IsAllowed(ip string) bool                    { return f.allowed[ip] }

// TestEmitASNCrawlDropsFirewallAllowedCIDR asserts a candidate /24 containing a
// firewall-allowed observed IP is removed from the emitted finding's CIDRs,
// while a clean /24 remains. See spec section 6.2.
func TestEmitASNCrawlDropsFirewallAllowedCIDR(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	s := newDomlogStatsAt(mustTime("2026-06-24T12:30:00Z"))
	a := &asnCrawlASN{
		org:       "Alibaba",
		expensive: 600,
		total:     600,
		amplified: 600,
		domains:   map[string]struct{}{"radius.ro": {}},
		ips:       map[string]struct{}{},
		cidr24:    map[string]int{},
	}
	// 20 IPs in 203.0.113.0/24 (allowed) and 20 in 198.51.100.0/24 (clean).
	for i := 1; i <= 20; i++ {
		for _, ip := range []string{fmt.Sprintf("203.0.113.%d", i), fmt.Sprintf("198.51.100.%d", i)} {
			a.ips[ip] = struct{}{}
			if g := asnCrawlGroupCIDR(ip); g != "" {
				a.cidr24[g]++
			}
		}
	}
	s.asnCrawl = map[string]*asnCrawlScope{
		"radiusro": {byASN: map[uint]*asnCrawlASN{45102: a}, scopeExpensive: 600},
	}

	prev := getIPBlocker()
	SetIPBlocker(&allowFake{allowed: map[string]bool{"203.0.113.5": true}})
	t.Cleanup(func() { SetIPBlocker(prev) })

	out := s.emitASNCrawl(cfg)
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	for _, c := range out[0].CIDRs {
		if c == "203.0.113.0/24" {
			t.Fatalf("firewall-allowed /24 must be dropped, got CIDRs %v", out[0].CIDRs)
		}
	}
	found := false
	for _, c := range out[0].CIDRs {
		if c == "198.51.100.0/24" {
			found = true
		}
	}
	if !found {
		t.Fatalf("clean /24 must remain, got CIDRs %v", out[0].CIDRs)
	}
	// Details "Suggested subnets" must reflect the filtered list too.
	if strings.Contains(out[0].Details, "203.0.113.0/24") {
		t.Fatalf("Details must not list the dropped /24: %q", out[0].Details)
	}
}

// TestEmitASNCrawlStage2UsesSaturationConfig asserts the primary
// http_asn_crawl_saturation threshold (not only the PHPProcessWarnPerUser
// fallback) drives Stage-2 escalation. See spec section 5.2.
func TestEmitASNCrawlStage2UsesSaturationConfig(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	cfg.Thresholds.HTTPASNCrawlSaturation = 50
	cfg.Performance.PHPProcessWarnPerUser = 999 // would block escalation if used
	withPHPWorkers(t, map[string]int{"radiusro": 50})
	s := asnCrawlStatsWith(t, cfg, "radiusro", 45102, "Alibaba", 30, 600, 600, 600)
	out := s.emitASNCrawl(cfg)
	if len(out) != 1 || out[0].Severity != alert.Critical {
		t.Fatalf("saturation config must drive Critical escalation, got %+v", out)
	}
}
