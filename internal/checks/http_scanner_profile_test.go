package checks

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/threatintel"
)

// scannerTestNow anchors every record inside the flood window so the
// in-window gating never interferes with what each test asserts.
var scannerTestNow = time.Date(2026, 6, 12, 10, 5, 0, 0, time.UTC)

func scannerCfg(minReq, pct, minPaths int, codes []int) *config.Config {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodWindowMin = 5
	cfg.Thresholds.HTTPScannerMinRequests = minReq
	cfg.Thresholds.HTTPScannerErrorPct = pct
	cfg.Thresholds.HTTPScannerMinDistinctPaths = minPaths
	cfg.Thresholds.HTTPScannerStatusCodes = codes
	return cfg
}

func scannerRec(ip, uri string, status int) accessLogRecord {
	return accessLogRecord{
		RemoteIP:  ip,
		Time:      scannerTestNow,
		Method:    "GET",
		URI:       uri,
		Status:    status,
		UserAgent: "Mozilla/5.0",
	}
}

func findScannerFindings(fs []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range fs {
		if f.Check == "http_scanner_profile" {
			out = append(out, f)
		}
	}
	return out
}

func TestHTTPScannerProfile_DisabledByDefault(t *testing.T) {
	cfg := scannerCfg(0, 0, 0, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < 100; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/probe-%d.zip", i), 404), cfg, nopBotClassifier{})
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("detector fired while disabled: %+v", got)
	}
}

// Defaults: error_pct=90 and min_distinct_paths=10 apply when the
// operator only sets the volume gate.
func TestHTTPScannerProfile_FiresOnProbeStorm(t *testing.T) {
	cfg := scannerCfg(30, 0, 0, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < 50; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/backup-%d.sql", i), 404), cfg, nopBotClassifier{})
	}
	got := findScannerFindings(stats.emit(cfg))
	if len(got) != 1 {
		t.Fatalf("findings=%d, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != alert.High {
		t.Errorf("severity=%v want High", f.Severity)
	}
	if f.SourceIP != "192.0.2.10" {
		t.Errorf("SourceIP=%q want 192.0.2.10", f.SourceIP)
	}
	if !strings.Contains(f.Message, "50") {
		t.Errorf("message should carry request count: %q", f.Message)
	}
	if !strings.Contains(f.Details, "/backup-0.sql") {
		t.Errorf("details should carry first probe sample: %q", f.Details)
	}
}

func TestHTTPScannerProfile_VolumeGate(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < 20; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/p%d", i), 404), cfg, nopBotClassifier{})
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired below volume gate: %+v", got)
	}
}

func TestHTTPScannerProfile_ErrorRateBelowPct(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < 40; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/p%d", i), 404), cfg, nopBotClassifier{})
	}
	for i := 0; i < 10; i++ {
		stats.scan(scannerRec("192.0.2.10", "/index.html", 200), cfg, nopBotClassifier{})
	}
	// 40/50 = 80% < 90%
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired below error-rate threshold: %+v", got)
	}
}

// One dead bookmark or broken image hammered repeatedly is not a
// scanner: 100% errors but a single path.
func TestHTTPScannerProfile_SinglePathNotScanner(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < 100; i++ {
		stats.scan(scannerRec("192.0.2.10", "/dead-bookmark.html", 404), cfg, nopBotClassifier{})
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired on a single repeated path: %+v", got)
	}
}

// A site migration 301-redirects every legacy URL for every legitimate
// visitor. 301 must not count as a probe error unless opted in.
func TestHTTPScannerProfile_301NotCountedByDefault(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < 100; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/old-page-%d", i), 301), cfg, nopBotClassifier{})
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired on 301 redirects without opt-in: %+v", got)
	}
}

func TestHTTPScannerProfile_CustomCodesInclude301(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, []int{404, 301})
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < 50; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/old-%d", i), 301), cfg, nopBotClassifier{})
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 1 {
		t.Fatalf("findings=%d, want 1 with 301 opted in: %+v", len(got), got)
	}
}

// Cache-buster style queries on one missing endpoint must not inflate
// the distinct-path count.
func TestHTTPScannerProfile_QueryStringStripped(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < 50; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/missing.php?cb=%d", i), 404), cfg, nopBotClassifier{})
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("query strings inflated distinct path count: %+v", got)
	}
}

func TestHTTPScannerProfile_VerifiedBotSkipped(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	bot := staticBotClassifier{verified: true}
	for i := 0; i < 50; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/p%d", i), 404), cfg, bot)
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired on verified bot traffic: %+v", got)
	}
}

type staticBotClassifier struct{ verified bool }

func (c staticBotClassifier) IsVerifiedBot(string, string) bool { return c.verified }

// A verified SERanking backlink crawler (FCrDNS positive, cached) must not
// trip the scanner profile even though it requests many distinct URLs that
// 404 -- those are stale backlinks, not vulnerability probing. Proves the
// SERankingBacklinksBot UA maps to the "seranking" identity and rides the
// verified-bot skip the same as Googlebot.
func TestHTTPScannerProfile_VerifiedSerankingBotSkipped(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	const ua = "Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0; +https://seranking.com/backlinks-crawler)"
	bot := newVerifyingClassifier(nil, func(_ net.IP, b string) (bool, bool) {
		return b == "seranking", b == "seranking"
	})
	for i := 0; i < 50; i++ {
		rec := scannerRec("203.0.113.55", fmt.Sprintf("/p%d", i), 404)
		rec.UserAgent = ua
		stats.scan(rec, cfg, bot)
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired on verified SERanking crawler traffic: %+v", got)
	}
}

// An operator-configured crawler UA is classified as a claimed bot so that an
// impostor using the same UA from an unrelated host can be caught as a spoof.
func TestClassifyUA_OperatorClaimedBot(t *testing.T) {
	t.Cleanup(func() { threatintel.SetOperatorBots(nil) })
	threatintel.SetOperatorBots([]threatintel.BotEntry{{
		Name:         "acmebot",
		UASubstrings: []string{"acmecrawler"},
		RDNSSuffixes: []string{"acme.example"},
	}})
	if got := classifyUA("Mozilla/5.0 (compatible; AcmeCrawler/2.0)", "GET"); got != uaKindClaimedBot {
		t.Errorf("classifyUA(operator bot) = %v, want uaKindClaimedBot", got)
	}
}

// A verified operator-configured crawler must ride the same scanner-profile
// skip as a built-in once verified_bots names it.
func TestHTTPScannerProfile_VerifiedOperatorBotSkipped(t *testing.T) {
	t.Cleanup(func() { threatintel.SetOperatorBots(nil) })
	threatintel.SetOperatorBots([]threatintel.BotEntry{{
		Name:         "acmebot",
		UASubstrings: []string{"acmecrawler"},
		RDNSSuffixes: []string{"acme.example"},
	}})
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	const ua = "Mozilla/5.0 (compatible; AcmeCrawler/2.0; +http://acme.example/bot)"
	bot := newVerifyingClassifier(nil, func(_ net.IP, b string) (bool, bool) {
		return b == "acmebot", b == "acmebot"
	})
	for i := 0; i < 50; i++ {
		rec := scannerRec("203.0.113.77", fmt.Sprintf("/p%d", i), 404)
		rec.UserAgent = ua
		stats.scan(rec, cfg, bot)
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired on verified operator crawler traffic: %+v", got)
	}
}

// An operator bot defined by IP range (AI agent: UA + published CIDRs, no
// rDNS) is skipped synchronously -- no rDNS cache is consulted (nil cacheGet).
func TestHTTPScannerProfile_VerifiedOperatorIPRangeBotSkipped(t *testing.T) {
	t.Cleanup(func() { threatintel.SetOperatorBots(nil) })
	threatintel.SetOperatorBots([]threatintel.BotEntry{{
		Name:         "perplexitybot",
		UASubstrings: []string{"perplexitybot"},
		IPRanges:     []string{"18.97.9.96/29"},
	}})
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	const ua = "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/bot)"
	bot := newVerifyingClassifier(nil, nil) // nil cacheGet: range path must not need it
	for i := 0; i < 50; i++ {
		rec := scannerRec("18.97.9.100", fmt.Sprintf("/p%d", i), 404)
		rec.UserAgent = ua
		stats.scan(rec, cfg, bot)
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired on verified operator IP-range bot: %+v", got)
	}
}

// The distinct-path set is capped to bound memory under a flood of
// unique probe URLs. The detector must still fire past the cap.
func TestHTTPScannerProfile_PathCapStillFires(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	for i := 0; i < httpScannerMaxTrackedPaths+500; i++ {
		stats.scan(scannerRec("192.0.2.10", fmt.Sprintf("/u-%d", i), 404), cfg, nopBotClassifier{})
	}
	if n := len(stats.scannerPaths["192.0.2.10"]); n > httpScannerMaxTrackedPaths {
		t.Fatalf("tracked paths %d exceeds cap %d", n, httpScannerMaxTrackedPaths)
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 1 {
		t.Fatalf("findings=%d, want 1 past the path cap", len(got))
	}
}

// Scanner-profile IPs participate in the distributed rollup like every
// other HTTP-abuse finding kind.
func TestHTTPScannerProfile_DistributedRollupCounts(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	cfg.Thresholds.HTTPDistributedMinIPs = 2
	stats := newDomlogStatsAt(scannerTestNow)
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		for i := 0; i < 50; i++ {
			rec := scannerRec(ip, fmt.Sprintf("/probe-%d", i), 404)
			rec.Domain = "victim.example"
			stats.scan(rec, cfg, nopBotClassifier{})
		}
	}
	var distributed []alert.Finding
	for _, f := range stats.emit(cfg) {
		if f.Check == "http_distributed_flood" {
			distributed = append(distributed, f)
		}
	}
	if len(distributed) != 1 {
		t.Fatalf("distributed findings=%d, want 1", len(distributed))
	}
	if distributed[0].Domain != "victim.example" {
		t.Errorf("Domain=%q want victim.example", distributed[0].Domain)
	}
}

func TestHTTPScannerProfile_DistributedRollupIgnoresIncidentalDomain404s(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	cfg.Thresholds.HTTPDistributedMinIPs = 2
	stats := newDomlogStatsAt(scannerTestNow)
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		for i := 0; i < 50; i++ {
			rec := scannerRec(ip, fmt.Sprintf("/probe-%d", i), 404)
			rec.Domain = "scanner-target.example"
			stats.scan(rec, cfg, nopBotClassifier{})
		}
		rec := scannerRec(ip, "/favicon.ico", 404)
		rec.Domain = "popular-site.example"
		stats.scan(rec, cfg, nopBotClassifier{})
	}

	var distributed []alert.Finding
	for _, f := range stats.emit(cfg) {
		if f.Check == "http_distributed_flood" {
			distributed = append(distributed, f)
		}
	}
	if len(distributed) != 1 {
		t.Fatalf("distributed findings=%d, want 1: %+v", len(distributed), distributed)
	}
	if distributed[0].Domain != "scanner-target.example" {
		t.Fatalf("Domain=%q want scanner-target.example; all findings=%+v", distributed[0].Domain, distributed)
	}
}

// End-to-end: status flows from a real Combined Log Format line through
// the parser into the detector.
func TestHTTPScannerProfile_StatusFromParsedLine(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	now := time.Date(2026, 6, 12, 10, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	stats := newDomlogStatsAt(now)
	for i := 0; i < 50; i++ {
		line := fmt.Sprintf(`192.0.2.20 - - [12/Jun/2026:10:03:00 +0300] "GET /wp-backup-%d.zip HTTP/1.1" 404 196 "-" "Mozilla/5.0"`, i)
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			t.Fatal("parse failed")
		}
		stats.scan(rec, cfg, nopBotClassifier{})
	}
	got := findScannerFindings(stats.emit(cfg))
	if len(got) != 1 {
		t.Fatalf("findings=%d, want 1: %+v", len(got), got)
	}
	if got[0].SourceIP != "192.0.2.20" {
		t.Errorf("SourceIP=%q want 192.0.2.20", got[0].SourceIP)
	}
}

// A scanner that spreads its probes thin across many vhosts (each vhost sees
// only a few error hits, below the per-IP minimum-requests gate) still trips
// the per-IP profile in aggregate. The distributed rollup must attribute every
// shared vhost it scanned, so a botnet of thin-spread scanners converging on
// the same vhosts is still seen -- the per-domain gate must not reuse the full
// per-IP minimum-request / min-path thresholds.
func TestHTTPScannerProfile_DistributedRollupCountsThinSpreadScanner(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	cfg.Thresholds.HTTPDistributedMinIPs = 2
	stats := newDomlogStatsAt(scannerTestNow)
	vhosts := []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		for vi, vhost := range vhosts {
			for i := 0; i < 6; i++ {
				rec := scannerRec(ip, fmt.Sprintf("/probe-%d-%d", vi, i), 404)
				rec.Domain = vhost
				stats.scan(rec, cfg, nopBotClassifier{})
			}
		}
	}

	var distributed []alert.Finding
	for _, f := range stats.emit(cfg) {
		if f.Check == "http_distributed_flood" {
			distributed = append(distributed, f)
		}
	}
	if len(distributed) != len(vhosts) {
		t.Fatalf("distributed findings=%d, want %d (thin-spread scanner must feed every shared vhost)", len(distributed), len(vhosts))
	}
}

func TestHTTPScannerProfile_DistributedRollupHonorsLowScannerThresholds(t *testing.T) {
	cfg := scannerCfg(2, 100, 2, nil)
	cfg.Thresholds.HTTPDistributedMinIPs = 2
	stats := newDomlogStatsAt(scannerTestNow)
	vhosts := []string{"a.example", "b.example"}
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		for vi, vhost := range vhosts {
			for i := 0; i < 2; i++ {
				rec := scannerRec(ip, fmt.Sprintf("/probe-%d-%d", vi, i), 404)
				rec.Domain = vhost
				stats.scan(rec, cfg, nopBotClassifier{})
			}
		}
	}

	got := map[string]bool{}
	for _, f := range stats.emit(cfg) {
		if f.Check == "http_distributed_flood" {
			got[f.Domain] = true
		}
	}
	if len(got) != len(vhosts) {
		t.Fatalf("distributed findings=%d, want %d under low scanner thresholds: %+v", len(got), len(vhosts), got)
	}
	for _, vhost := range vhosts {
		if !got[vhost] {
			t.Fatalf("distributed flood missing for %s under low scanner thresholds: %+v", vhost, got)
		}
	}
}

// A real visitor browsing a catalog whose CDN is missing every image
// fetches many distinct asset URLs that all 404. A 404 on a static
// sub-resource (image, stylesheet, script, font) discloses nothing and
// runs no code -- it is a broken-asset signal, not URL enumeration. Such
// requests must stay out of the scanner profile even when their volume,
// error rate, and path breadth would otherwise trip every gate.
func TestHTTPScannerProfile_DisplayAssetStormNotScanner(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	exts := []string{".gif", ".png", ".jpg", ".jpeg", ".webp", ".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".svg", ".ico", ".mp4"}
	for i := 0; i < 90; i++ {
		uri := fmt.Sprintf("/assets/SKU-%d%s", i, exts[i%len(exts)])
		stats.scan(scannerRec("192.0.2.20", uri, 404), cfg, nopBotClassifier{})
	}
	if got := findScannerFindings(stats.emit(cfg)); len(got) != 0 {
		t.Fatalf("fired on a broken-asset 404 storm (display assets are not probes): %+v", got)
	}
}

func TestHTTPScannerProfile_DisplayAssetClassificationEdges(t *testing.T) {
	for _, tc := range []struct {
		uri  string
		want bool
	}{
		{uri: "/.env", want: false},
		{uri: "/assets/", want: false},
		{uri: "/IMG.GIF?cache=1#ignored", want: true},
		{uri: "/IMG%2EGIF?cache=1#ignored", want: true},
		{uri: "/images/product.v2.PNG", want: true},
		{uri: "/uploads/shell.php.gif", want: false},
		{uri: "/uploads/shell%2Ephp.gif", want: false},
		{uri: "/backups/backup.zip.css", want: false},
		{uri: "/backups/backup%2ezip.css", want: false},
		{uri: "/static/app.js.map", want: false},
	} {
		if got := isDisplayAssetProbe(tc.uri); got != tc.want {
			t.Fatalf("isDisplayAssetProbe(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}

func TestHTTPScannerProfile_DisplayAssetExclusionKeepsScannerCountersAligned(t *testing.T) {
	cfg := scannerCfg(1, 1, 1, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	stats.scan(scannerRec("192.0.2.22", "/img/missing.PNG?cache=1#ignored", 404), cfg, nopBotClassifier{})
	stats.scan(scannerRec("192.0.2.22", "/index", 200), cfg, nopBotClassifier{})
	stats.scan(scannerRec("192.0.2.22", "/.env", 404), cfg, nopBotClassifier{})

	if got := stats.scannerReqs["192.0.2.22"]; got != 2 {
		t.Fatalf("scannerReqs = %d, want 2 (display asset 404 must not move scanner denominator)", got)
	}
	if got := stats.scannerErr["192.0.2.22"]; got != 1 {
		t.Fatalf("scannerErr = %d, want 1 (only the dotfile probe should count as scanner error)", got)
	}
	if stats.scannerErr["192.0.2.22"] > stats.scannerReqs["192.0.2.22"] {
		t.Fatalf("scannerErr exceeded scannerReqs: err=%d reqs=%d", stats.scannerErr["192.0.2.22"], stats.scannerReqs["192.0.2.22"])
	}
}

func TestHTTPScannerProfile_DisguisedProbeExtensionsStillCount(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	probes := []string{
		"/uploads/shell-%d.php.gif",
		"/backups/archive-%d.zip.css",
		"/configs/site-%d.env.js",
		"/static/app-%d.js.map",
	}
	for i := 0; i < 40; i++ {
		stats.scan(scannerRec("192.0.2.23", fmt.Sprintf(probes[i%len(probes)], i), 404), cfg, nopBotClassifier{})
	}

	got := findScannerFindings(stats.emit(cfg))
	if len(got) != 1 {
		t.Fatalf("findings=%d, want 1 (probe extensions hidden behind asset suffixes must still count): %+v", len(got), got)
	}
}

// Excluding display assets must not blind the detector: an attacker who
// sprays broken-asset requests alongside genuine probes for code, configs,
// and backups must still trip on the probe traffic. The asset noise must
// neither inflate the denominator (diluting the error rate) nor the volume
// gate -- the scanner profile is computed over non-asset requests only.
func TestHTTPScannerProfile_AssetStormWithRealProbesStillFires(t *testing.T) {
	cfg := scannerCfg(30, 90, 10, nil)
	stats := newDomlogStatsAt(scannerTestNow)
	// Broken display assets: pure noise, must be ignored entirely.
	for i := 0; i < 60; i++ {
		stats.scan(scannerRec("192.0.2.21", fmt.Sprintf("/img/p-%d.png", i), 404), cfg, nopBotClassifier{})
	}
	// Genuine probes across distinct dangerous paths (code, env, dumps,
	// archives, and an extensionless directory probe).
	probes := []string{".php", ".env", ".sql", ".zip", ".bak", ".aspx", ".rar", ""}
	for i := 0; i < 40; i++ {
		uri := fmt.Sprintf("/probe-%d%s", i, probes[i%len(probes)])
		stats.scan(scannerRec("192.0.2.21", uri, 404), cfg, nopBotClassifier{})
	}
	got := findScannerFindings(stats.emit(cfg))
	if len(got) != 1 {
		t.Fatalf("findings=%d, want 1 (real probes must fire despite asset noise): %+v", len(got), got)
	}
}
