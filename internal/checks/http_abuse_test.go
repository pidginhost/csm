package checks

import (
	"sort"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// TestRefactorParity feeds a fixed set of access-log lines through the
// current countBruteForce / aggregator path and asserts that the same
// three legacy findings come out with the same messages and severities.
// This locks the refactor down to "zero behavior change".
func TestRefactorParity(t *testing.T) {
	lines := []string{
		// 20 wp-login POSTs from one IP (at wpLoginThreshold=20)
		`192.0.2.10 - - [20/May/2026:18:00:00 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:01 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:02 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:03 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:04 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:05 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:06 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:07 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:08 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:09 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:10 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:11 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:12 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:13 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:14 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:15 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:16 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:17 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:18 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:19 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		// 32 xmlrpc POSTs from another IP (above xmlrpcThreshold=30)
	}
	for i := 0; i < 32; i++ {
		lines = append(lines,
			`198.51.100.20 - - [20/May/2026:18:00:00 +0300] "POST /xmlrpc.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`)
	}
	// 6 ?author= GETs from a third IP (above userEnumThreshold=5)
	for i := 0; i < 6; i++ {
		lines = append(lines,
			`203.0.113.30 - - [20/May/2026:18:00:00 +0300] "GET /?author=1 HTTP/1.1" 200 0 "-" "Mozilla/5.0"`)
	}

	stats := newDomlogStats()
	for _, ln := range lines {
		rec, ok := parseAccessLogRecord(ln)
		if !ok {
			t.Fatalf("parseAccessLogRecord rejected fixture line: %q", ln)
		}
		stats.scan(rec, nil, nopBotClassifier{})
	}

	got := stats.emitLegacy(nil)
	sort.Slice(got, func(i, j int) bool { return got[i].Check < got[j].Check })

	want := []struct {
		Check    string
		Severity alert.Severity
		Message  string
	}{
		{"wp_login_bruteforce", alert.Critical, "WordPress login brute force from 192.0.2.10: 20 attempts"},
		{"wp_user_enumeration", alert.High, "WordPress user enumeration from 203.0.113.30: 6 requests"},
		{"xmlrpc_abuse", alert.Critical, "XML-RPC abuse from 198.51.100.20: 32 requests"},
	}
	if len(got) != len(want) {
		t.Fatalf("findings=%d, want %d (%+v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Check != w.Check {
			t.Errorf("[%d] check=%q want %q", i, got[i].Check, w.Check)
		}
		if got[i].Severity != w.Severity {
			t.Errorf("[%d] severity=%v want %v", i, got[i].Severity, w.Severity)
		}
		if got[i].Message != w.Message {
			t.Errorf("[%d] message=%q want %q", i, got[i].Message, w.Message)
		}
		if got[i].SourceIP != "" {
			t.Errorf("[%d] SourceIP=%q, want empty to preserve legacy JSON shape", i, got[i].SourceIP)
		}
	}
}

func TestHTTPRequestFlood_Disabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 0 // disabled
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStats()
	for i := 0; i < 500; i++ {
		stats.httpReqs["192.0.2.50"]++
	}
	got := stats.emit(cfg)
	for _, f := range got {
		if f.Check == "http_request_flood" {
			t.Fatalf("flood emitted despite threshold=0: %+v", f)
		}
	}
}

func TestHTTPRequestFlood_AboveThreshold(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 100
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStats()
	stats.samples["192.0.2.50"] = httpSample{Method: "GET", URI: "/", UA: "curl/8"}
	stats.httpReqs["192.0.2.50"] = 196 // motivating attack volume

	got := stats.emit(cfg)
	found := false
	for _, f := range got {
		if f.Check == "http_request_flood" {
			found = true
			if f.Severity != alert.High {
				t.Errorf("severity=%v want High", f.Severity)
			}
			if f.SourceIP != "192.0.2.50" {
				t.Errorf("sourceIP=%q want 192.0.2.50", f.SourceIP)
			}
		}
	}
	if !found {
		t.Errorf("http_request_flood not emitted, got=%+v", got)
	}
}

func TestHTTPRequestFlood_RecordCountedThroughScan(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStatsAt(now)
	line := `192.0.2.60 - - [20/May/2026:18:00:00 +0300] "GET /index.html HTTP/1.1" 200 100 "-" "Mozilla/5.0"`
	rec, ok := parseAccessLogRecord(line)
	if !ok {
		t.Fatal("parse failed")
	}
	for i := 0; i < 75; i++ {
		stats.scan(rec, cfg, nopBotClassifier{})
	}
	got := stats.emit(cfg)
	if len(got) != 1 || got[0].Check != "http_request_flood" {
		t.Fatalf("emit=%+v", got)
	}
}

func TestHTTPRequestFlood_IgnoresRecordsOutsideWindow(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 30, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 1
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStatsAt(now)
	line := `192.0.2.61 - - [20/May/2026:18:00:00 +0300] "GET /index.html HTTP/1.1" 200 100 "-" "Mozilla/5.0"`
	rec, ok := parseAccessLogRecord(line)
	if !ok {
		t.Fatal("parse failed")
	}
	stats.scan(rec, cfg, nopBotClassifier{})
	if got := stats.emit(cfg); len(got) != 0 {
		t.Fatalf("old request emitted findings: %+v", got)
	}
}

func TestClassifyUA(t *testing.T) {
	cases := []struct {
		ua     string
		method string
		want   uaKind
	}{
		{"", "GET", uaKindEmpty},
		{"-", "GET", uaKindEmpty},
		{"Mozilla/5.0 nikto/2.5", "GET", uaKindKnownScanner},
		{"sqlmap/1.7", "POST", uaKindKnownScanner},
		{"WordPress/6.9.4; https://example.com", "GET", uaKindWPSpoofPingback},
		{"WordPress/6.9.4; https://example.com", "POST", uaKindBrowser}, // POST is legit pingback
		{"Googlebot/2.1 (+http://www.google.com/bot.html)", "GET", uaKindClaimedBot},
		{"python-requests/2.31.0", "GET", uaKindScriptingLang},
		{"curl/8.4.0", "POST", uaKindScriptingLang},
		{"HeadlessChrome/120.0", "GET", uaKindHeadless},
		{"Mozilla/5.0 (Windows NT 10.0)", "GET", uaKindBrowser},
	}
	for _, c := range cases {
		got := classifyUA(c.ua, c.method)
		if got != c.want {
			t.Errorf("classifyUA(%q,%q)=%v want %v", c.ua, c.method, got, c.want)
		}
	}
}

func TestHTTPUASpoof_KnownScannerImmediate(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPUASpoofThreshold = 30 // not used for scanner

	stats := newDomlogStats()
	stats.samples["192.0.2.70"] = httpSample{Method: "GET", URI: "/wp-admin/", UA: "nikto/2.5"}
	stats.uaCat["192.0.2.70"] = map[uaKind]int{uaKindKnownScanner: 1}

	got := stats.emit(cfg)
	found := false
	for _, f := range got {
		if f.Check == "http_ua_spoof" {
			found = true
			if f.Severity != alert.Critical {
				t.Errorf("severity=%v want Critical", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("scanner UA did not emit http_ua_spoof: %+v", got)
	}
}

func TestHTTPUASpoof_WPPingbackBelowThreshold(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPUASpoofThreshold = 30
	stats := newDomlogStats()
	stats.uaCat["192.0.2.71"] = map[uaKind]int{uaKindWPSpoofPingback: 29}
	got := stats.emit(cfg)
	for _, f := range got {
		if f.Check == "http_ua_spoof" {
			t.Fatalf("emitted below threshold: %+v", f)
		}
	}
}

func TestHTTPUASpoof_WPPingbackAtThreshold(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPUASpoofThreshold = 30
	stats := newDomlogStats()
	stats.samples["192.0.2.72"] = httpSample{
		Method: "GET", URI: "/wp-content/plugins/x.js?ver=1",
		UA: "WordPress/6.9.4; https://victim.example",
	}
	stats.uaCat["192.0.2.72"] = map[uaKind]int{uaKindWPSpoofPingback: 30}
	got := stats.emit(cfg)
	found := false
	for _, f := range got {
		if f.Check == "http_ua_spoof" && f.SourceIP == "192.0.2.72" {
			found = true
		}
	}
	if !found {
		t.Errorf("WP pingback spoof at threshold did not emit: %+v", got)
	}
}

func TestClaimedBot_StaticAllowlistSkips(t *testing.T) {
	// IP inside a known Googlebot range -> verified by static list ->
	// stats.scan should NOT count this request into httpReqs or uaCat.
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50

	bot := &staticAllowlistClassifier{}
	stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
	line := `66.249.66.1 - - [20/May/2026:18:00:00 +0300] "GET /robots.txt HTTP/1.1" 200 100 "-" ` +
		`"Googlebot/2.1 (+http://www.google.com/bot.html)"`
	rec, ok := parseAccessLogRecord(line)
	if !ok {
		t.Fatal("parse failed")
	}
	for i := 0; i < 200; i++ {
		stats.scan(rec, cfg, bot)
	}
	if stats.httpReqs["66.249.66.1"] != 0 {
		t.Errorf("verified Googlebot got counted: %d", stats.httpReqs["66.249.66.1"])
	}
	if len(stats.uaCat["66.249.66.1"]) != 0 {
		t.Errorf("verified Googlebot UA categories got counted: %v", stats.uaCat["66.249.66.1"])
	}
}

func TestClaimedBot_OutsideStaticRangeDoesNotEmitYet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPUASpoofThreshold = 1

	stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
	line := `203.0.113.77 - - [20/May/2026:18:05:00 +0300] "GET /robots.txt HTTP/1.1" 200 100 "-" ` +
		`"Googlebot/2.1 fake"`
	rec, ok := parseAccessLogRecord(line)
	if !ok {
		t.Fatal("parse failed")
	}
	stats.scan(rec, cfg, staticAllowlistClassifier{})
	for _, f := range stats.emit(cfg) {
		if f.Check == "http_ua_spoof" {
			t.Fatalf("claimed bot must fail open until rDNS confirms negative: %+v", f)
		}
	}
}
