package checks

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
)

// TestRefactorParity feeds a fixed set of access-log lines through the
// current countBruteForce / aggregator path and asserts that the same
// three legacy findings come out with the same operator-facing messages
// and severities.
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
		SourceIP string
	}{
		{"wp_login_bruteforce", alert.Critical, "WordPress login brute force from 192.0.2.10: 20 attempts", "192.0.2.10"},
		{"wp_user_enumeration", alert.High, "WordPress user enumeration from 203.0.113.30: 6 requests", "203.0.113.30"},
		{"xmlrpc_abuse", alert.Critical, "XML-RPC abuse from 198.51.100.20: 32 requests", "198.51.100.20"},
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
		if got[i].SourceIP != w.SourceIP {
			t.Errorf("[%d] SourceIP=%q want %q", i, got[i].SourceIP, w.SourceIP)
		}
		if key := incident.KeyFor(got[i]); key.RemoteIP != w.SourceIP {
			t.Errorf("[%d] incident RemoteIP=%q want %q", i, key.RemoteIP, w.SourceIP)
		}
	}
}

func TestHTTPAbuseRejectsMalformedClientIP(t *testing.T) {
	stats := newDomlogStats()
	rec := accessLogRecord{RemoteIP: "client.example", Method: "POST", URI: "/wp-login.php"}
	for i := 0; i < wpLoginThreshold; i++ {
		stats.scan(rec, nil, nopBotClassifier{})
	}

	if got := stats.emitLegacy(nil); len(got) != 0 {
		t.Fatalf("malformed client IP emitted structured finding: %+v", got)
	}
}

func TestHTTPAbuseNormalizesStructuredSourceIP(t *testing.T) {
	stats := newDomlogStats()
	rec := accessLogRecord{
		RemoteIP: "2001:0db8:0000:0000:0000:0000:0000:0001",
		Method:   "POST",
		URI:      "/wp-login.php",
	}
	for i := 0; i < wpLoginThreshold; i++ {
		stats.scan(rec, nil, nopBotClassifier{})
	}

	got := stats.emitLegacy(nil)
	if len(got) != 1 {
		t.Fatalf("findings=%d, want 1: %+v", len(got), got)
	}
	if got[0].SourceIP != "2001:db8::1" {
		t.Fatalf("SourceIP=%q want canonical IPv6", got[0].SourceIP)
	}
	if key := incident.KeyFor(got[0]); key.RemoteIP != "2001:db8::1" {
		t.Fatalf("incident RemoteIP=%q want canonical IPv6", key.RemoteIP)
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

func TestHTTPRequestFlood_StampsSingleVhost(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStatsAt(now)
	rec, _ := parseAccessLogRecord(`192.0.2.60 - - [20/May/2026:18:00:00 +0300] "GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0"`)
	rec.Domain = "example.com"
	for i := 0; i < 75; i++ {
		stats.scan(rec, cfg, nopBotClassifier{})
	}
	got := stats.emit(cfg)
	if len(got) != 1 || got[0].Check != "http_request_flood" {
		t.Fatalf("emit=%+v", got)
	}
	if got[0].Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", got[0].Domain)
	}
	if strings.Contains(got[0].Message, "across") {
		t.Errorf("single-vhost message should not claim cross-vhost spread: %q", got[0].Message)
	}
}

func TestHTTPRequestFlood_ReportsCrossVhostSpread(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStatsAt(now)
	// One IP spread across three vhosts: aggregate trips, and the finding
	// reports the cross-site spread with no single attributable domain.
	for _, dom := range []string{"a.example", "b.example", "c.example"} {
		rec, _ := parseAccessLogRecord(`192.0.2.70 - - [20/May/2026:18:00:00 +0300] "GET /x HTTP/1.1" 200 100 "-" "Mozilla/5.0"`)
		rec.Domain = dom
		for i := 0; i < 30; i++ {
			stats.scan(rec, cfg, nopBotClassifier{})
		}
	}
	got := stats.emit(cfg)
	if len(got) != 1 || got[0].Check != "http_request_flood" {
		t.Fatalf("emit=%+v", got)
	}
	if got[0].Domain != "" {
		t.Errorf("Domain = %q, want empty for multi-vhost flood", got[0].Domain)
	}
	if !strings.Contains(got[0].Message, "across 3 vhosts") {
		t.Errorf("message should report cross-vhost spread: %q", got[0].Message)
	}
}

func TestHTTPRequestFlood_VhostSpreadIgnoresRecordsOutsideWindow(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 3
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStatsAt(now)
	old, _ := parseAccessLogRecord(`192.0.2.80 - - [20/May/2026:17:00:00 +0300] "GET /old HTTP/1.1" 200 100 "-" "Mozilla/5.0"`)
	old.Domain = "stale.example"
	stats.scan(old, cfg, nopBotClassifier{})

	for _, dom := range []string{"a.example", "b.example"} {
		rec, _ := parseAccessLogRecord(`192.0.2.80 - - [20/May/2026:18:04:00 +0300] "GET /new HTTP/1.1" 200 100 "-" "Mozilla/5.0"`)
		rec.Domain = dom
		for i := 0; i < 2; i++ {
			stats.scan(rec, cfg, nopBotClassifier{})
		}
	}
	got := stats.emit(cfg)
	if len(got) != 1 || got[0].Check != "http_request_flood" {
		t.Fatalf("emit=%+v", got)
	}
	if got[0].Domain != "" {
		t.Errorf("Domain = %q, want empty for multi-vhost flood", got[0].Domain)
	}
	if !strings.Contains(got[0].Message, "across 2 vhosts") {
		t.Errorf("message should count only in-window vhosts: %q", got[0].Message)
	}
	if strings.Contains(got[0].Details, "/old") {
		t.Errorf("sample should come from an in-window request: %q", got[0].Details)
	}
}

func TestHTTPRequestFlood_CentralRecordsDoNotInheritStaleVhost(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 3
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStatsAt(now)
	old, _ := parseAccessLogRecord(`192.0.2.81 - - [20/May/2026:17:00:00 +0300] "GET /old HTTP/1.1" 200 100 "-" "Mozilla/5.0"`)
	old.Domain = "stale.example"
	stats.scan(old, cfg, nopBotClassifier{})

	current, _ := parseAccessLogRecord(`192.0.2.81 - - [20/May/2026:18:04:00 +0300] "GET /central HTTP/1.1" 200 100 "-" "Mozilla/5.0"`)
	for i := 0; i < 3; i++ {
		stats.scan(current, cfg, nopBotClassifier{})
	}
	got := stats.emit(cfg)
	if len(got) != 1 || got[0].Check != "http_request_flood" {
		t.Fatalf("emit=%+v", got)
	}
	if got[0].Domain != "" {
		t.Errorf("central-log flood Domain = %q, want empty", got[0].Domain)
	}
	if strings.Contains(got[0].Message, "across") {
		t.Errorf("central-log flood should not claim vhost spread: %q", got[0].Message)
	}
}

func TestDomainFromDomlogPath(t *testing.T) {
	cases := map[string]string{
		"/usr/local/apache/domlogs/example.com":              "example.com",
		"/home/u/access-logs/example.com-ssl_log":            "example.com",
		"/home/u/access-logs/example.com_log":                "example.com",
		"/var/log/apache2/sub.example.co.uk_log":             "sub.example.co.uk",
		"/usr/local/apache/domlogs/Example.COM":              "example.com",
		"/var/log/apache2/www.example.com-access.log":        "www.example.com",
		"/var/log/apache2/www.example.com_access.log":        "www.example.com",
		"/var/log/httpd/www.example.com-access_log":          "www.example.com",
		"/var/log/httpd/www.example.com_access_log":          "www.example.com",
		"/var/log/nginx/www.example.com.access.log":          "www.example.com",
		"/var/log/nginx/www.example.com-access.log":          "www.example.com",
		"/var/log/httpd/domains/www.example.com.log":         "www.example.com",
		"/var/www/vhosts/Example.COM/logs/access_log":        "example.com",
		"/var/www/vhosts/example.net/logs/access_ssl_log":    "example.net",
		"/var/www/vhosts/system/example.org/logs/access_log": "example.org",
		"/var/log/httpd/access_log":                          "", // central, not a domain
		"/var/log/apache2/access.log":                        "", // central, not a domain
		"/var/log/apache2/other_vhosts_access.log":           "", // central, not a domain
		"/some/path/ftpxferlog":                              "", // no dot
		"/var/log/httpd/domains/192.0.2.10.log":              "", // IP-literal vhost
		"/var/log/httpd/domains/bad_name.example.log":        "", // invalid label
	}
	for in, want := range cases {
		if got := domainFromDomlogPath(in); got != want {
			t.Errorf("domainFromDomlogPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// seedAbusiveIPsToDomain drives `count` distinct IPs, each making enough
// in-window xmlrpc POSTs to cross xmlrpcThreshold, against one vhost.
func seedAbusiveIPsToDomain(t *testing.T, stats *domlogStats, domain string, count int, ts time.Time) {
	t.Helper()
	for i := 0; i < count; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		seedAbusiveIPToDomains(t, stats, ip, []string{domain}, ts)
	}
}

func seedAbusiveIPToDomains(t *testing.T, stats *domlogStats, ip string, domains []string, ts time.Time) {
	t.Helper()
	line := `IP - - [20/May/2026:18:00:00 +0300] "POST /xmlrpc.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`
	for _, domain := range domains {
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			t.Fatal("parse")
		}
		rec.RemoteIP = ip
		rec.Time = ts
		rec.Domain = domain
		for j := 0; j < xmlrpcThreshold; j++ {
			stats.scan(rec, &config.Config{}, nopBotClassifier{})
		}
	}
}

func TestHTTPDistributedFlood_FiresOnManyAbusiveIPsOneVhost(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodWindowMin = 60
	cfg.Thresholds.HTTPDistributedMinIPs = 10

	stats := newDomlogStatsAt(now)
	seedAbusiveIPsToDomain(t, stats, "victim.example", 12, now)

	got := stats.emit(cfg)
	var dist *alert.Finding
	for i := range got {
		if got[i].Check == "http_distributed_flood" {
			dist = &got[i]
		}
	}
	if dist == nil {
		t.Fatalf("expected http_distributed_flood, got %+v", got)
	}
	if dist.Domain != "victim.example" {
		t.Errorf("Domain = %q, want victim.example", dist.Domain)
	}
	if !strings.Contains(dist.Message, "12 distinct abusive source IPs") {
		t.Errorf("message = %q", dist.Message)
	}
}

func TestHTTPDistributedFlood_DoesNotUseNormalCurrentHitsForStaleAbuse(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodWindowMin = 60
	cfg.Thresholds.HTTPDistributedMinIPs = 10

	stats := newDomlogStatsAt(now)
	seedAbusiveIPsToDomain(t, stats, "attacked.example", 12, now.Add(-2*time.Hour))

	normal, ok := parseAccessLogRecord(`IP - - [20/May/2026:18:04:00 +0300] "GET / HTTP/1.1" 200 0 "-" "Mozilla/5.0"`)
	if !ok {
		t.Fatal("parse")
	}
	normal.Time = now
	normal.Domain = "popular.example"
	for i := 0; i < 12; i++ {
		normal.RemoteIP = fmt.Sprintf("203.0.113.%d", i+1)
		stats.scan(normal, cfg, nopBotClassifier{})
	}

	for _, f := range stats.emit(cfg) {
		if f.Check == "http_distributed_flood" {
			t.Fatalf("old XML-RPC abuse plus current normal hits must not roll up to popular.example: %+v", f)
		}
	}
}

func TestHTTPDistributedFlood_AbusiveIPContributesToEachAbusedVhost(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodWindowMin = 60
	cfg.Thresholds.HTTPDistributedMinIPs = 2

	stats := newDomlogStatsAt(now)
	for _, ip := range []string{"203.0.113.10", "203.0.113.11"} {
		seedAbusiveIPToDomains(t, stats, ip, []string{"a.example", "b.example"}, now)
	}

	got := stats.emit(cfg)
	found := map[string]bool{}
	for _, f := range got {
		if f.Check == "http_distributed_flood" {
			found[f.Domain] = true
		}
	}
	for _, dom := range []string{"a.example", "b.example"} {
		if !found[dom] {
			t.Fatalf("distributed flood missing for %s: %+v", dom, got)
		}
	}
}

func TestHTTPDistributedFlood_IgnoresNormalVisitorSpread(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodWindowMin = 60
	cfg.Thresholds.HTTPDistributedMinIPs = 10

	stats := newDomlogStatsAt(now)
	line := `IP - - [20/May/2026:18:04:00 +0300] "GET / HTTP/1.1" 200 0 "-" "Mozilla/5.0"`
	for i := 0; i < 25; i++ {
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			t.Fatal("parse")
		}
		rec.RemoteIP = fmt.Sprintf("203.0.113.%d", i+1)
		rec.Time = now
		rec.Domain = "popular.example"
		stats.scan(rec, cfg, nopBotClassifier{})
	}

	for _, f := range stats.emit(cfg) {
		if f.Check == "http_distributed_flood" {
			t.Fatalf("normal visitor spread must not emit distributed flood: %+v", f)
		}
	}
}

func TestHTTPDistributedFlood_BelowThresholdAndDisabled(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	stats := newDomlogStatsAt(now)
	seedAbusiveIPsToDomain(t, stats, "victim.example", 6, now)

	// Below the min-IP threshold: no distributed finding.
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodWindowMin = 60
	cfg.Thresholds.HTTPDistributedMinIPs = 10
	for _, f := range stats.emit(cfg) {
		if f.Check == "http_distributed_flood" {
			t.Fatalf("6 IPs must not trip a min-10 distributed flood: %+v", f)
		}
	}

	// Threshold 0 disables the rollup even with many abusive IPs.
	stats2 := newDomlogStatsAt(now)
	seedAbusiveIPsToDomain(t, stats2, "victim.example", 20, now)
	cfg0 := &config.Config{}
	cfg0.Thresholds.HTTPFloodWindowMin = 60
	cfg0.Thresholds.HTTPDistributedMinIPs = 0
	for _, f := range stats2.emit(cfg0) {
		if f.Check == "http_distributed_flood" {
			t.Fatalf("threshold 0 must disable distributed flood: %+v", f)
		}
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

func TestClientIPForRecord_RequiresTrustedProxy(t *testing.T) {
	// A trusted proxy appends the real client as the rightmost XFF entry.
	rec := accessLogRecord{
		RemoteIP: "198.51.100.10",
		XFF:      "192.0.2.50, 203.0.113.10",
	}

	if got := clientIPForRecord(rec, &config.Config{}); got != "198.51.100.10" {
		t.Fatalf("untrusted proxy used XFF: got %q", got)
	}

	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"198.51.100.0/24"}
	if got := clientIPForRecord(rec, cfg); got != "203.0.113.10" {
		t.Fatalf("trusted proxy client IP=%q, want 203.0.113.10", got)
	}
}

// A client must not be able to forge an attribution by injecting a victim IP
// into the leftmost X-Forwarded-For position. The proxy-appended rightmost
// entry is authoritative; the leftmost is attacker-controlled. Taking the
// leftmost let an attacker auto-block any chosen victim.
func TestClientIPForRecord_RejectsSpoofedLeftmost(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"198.51.100.0/24"}
	rec := accessLogRecord{
		RemoteIP: "198.51.100.10",
		XFF:      "203.0.113.99, 203.0.113.10", // attacker put victim 203.0.113.99 leftmost
	}
	if got := clientIPForRecord(rec, cfg); got != "203.0.113.10" {
		t.Fatalf("spoofed leftmost XFF honoured: got %q, want 203.0.113.10", got)
	}
}

// The direct proxy's appended entry is authoritative even when it also matches
// a trusted-proxy CIDR. Skipping it would make the next entry to the left
// client-controlled again.
func TestClientIPForRecord_UsesProxyAppendedEntryInTrustedCIDR(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"198.51.100.0/24"}
	rec := accessLogRecord{
		RemoteIP: "198.51.100.10",
		XFF:      "203.0.113.99, 198.51.100.20",
	}
	if got := clientIPForRecord(rec, cfg); got != "198.51.100.20" {
		t.Fatalf("trusted-CIDR appended entry: got %q, want 198.51.100.20", got)
	}
}

func TestClientIPForRecord_TrimsTrustedProxyEntries(t *testing.T) {
	rec := accessLogRecord{RemoteIP: "198.51.100.10", XFF: "203.0.113.10"}
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{" 198.51.100.10 "}

	if got := clientIPForRecord(rec, cfg); got != "203.0.113.10" {
		t.Fatalf("trusted proxy client IP=%q, want 203.0.113.10", got)
	}
}

func TestParseAccessLogRecord_CPanelVhostNotXFF(t *testing.T) {
	line := `192.0.2.60 - - [20/May/2026:18:00:00 +0300] "GET /index.html HTTP/1.1" 200 100 "-" "Mozilla/5.0" "example.com:443"`

	rec, ok := parseAccessLogRecord(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if rec.XFF != "" {
		t.Fatalf("cPanel vhost extension parsed as XFF: %q", rec.XFF)
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
		{"Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)", "GET", uaKindClaimedBot},
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

func TestHTTPUASpoof_StampsSingleVhost(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPUASpoofThreshold = 30
	cfg.Thresholds.HTTPFloodWindowMin = 5

	stats := newDomlogStatsAt(now)
	rec, ok := parseAccessLogRecord(`192.0.2.82 - - [20/May/2026:18:04:00 +0300] "GET /wp-admin/ HTTP/1.1" 404 100 "-" "nikto/2.5"`)
	if !ok {
		t.Fatal("parse failed")
	}
	rec.Domain = "example.com"
	stats.scan(rec, cfg, nopBotClassifier{})

	got := stats.emit(cfg)
	for _, f := range got {
		if f.Check != "http_ua_spoof" {
			continue
		}
		if f.Domain != "example.com" {
			t.Fatalf("Domain = %q, want example.com", f.Domain)
		}
		if strings.Contains(f.Message, "across") {
			t.Fatalf("single-vhost message should not claim spread: %q", f.Message)
		}
		return
	}
	t.Fatalf("http_ua_spoof not emitted: %+v", got)
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

// pendingVerifyClassifier simulates a verifyingClassifier whose cache is
// empty -- the async job has been enqueued but has not completed yet.
type pendingVerifyClassifier struct{}

func (pendingVerifyClassifier) IsVerifiedBot(string, string) bool { return false }

func TestClaimedBot_PendingVerifyStillCountsForFlood(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50

	stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
	line := `203.0.113.99 - - [20/May/2026:18:00:00 +0300] "GET /robots.txt HTTP/1.1" 200 100 "-" "Googlebot/2.1 fake"`
	rec, ok := parseAccessLogRecord(line)
	if !ok {
		t.Fatal("parse failed")
	}
	for i := 0; i < 75; i++ {
		stats.scan(rec, cfg, pendingVerifyClassifier{})
	}
	got := stats.emit(cfg)
	floodSeen := false
	uaSpoofSeen := false
	for _, f := range got {
		if f.Check == "http_request_flood" {
			floodSeen = true
		}
		if f.Check == "http_ua_spoof" {
			uaSpoofSeen = true
		}
	}
	if !floodSeen {
		t.Error("flood must still emit while verify is pending")
	}
	if uaSpoofSeen {
		t.Error("ua_spoof must NOT emit while verify is pending (fail-open)")
	}
}

// negativeVerifyClassifier simulates a cache-confirmed negative: the IP
// sent a claimed-bot UA but PTR+forward-A verification failed.
type negativeVerifyClassifier struct{}

func (negativeVerifyClassifier) IsVerifiedBot(string, string) bool     { return false }
func (negativeVerifyClassifier) ConfirmedNegative(string, string) bool { return true }

func TestClaimedBot_ConfirmedNegativeEmitsUASpoof(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 0
	cfg.Thresholds.HTTPUASpoofThreshold = 30

	stats := newDomlogStatsAt(time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600)))
	line := `203.0.113.100 - - [20/May/2026:18:05:00 +0300] "GET /robots.txt HTTP/1.1" 200 100 "-" "Googlebot/2.1 fake"`
	rec, ok := parseAccessLogRecord(line)
	if !ok {
		t.Fatal("parse failed")
	}
	stats.scan(rec, cfg, negativeVerifyClassifier{})
	got := stats.emit(cfg)
	for _, f := range got {
		if f.Check == "http_ua_spoof" {
			return
		}
	}
	t.Fatalf("confirmed negative claimed bot did not emit ua spoof: %+v", got)
}
