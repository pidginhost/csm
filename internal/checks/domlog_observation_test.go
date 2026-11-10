package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

var domlogScanTime = time.Date(2026, 11, 9, 12, 5, 0, 0, time.UTC)

func domlogTestLine(ip string, second int, method, uri string, status int, ua string) string {
	return fmt.Sprintf(`%s - - [09/Nov/2026:12:01:%02d +0000] "%s %s HTTP/1.1" %d 100 "-" "%s"`, ip, second, method, uri, status, ua)
}

func domlogTestTime(second int) time.Time { return time.Date(2026, 11, 9, 12, 1, second, 0, time.UTC) }

// scanDomlogFile feeds lines through the domlog tail as one per-vhost log
// and returns the file's path and the findings.
func scanDomlogFile(t *testing.T, cfg *config.Config, bot botClassifier, lines []string) (string, []alert.Finding) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.test")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: os.Open})
	stats := newDomlogStatsAt(domlogScanTime)
	if n := tailDomlogsInto(context.Background(), []string{path}, cfg, stats, bot, 1000); n != 1 {
		t.Fatalf("tailed %d logs, want 1", n)
	}
	return path, stats.emit(cfg)
}

// Every per-address domlog finding names the newest record that counted
// toward it, read as the HTTP peer, at the time the server logged it.
func TestDomlogScanNamesEachFindingsNewestRecord(t *testing.T) {
	const ip = "203.0.113.60"
	repeat := func(n int, line func(i int) string) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, line(i))
		}
		return out
	}
	other := func(second int) string { return domlogTestLine(ip, second, "GET", "/", 200, "Mozilla/5.0") }
	for check, tc := range map[string]struct {
		cfg    func(*config.Config)
		bot    botClassifier
		lines  []string
		newest int
	}{
		"wp_login_bruteforce": {lines: append(repeat(20, func(i int) string { return domlogTestLine(ip, i, "POST", "/wp-login.php", 200, "Mozilla/5.0") }), other(30)), newest: 19},
		"xmlrpc_abuse": {cfg: func(c *config.Config) { c.Thresholds.XMLRPCThreshold = 3 },
			lines: append(repeat(3, func(i int) string { return domlogTestLine(ip, i, "POST", "/xmlrpc.php", 200, "Mozilla/5.0") }), other(30)), newest: 2},
		"wp_user_enumeration": {lines: append(repeat(5, func(i int) string {
			return domlogTestLine(ip, i, "GET", fmt.Sprintf("/?author=%d", i), 200, "Mozilla/5.0")
		}), other(30)), newest: 4},
		"http_request_flood": {cfg: func(c *config.Config) { c.Thresholds.HTTPFloodThreshold = 20 },
			lines: append(repeat(20, func(i int) string {
				return domlogTestLine(ip, i, "GET", fmt.Sprintf("/page-%d", i), 200, "Mozilla/5.0")
			}),
				domlogTestLine("198.51.100.61", 40, "GET", "/", 200, "Mozilla/5.0")), newest: 19},
		"http_ua_spoof": {lines: []string{domlogTestLine(ip, 0, "GET", "/", 200, "sqlmap/1.7"), domlogTestLine(ip, 1, "GET", "/a", 200, "sqlmap/1.7"), other(5)}, newest: 1},
		"http_scanner_profile": {cfg: func(c *config.Config) {
			c.Thresholds.HTTPScannerMinRequests, c.Thresholds.HTTPScannerErrorPct, c.Thresholds.HTTPScannerMinDistinctPaths = 10, 80, 5
		}, lines: append(repeat(12, func(i int) string {
			return domlogTestLine(ip, i, "GET", fmt.Sprintf("/probe-%d", i), 404, "Mozilla/5.0")
		}), other(20)), newest: 11},
		"http_claimed_bot_unverified": {cfg: func(c *config.Config) { c.Thresholds.HTTPFloodThreshold = 20 }, bot: pendingVerifyClassifier{},
			lines: append(repeat(20, func(i int) string { return domlogTestLine(ip, i, "GET", "/robots.txt", 200, "Googlebot/2.1 fake") }), other(25)), newest: 19},
	} {
		t.Run(check, func(t *testing.T) {
			cfg := &config.Config{}
			if tc.cfg != nil {
				tc.cfg(cfg)
			}
			bot := tc.bot
			if bot == nil {
				bot = nopBotClassifier{}
			}
			path, findings := scanDomlogFile(t, cfg, bot, tc.lines)
			var got []alert.Finding
			for _, f := range findings {
				if f.Check == check && f.SourceIP == ip {
					got = append(got, f)
				}
			}
			if len(got) != 1 {
				t.Fatalf("%s findings %+v, want one for %s", check, findings, ip)
			}
			if got[0].Attribution != admission.AttributionHTTPPeer {
				t.Fatalf("attribution %s, want http_peer", got[0].Attribution)
			}
			wantScanObservation(t, got[0], ProducerDomlogScan, lineRef(t, path, tc.lines, tc.newest), domlogTestTime(tc.newest))
		})
	}
}

// An address resolved from a trusted proxy's forwarded header is not the
// HTTP peer of its record: the finding keeps the record but no kind, until
// trusted chains are read (plan 2.1c).
func TestDomlogScanLeavesAForwardedAddressUnattributed(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"192.0.2.10"}
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf(`192.0.2.10 - - [09/Nov/2026:12:01:%02d +0000] "POST /wp-login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0" "203.0.113.62"`, i))
	}
	path, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
	f := oneScanFinding(t, findings, "wp_login_bruteforce")
	if f.SourceIP != "203.0.113.62" || f.Attribution != admission.AttributionUnknown {
		t.Fatalf("finding %s read as %s, want the forwarded address with no kind", f.SourceIP, f.Attribution)
	}
	wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, 19), domlogTestTime(19))
}

// A count that mixes forwarded and direct records is not the HTTP peer's,
// even when the newest record is direct: one direct request cannot vouch for
// the rest.
func TestDomlogScanLeavesAMixedCountUnattributed(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"192.0.2.10"}
	var lines []string
	for i := 0; i < 19; i++ {
		lines = append(lines, fmt.Sprintf(`192.0.2.10 - - [09/Nov/2026:12:01:%02d +0000] "POST /wp-login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0" "203.0.113.62"`, i))
	}
	lines = append(lines, domlogTestLine("203.0.113.62", 30, "POST", "/wp-login.php", 200, "Mozilla/5.0"))
	path, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
	f := oneScanFinding(t, findings, "wp_login_bruteforce")
	if f.SourceIP != "203.0.113.62" || f.Attribution != admission.AttributionUnknown {
		t.Fatalf("finding %s read as %s, want the mixed count with no kind", f.SourceIP, f.Attribution)
	}
	wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, 19), domlogTestTime(30))
}

// The central access log read alongside the domlogs names its own records.
func TestWPBruteForceCentralLogNamesItsRecords(t *testing.T) {
	root := t.TempDir()
	central := filepath.Join(root, "central.log")
	var lines []string
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf(`203.0.113.63 - - [%s] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`, now.Add(time.Duration(i-30)*time.Second).Format("02/Jan/2006:15:04:05 -0700")))
	}
	if err := os.WriteFile(central, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{AccessLogPaths: []string{central}, DomlogGlobs: []string{filepath.Join(root, "*_log")}})
	t.Cleanup(platform.ResetForTest)
	withMockOS(t, &mockOS{glob: filepath.Glob, stat: os.Stat, open: os.Open})
	f := oneScanFinding(t, CheckWPBruteForce(context.Background(), &config.Config{}, nil), "wp_login_bruteforce")
	if f.Attribution != admission.AttributionHTTPPeer {
		t.Fatalf("attribution %s, want http_peer", f.Attribution)
	}
	wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, central, lines, 19), now.Add(-11*time.Second))
}

// domlogProxy is the trusted proxy of the forwarded fixtures.
const domlogProxy = "192.0.2.10"

// forwardedVia rewrites a direct domlog line from ip as one the trusted proxy
// logged, with ip as the forwarded client.
func forwardedVia(line, ip string) string {
	return strings.Replace(line, ip+" - - ", domlogProxy+" - - ", 1) + ` "` + ip + `"`
}

// scanDomlogFiles feeds each list of lines through the domlog tail as its own
// per-vhost log and returns the files' paths and the findings.
func scanDomlogFiles(t *testing.T, cfg *config.Config, bot botClassifier, logs ...[]string) ([]string, []alert.Finding) {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, lines := range logs {
		path := filepath.Join(dir, fmt.Sprintf("site%d.example.test", i))
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	withMockOS(t, &mockOS{open: os.Open})
	stats := newDomlogStatsAt(domlogScanTime)
	if n := tailDomlogsInto(context.Background(), paths, cfg, stats, bot, 1000); n != len(paths) {
		t.Fatalf("tailed %d logs, want %d", n, len(paths))
	}
	return paths, stats.emit(cfg)
}

// mintScanFinding mints f through the registered producer its observation
// names, as admission would.
func mintScanFinding(t *testing.T, f alert.Finding) (admission.Evidence, admission.Target, error) {
	t.Helper()
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	producers := map[admission.ProducerID]*admission.Producer{}
	for _, p := range ProducerTable() {
		registered, regErr := reg.Register(p.Spec)
		if regErr != nil {
			t.Fatal(regErr)
		}
		producers[p.Spec.ID] = registered
	}
	id, in, err := AdmissionEvidence(f)
	if err != nil {
		return admission.Evidence{}, admission.Target{}, err
	}
	e, err := producers[id].Mint(in)
	return e, in.Target, err
}

// wantNoKind fails unless f keeps its observation but no kind, so admission
// refuses it for want of an attributed address.
func wantNoKind(t *testing.T, f alert.Finding) {
	t.Helper()
	if f.Attribution != admission.AttributionUnknown {
		t.Fatalf("%s from %s read as %s, want no kind", f.Check, f.SourceIP, f.Attribution)
	}
	if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseKindNotAllowed {
		t.Fatalf("%s from %s minted or refused without the kind cause: %v", f.Check, f.SourceIP, err)
	}
}

// wantPeerMints fails unless f is read as the HTTP peer and mints.
func wantPeerMints(t *testing.T, f alert.Finding) {
	t.Helper()
	if f.Attribution != admission.AttributionHTTPPeer {
		t.Fatalf("%s from %s read as %s, want http_peer", f.Check, f.SourceIP, f.Attribution)
	}
	if _, _, err := mintScanFinding(t, f); err != nil {
		t.Fatalf("%s from %s: %v", f.Check, f.SourceIP, err)
	}
}

// A trusted proxy's forwarded selection is not the HTTP peer, even when the
// forwarded address equals the proxy's own. An untrusted peer's forged
// header is ignored: the peer itself is read and mints.
func TestDomlogScanForwardedPeerEquality(t *testing.T) {
	for name, tc := range map[string]struct {
		peer, forwarded, trusted string
	}{
		"ipv4":        {"192.0.2.10", "192.0.2.10", "192.0.2.10"},
		"mapped ipv4": {"192.0.2.10", "::ffff:192.0.2.10", "192.0.2.10"},
		"ipv6":        {"2001:db8::10", "2001:db8::10", "2001:db8::10"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.WebServer.TrustedProxies = []string{tc.trusted}
			var lines []string
			for i := 0; i < 20; i++ {
				lines = append(lines, domlogTestLine(tc.peer, i, "POST", "/wp-login.php", 200, "Mozilla/5.0")+` "`+tc.forwarded+`"`)
			}
			path, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
			f := oneScanFinding(t, findings, "wp_login_bruteforce")
			wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, 19), domlogTestTime(19))
			wantNoKind(t, f)
		})
	}
	t.Run("untrusted peer", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.WebServer.TrustedProxies = []string{domlogProxy}
		var lines []string
		for i := 0; i < 20; i++ {
			lines = append(lines, domlogTestLine("203.0.113.70", i, "POST", "/wp-login.php", 200, "Mozilla/5.0")+` "198.51.100.9"`)
		}
		path, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
		f := oneScanFinding(t, findings, "wp_login_bruteforce")
		if f.SourceIP != "203.0.113.70" {
			t.Fatalf("a forged header named %s", f.SourceIP)
		}
		wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, 19), domlogTestTime(19))
		wantPeerMints(t, f)
	})
}

func scannerTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{domlogProxy}
	cfg.Thresholds.HTTPScannerMinRequests, cfg.Thresholds.HTTPScannerErrorPct, cfg.Thresholds.HTTPScannerMinDistinctPaths = 10, 80, 5
	return cfg
}

// The scanner profile is decided by its whole denominator, not only its
// error records. Forwarded successes that bring the count to the minimum
// leave the finding, and its newest error record, with no kind.
func TestDomlogScannerDenominatorCannotVouchForPeer(t *testing.T) {
	const ip = "203.0.113.63"
	var errs, forwarded, direct []string
	for i := 0; i < 8; i++ {
		errs = append(errs, domlogTestLine(ip, i, "GET", fmt.Sprintf("/probe-%d", i), 404, "Mozilla/5.0"))
	}
	for i := 0; i < 2; i++ {
		line := domlogTestLine(ip, 20+i, "GET", fmt.Sprintf("/ok-%d", i), 200, "Mozilla/5.0")
		forwarded, direct = append(forwarded, forwardedVia(line, ip)), append(direct, line)
	}
	for name, tc := range map[string]struct {
		logs    [][]string
		file    int
		newest  int
		control bool
	}{
		"errors first":    {logs: [][]string{append(append([]string{}, errs...), forwarded...)}, newest: 7},
		"forwarded first": {logs: [][]string{append(append([]string{}, forwarded...), errs...)}, newest: 9},
		"separate files":  {logs: [][]string{forwarded, errs}, file: 1, newest: 7},
		"direct control":  {logs: [][]string{append(append([]string{}, errs...), direct...)}, newest: 7, control: true},
	} {
		t.Run(name, func(t *testing.T) {
			paths, findings := scanDomlogFiles(t, scannerTestConfig(), nopBotClassifier{}, tc.logs...)
			f := oneScanFinding(t, findings, "http_scanner_profile")
			if f.SourceIP != ip {
				t.Fatalf("scanner finding for %s", f.SourceIP)
			}
			wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, paths[tc.file], tc.logs[tc.file], tc.newest), domlogTestTime(7))
			if tc.control {
				wantPeerMints(t, f)
			} else {
				wantNoKind(t, f)
			}
		})
	}
}

// Browser assets do not count toward the scanner profile, but can defeat
// the pending-bot majority that would otherwise route it to a challenge.
// A forwarded vote in that decision cannot vouch for the HTTP peer.
func TestDomlogScannerBotRoutingCannotVouchForPeer(t *testing.T) {
	const ip = "203.0.113.72"
	for _, tc := range []struct {
		name         string
		pending      bool
		forwarded    bool
		assetsFirst  bool
		separateLogs bool
	}{
		{name: "forwarded assets last", pending: true, forwarded: true},
		{name: "forwarded assets first", pending: true, forwarded: true, assetsFirst: true},
		{name: "forwarded assets separate log", pending: true, forwarded: true, separateLogs: true},
		{name: "direct assets", pending: true},
		{name: "no pending bots", forwarded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := scannerTestConfig()
			ua := "Mozilla/5.0"
			if tc.pending {
				ua = "Googlebot/2.1 fake"
			}
			var probes, assets []string
			for i := 0; i < 10; i++ {
				probes = append(probes, domlogTestLine(ip, i, "GET", fmt.Sprintf("/probe-%d", i), 404, ua))
				line := domlogTestLine(ip, 20+i, "GET", "/style.css", 200, "Mozilla/5.0")
				if tc.forwarded {
					line = forwardedVia(line, ip)
				}
				assets = append(assets, line)
			}
			logs := [][]string{append(append([]string{}, probes...), assets...)}
			probeFile, newest := 0, len(probes)-1
			if tc.assetsFirst {
				logs = [][]string{append(append([]string{}, assets...), probes...)}
				newest += len(assets)
			} else if tc.separateLogs {
				logs = [][]string{assets, probes}
				probeFile = 1
			}
			paths, findings := scanDomlogFiles(t, cfg, pendingVerifyClassifier{}, logs...)
			if len(findings) != 1 {
				t.Fatalf("findings %+v, want only the scanner profile", findings)
			}
			f := oneScanFinding(t, findings, "http_scanner_profile")
			if f.SourceIP != ip || f.Severity != alert.High || !strings.Contains(f.Message, "10 of 10 requests") {
				t.Fatalf("scanner detection changed: %+v", f)
			}
			wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, paths[probeFile], logs[probeFile], newest), domlogTestTime(9))
			if tc.pending && tc.forwarded {
				wantNoKind(t, f)
			} else {
				wantPeerMints(t, f)
			}
		})
	}
}

// A pending claimed bot is decided by every in-window request: its majority,
// flood and scanner gates. Forwarded browser requests that complete those
// gates leave the claimed-bot finding with its pending-bot record but no
// kind, in either read order; direct traffic alone still mints.
func TestDomlogClaimedBotMixedThresholdHasNoKind(t *testing.T) {
	const ip = "203.0.113.64"
	pending := func(second int, uri string, status int) string {
		return domlogTestLine(ip, second, "GET", uri, status, "Googlebot/2.1 fake")
	}
	browser := func(second int, uri string, status int, forwarded bool) string {
		line := domlogTestLine(ip, second, "GET", uri, status, "Mozilla/5.0")
		if forwarded {
			return forwardedVia(line, ip)
		}
		return line
	}
	build := func(bots, others int, botURI func(int) (string, int), otherStatus int, forwarded, othersFirst bool) ([]string, int) {
		var b, o []string
		for i := 0; i < bots; i++ {
			uri, status := botURI(i)
			b = append(b, pending(i, uri, status))
		}
		for i := 0; i < others; i++ {
			o = append(o, browser(30+i, fmt.Sprintf("/ok-%d", i), otherStatus, forwarded))
		}
		if othersFirst {
			return append(o, b...), len(o) + bots - 1
		}
		return append(b, o...), bots - 1
	}
	flood := func(int) (string, int) { return "/robots.txt", 200 }
	probe := func(i int) (string, int) { return fmt.Sprintf("/probe-%d", i), 404 }
	for _, gate := range []string{"flood", "scanner"} {
		for _, order := range []string{"bots first", "others first", "direct control"} {
			t.Run(gate+"/"+order, func(t *testing.T) {
				cfg := scannerTestConfig()
				var lines []string
				var newest int
				forwarded, othersFirst := order != "direct control", order == "others first"
				if gate == "flood" {
					cfg.Thresholds.HTTPFloodThreshold = 20
					cfg.Thresholds.HTTPScannerMinRequests = 0
					lines, newest = build(11, 9, flood, 200, forwarded, othersFirst)
				} else {
					lines, newest = build(8, 2, probe, 200, forwarded, othersFirst)
				}
				path, findings := scanDomlogFile(t, cfg, pendingVerifyClassifier{}, lines)
				f := oneScanFinding(t, findings, "http_claimed_bot_unverified")
				at := 10
				if gate == "scanner" {
					at = 7
				}
				wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, newest), domlogTestTime(at))
				if forwarded {
					wantNoKind(t, f)
				} else {
					wantPeerMints(t, f)
				}
			})
		}
	}
}

// domlogFixture is a set of records that reaches one per-address finding,
// each record built by line at its second.
type domlogFixture struct {
	check string
	cfg   func(*config.Config)
	bot   botClassifier
	n     int
	line  func(ip string, i int) string
}

func domlogFixtures() map[string]domlogFixture {
	ua := func(agent string) func(string, int) string {
		return func(ip string, i int) string {
			return domlogTestLine(ip, i, "GET", fmt.Sprintf("/ua-%d", i), 200, agent)
		}
	}
	spoof := func(c *config.Config) {
		c.Thresholds.HTTPUASpoofThreshold = 3
		c.Thresholds.HTTPUAScriptingEnabled, c.Thresholds.HTTPUAHeadlessEnabled, c.Thresholds.HTTPUAEmptyEnabled = true, true, true
	}
	return map[string]domlogFixture{
		"wp_login_bruteforce": {check: "wp_login_bruteforce", n: 20, line: func(ip string, i int) string {
			return domlogTestLine(ip, i, "POST", "/wp-login.php", 200, "Mozilla/5.0")
		}},
		"xmlrpc_abuse": {check: "xmlrpc_abuse", cfg: func(c *config.Config) { c.Thresholds.XMLRPCThreshold = 3 }, n: 3, line: func(ip string, i int) string {
			return domlogTestLine(ip, i, "POST", "/xmlrpc.php", 200, "Mozilla/5.0")
		}},
		"wp_user_enumeration": {check: "wp_user_enumeration", n: 5, line: func(ip string, i int) string {
			return domlogTestLine(ip, i, "GET", fmt.Sprintf("/?author=%d", i), 200, "Mozilla/5.0")
		}},
		"http_request_flood": {check: "http_request_flood", cfg: func(c *config.Config) { c.Thresholds.HTTPFloodThreshold = 20 }, n: 20, line: func(ip string, i int) string {
			return domlogTestLine(ip, i, "GET", fmt.Sprintf("/page-%d", i), 200, "Mozilla/5.0")
		}},
		"http_scanner_profile": {check: "http_scanner_profile", cfg: func(c *config.Config) {
			c.Thresholds.HTTPScannerMinRequests, c.Thresholds.HTTPScannerErrorPct, c.Thresholds.HTTPScannerMinDistinctPaths = 10, 80, 5
		}, n: 12, line: func(ip string, i int) string {
			return domlogTestLine(ip, i, "GET", fmt.Sprintf("/probe-%d", i), 404, "Mozilla/5.0")
		}},
		"http_claimed_bot_unverified": {check: "http_claimed_bot_unverified", cfg: func(c *config.Config) { c.Thresholds.HTTPFloodThreshold = 20 },
			bot: pendingVerifyClassifier{}, n: 20, line: ua("Googlebot/2.1 fake")},
		"http_ua_spoof/known scanner":     {check: "http_ua_spoof", cfg: spoof, n: 2, line: ua("sqlmap/1.7")},
		"http_ua_spoof/claimed negative":  {check: "http_ua_spoof", cfg: spoof, bot: negativeVerifyClassifier{}, n: 3, line: ua("Googlebot/2.1 fake")},
		"http_ua_spoof/pingback":          {check: "http_ua_spoof", cfg: spoof, n: 3, line: ua("WordPress/6.4; https://example.test")},
		"http_ua_spoof/scripting":         {check: "http_ua_spoof", cfg: spoof, n: 3, line: ua("curl/8.0")},
		"http_ua_spoof/headless":          {check: "http_ua_spoof", cfg: spoof, n: 3, line: ua("HeadlessChrome/120")},
		"http_ua_spoof/empty user agent":  {check: "http_ua_spoof", cfg: spoof, n: 3, line: ua("-")},
		"http_ua_spoof/forwarded browser": {check: "http_ua_spoof", cfg: spoof, n: 3, line: ua("python-requests/2.31")},
	}
}

// Every per-address check and User-Agent category: direct records read as
// the HTTP peer and mint; all-forwarded and mixed counts keep the newest
// record but no kind. Aggregate findings stay unstamped.
func TestDomlogScanForwardedCountsHaveNoKind(t *testing.T) {
	const ip = "203.0.113.65"
	for name, fx := range domlogFixtures() {
		for _, variant := range []string{"direct", "forwarded", "mixed"} {
			t.Run(name+"/"+variant, func(t *testing.T) {
				cfg := &config.Config{}
				cfg.WebServer.TrustedProxies = []string{domlogProxy}
				if fx.cfg != nil {
					fx.cfg(cfg)
				}
				bot := fx.bot
				if bot == nil {
					bot = nopBotClassifier{}
				}
				var lines []string
				for i := 0; i < fx.n; i++ {
					line := fx.line(ip, i)
					if variant == "forwarded" || variant == "mixed" && i == 0 {
						line = forwardedVia(line, ip)
					}
					lines = append(lines, line)
				}
				path, findings := scanDomlogFile(t, cfg, bot, lines)
				var got []alert.Finding
				for _, f := range findings {
					switch {
					case f.Check == fx.check && f.SourceIP == ip:
						got = append(got, f)
					case f.Check == "http_asn_crawl" || f.Check == "http_distributed_flood":
						if f.Observation != (alert.Observation{}) {
							t.Fatalf("aggregate %s named %+v", f.Check, f.Observation)
						}
					}
				}
				if len(got) != 1 {
					t.Fatalf("%s findings %+v, want one for %s", fx.check, findings, ip)
				}
				wantScanObservation(t, got[0], ProducerDomlogScan, lineRef(t, path, lines, fx.n-1), domlogTestTime(fx.n-1))
				if variant == "direct" {
					wantPeerMints(t, got[0])
				} else {
					wantNoKind(t, got[0])
				}
			})
		}
	}
}

// A forwarded legacy POST counts toward the threshold even without a usable
// time; dropping its time must not drop its forwarded mark. Forwarded
// traffic of an unrelated check leaves a direct-only count its kind.
func TestDomlogScanForwardedMarkSurvivesTimeAndStaysPerCheck(t *testing.T) {
	const ip = "203.0.113.66"
	post := func(uri, stamp string) string {
		return forwardedVia(fmt.Sprintf(`%s - - [%s +0000] "POST %s HTTP/1.1" 200 100 "-" "Mozilla/5.0"`, ip, stamp, uri), ip)
	}
	for _, tc := range []struct {
		name, check, uri string
		n                int
		cfg              func(*config.Config)
	}{
		{"wp-login untimed", "wp_login_bruteforce", "/wp-login.php", 20, nil},
		{"wp-login future", "wp_login_bruteforce", "/wp-login.php", 20, nil},
		{"xmlrpc untimed", "xmlrpc_abuse", "/xmlrpc.php", 3, func(c *config.Config) { c.Thresholds.XMLRPCThreshold = 3 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.WebServer.TrustedProxies = []string{domlogProxy}
			if tc.cfg != nil {
				tc.cfg(cfg)
			}
			var lines []string
			for i := 0; i < tc.n-1; i++ {
				lines = append(lines, domlogTestLine(ip, i, "POST", tc.uri, 200, "Mozilla/5.0"))
			}
			stamp := "09/Nov/2026:99:99:99"
			if strings.HasSuffix(tc.name, "future") {
				stamp = "09/Nov/2099:12:00:00"
			}
			lines = append(lines, post(tc.uri, stamp))
			path, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
			f := oneScanFinding(t, findings, tc.check)
			wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, tc.n-2), domlogTestTime(tc.n-2))
			wantNoKind(t, f)
		})
	}
	t.Run("unrelated check", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.WebServer.TrustedProxies = []string{domlogProxy}
		var lines []string
		for i := 0; i < 20; i++ {
			lines = append(lines, domlogTestLine(ip, i, "POST", "/wp-login.php", 200, "Mozilla/5.0"))
		}
		for i := 0; i < 5; i++ {
			lines = append(lines, forwardedVia(domlogTestLine(ip, 30+i, "GET", fmt.Sprintf("/?author=%d", i), 200, "Mozilla/5.0"), ip))
		}
		_, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
		wantPeerMints(t, oneScanFinding(t, findings, "wp_login_bruteforce"))
		wantNoKind(t, oneScanFinding(t, findings, "wp_user_enumeration"))
	})
}

// Each scan's real finding mints through its registered producer, and a
// re-run over unchanged input, after a reader restart where the scan keeps
// one, mints the same evidence and ID for the same target, which admission
// accepts at the record's own time. A finding without an observation or a
// kind keeps its legacy shape and mints nothing.
func TestScanObservationsMintAndRemainStable(t *testing.T) {
	stable := func(t *testing.T, run func() alert.Finding) {
		t.Helper()
		first, again := run(), run()
		a, target, err := mintScanFinding(t, first)
		if err != nil {
			t.Fatalf("mint %+v: %v", first, err)
		}
		b, againTarget, err := mintScanFinding(t, again)
		if err != nil {
			t.Fatalf("re-mint %+v: %v", again, err)
		}
		if !a.Equal(b) || a.ID() != b.ID() || target != againTarget {
			t.Fatalf("unchanged input minted %v then %v", a.ID(), b.ID())
		}
		if _, err := admission.Assess(target, []admission.Evidence{a, b}, a.ObservedAt().Add(time.Minute)); err != nil {
			t.Fatalf("assess at the record's time: %v", err)
		}
	}
	t.Run("cpanel", func(t *testing.T) {
		var access []string
		for i := 0; i < apiFailThreshold; i++ {
			access = append(access, staleSessionAccessLine("203.0.113.9", "-", cpanelStamp(i), "/execute/Themes/list", "401"))
		}
		cpanelScanLog(t, access)
		stable(t, func() alert.Finding {
			return oneScanFinding(t, CheckAPIAuthFailures(context.Background(), &config.Config{}, nil), "api_auth_failure")
		})
	})
	t.Run("modsecurity", func(t *testing.T) {
		denial := modsecIndexLine("example.com", "203.0.113.50", "GET /x HTTP/1.1", "probe", 403)
		setupSerialAuditLog(t, strings.Repeat(denial+"\n", 25))
		stable(t, func() alert.Finding {
			modsecAuditReader.Lock()
			modsecAuditReader.path = ""
			modsecAuditReader.Unlock()
			return oneScanFinding(t, CheckModSecAuditLog(context.Background(), &config.Config{}, nil), "waf_attack_blocked")
		})
	})
	t.Run("domlog", func(t *testing.T) {
		var lines []string
		for i := 0; i < 20; i++ {
			lines = append(lines, domlogTestLine("203.0.113.67", i, "POST", "/wp-login.php", 200, "Mozilla/5.0"))
		}
		path := filepath.Join(t.TempDir(), "example.test")
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		withMockOS(t, &mockOS{open: os.Open})
		stable(t, func() alert.Finding {
			stats := newDomlogStatsAt(domlogScanTime)
			tailDomlogsInto(context.Background(), []string{path}, &config.Config{}, stats, nopBotClassifier{}, 1000)
			return oneScanFinding(t, stats.emit(&config.Config{}), "wp_login_bruteforce")
		})
	})
	t.Run("central", func(t *testing.T) {
		root := t.TempDir()
		central := filepath.Join(root, "central.log")
		now := time.Now().UTC().Truncate(time.Second)
		var lines []string
		for i := 0; i < 20; i++ {
			lines = append(lines, fmt.Sprintf(`203.0.113.68 - - [%s] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`, now.Add(time.Duration(i-30)*time.Second).Format("02/Jan/2006:15:04:05 -0700")))
		}
		if err := os.WriteFile(central, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		platform.ResetForTest()
		platform.SetOverrides(platform.Overrides{AccessLogPaths: []string{central}, DomlogGlobs: []string{filepath.Join(root, "*_log")}})
		t.Cleanup(platform.ResetForTest)
		withMockOS(t, &mockOS{glob: filepath.Glob, stat: os.Stat, open: os.Open})
		stable(t, func() alert.Finding {
			return oneScanFinding(t, CheckWPBruteForce(context.Background(), &config.Config{}, nil), "wp_login_bruteforce")
		})
	})
	t.Run("no observation", func(t *testing.T) {
		var access []string
		for i := 0; i < apiFailThreshold; i++ {
			access = append(access, staleSessionAccessLine("203.0.113.9", "-", "bad", "/execute/Themes/list", "401"))
		}
		cpanelScanLog(t, access)
		f := oneScanFinding(t, CheckAPIAuthFailures(context.Background(), &config.Config{}, nil), "api_auth_failure")
		if f.SourceIP != "203.0.113.9" || f.Severity != alert.High {
			t.Fatalf("legacy finding changed: %+v", f)
		}
		if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseNoObservation {
			t.Fatalf("a finding without an observation minted or refused without the cause: %v", err)
		}
	})
	t.Run("no kind", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.WebServer.TrustedProxies = []string{domlogProxy}
		var lines []string
		for i := 0; i < 20; i++ {
			lines = append(lines, forwardedVia(domlogTestLine("203.0.113.69", i, "POST", "/wp-login.php", 200, "Mozilla/5.0"), "203.0.113.69"))
		}
		_, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
		f := oneScanFinding(t, findings, "wp_login_bruteforce")
		if f.SourceIP != "203.0.113.69" || f.Severity != alert.Critical {
			t.Fatalf("legacy finding changed: %+v", f)
		}
		wantNoKind(t, f)
	})
}

// A windowed domlog finding is minted from its record, so a later scan of
// unchanged logs mints the same evidence even when another vhost's request
// has left the window meanwhile. The vhosts an address touched are not a
// property of the record, so the evidence claims none and stays host-owned.
func TestDomlogRescanKeepsEvidenceAcrossWindowChanges(t *testing.T) {
	const ip = "203.0.113.73"
	dir := t.TempDir()
	write := func(name string, lines []string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var flood []string
	for i := 0; i < 12; i++ {
		flood = append(flood, fmt.Sprintf(`%s - - [09/Nov/2026:12:04:%02d +0000] "GET /page-%d HTTP/1.1" 200 100 "-" "Mozilla/5.0"`, ip, i, i))
	}
	paths := []string{
		write("example.test", flood),
		write("example.org", []string{fmt.Sprintf(`%s - - [09/Nov/2026:12:00:10 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"`, ip)}),
	}
	withMockOS(t, &mockOS{open: os.Open})
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 10
	inv, err := admission.NewInventory(map[string]uint64{"tenanta": 1, "tenantb": 1}, map[string]string{"example.test": "tenanta", "example.org": "tenantb"})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var producer *admission.Producer
	for _, p := range ProducerTable() {
		registered, regErr := reg.Register(p.Spec)
		if regErr != nil {
			t.Fatal(regErr)
		}
		if p.Spec.ID == ProducerDomlogScan {
			producer = registered
		}
	}
	mintAt := func(scan time.Time) admission.Evidence {
		t.Helper()
		stats := newDomlogStatsAt(scan)
		tailDomlogsInto(context.Background(), paths, cfg, stats, nopBotClassifier{}, 1000)
		f := oneScanFinding(t, stats.emit(cfg), "http_request_flood")
		_, in, err := AdmissionEvidence(f)
		if err != nil {
			t.Fatal(err)
		}
		in.Inventory = inv
		e, err := producer.Mint(in)
		if err != nil {
			t.Fatalf("mint at %v: %v", scan, err)
		}
		return e
	}
	early := mintAt(time.Date(2026, 11, 9, 12, 5, 0, 0, time.UTC))
	late := mintAt(time.Date(2026, 11, 9, 12, 5, 30, 0, time.UTC))
	if early.ID() != late.ID() || (!early.Equal(late) && !early.SameExceptFinding(late)) {
		t.Fatalf("a later scan of the same record minted another record under %v: owners %+v then %+v", early.ID(), early.Owner(), late.Owner())
	}
	if !early.Owner().IsHost() || !late.Owner().IsHost() {
		t.Fatalf("owners %+v then %+v, want host-owned evidence", early.Owner(), late.Owner())
	}
}

// A finding observed in the central log claims no vhost, even while the
// address's only in-window vhost request would name one: that request leaves
// the window and the evidence of the unchanged record must not change.
func TestDomlogCentralRecordClaimsNoVhost(t *testing.T) {
	const ip = "203.0.113.74"
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 10
	scanAt := func(scan time.Time) alert.Finding {
		t.Helper()
		stats := newDomlogStatsAt(scan)
		add := func(line string, offset int64, domain string) {
			rec, ok := parseAccessLogRecord(line)
			if !ok {
				t.Fatalf("unparsable fixture %q", line)
			}
			rec.ref = syslogRecord{text: line, offset: offset, stream: alert.FileStream(1, 2)}
			rec.Domain, rec.Central = domain, domain == ""
			stats.scan(rec, cfg, nopBotClassifier{})
		}
		add(fmt.Sprintf(`%s - - [09/Nov/2026:12:00:10 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"`, ip), 0, "example.org")
		for i := 0; i < 12; i++ {
			add(fmt.Sprintf(`%s - - [09/Nov/2026:12:04:%02d +0000] "GET /page-%d HTTP/1.1" 200 100 "-" "Mozilla/5.0"`, ip, i, i), int64(1000+100*i), "")
		}
		return oneScanFinding(t, stats.emit(cfg), "http_request_flood")
	}
	for _, scan := range []time.Time{time.Date(2026, 11, 9, 12, 5, 0, 0, time.UTC), time.Date(2026, 11, 9, 12, 5, 30, 0, time.UTC)} {
		f := scanAt(scan)
		if f.Observation == (alert.Observation{}) || len(f.Claims) != 0 {
			t.Fatalf("scan at %v: observation %+v with claims %+v, want the central record with no claim", scan, f.Observation, f.Claims)
		}
		_, in, err := AdmissionEvidence(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(in.Claims) != 0 {
			t.Fatalf("evidence input claims %+v", in.Claims)
		}
	}
}

// A trusted proxy that sends no usable forwarded header is still a proxy: the
// requests it carries are its clients', so its own address is never read as
// the HTTP peer. The legacy finding stays; admission refuses it.
func TestDomlogScanNeverVouchesForATrustedProxy(t *testing.T) {
	for name, tc := range map[string]struct{ trusted, suffix string }{
		"no header":       {domlogProxy, ""},
		"unusable header": {domlogProxy, ` "not-an-address"`},
		"trusted range":   {"192.0.2.0/24", ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.WebServer.TrustedProxies = []string{tc.trusted}
			var lines []string
			for i := 0; i < 20; i++ {
				lines = append(lines, domlogTestLine(domlogProxy, i, "POST", "/wp-login.php", 200, "Mozilla/5.0")+tc.suffix)
			}
			path, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
			f := oneScanFinding(t, findings, "wp_login_bruteforce")
			if f.SourceIP != domlogProxy {
				t.Fatalf("legacy finding names %s, want the proxy's address", f.SourceIP)
			}
			wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, 19), domlogTestTime(19))
			wantNoKind(t, f)
		})
	}
}
