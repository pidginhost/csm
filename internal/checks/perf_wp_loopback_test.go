package checks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

const (
	wpLoopbackTestUA     = "WordPress/7.0.6; https://example.com"
	wpLoopbackTestTarget = "/wp-admin/admin-ajax.php?action=shop_sync_async"
	wpLoopbackTestHostIP = "203.0.113.10"
)

// wpLoopbackTestNow is 20 minutes into an hour, so the last three complete
// hours are 12:00-15:00 local time.
var (
	wpLoopbackTestZone = time.FixedZone("EEST", 3*3600)
	wpLoopbackTestNow  = time.Date(2026, 9, 1, 15, 20, 0, 0, wpLoopbackTestZone)
)

type wpLoopbackLine struct {
	ip      string
	at      time.Time // request start, the time stamped in the line
	logged  time.Time // when the server wrote it; zero means at
	method  string
	uri     string
	status  int
	referer string
	ua      string
}

func (l wpLoopbackLine) writtenAt() time.Time {
	if l.logged.IsZero() {
		return l.at
	}
	return l.logged
}

func (l wpLoopbackLine) String() string {
	referer := l.referer
	if referer == "" {
		referer = "-"
	}
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d 20 "%s" "%s"`,
		l.ip, l.at.Format("02/Jan/2006:15:04:05 -0700"), l.method, l.uri, l.status, referer, l.ua)
}

// loopbacks returns n self-requests from ip spread evenly across the hour
// starting at hourStart.
func loopbacks(ip string, hourStart time.Time, n int, uri string) []wpLoopbackLine {
	out := make([]wpLoopbackLine, 0, n)
	for i := 0; i < n; i++ {
		at := hourStart.Add(time.Duration(i) * time.Hour / time.Duration(n))
		out = append(out, wpLoopbackLine{ip: ip, at: at, method: "POST", uri: uri, status: 200, ua: wpLoopbackTestUA})
	}
	return out
}

func wpLoopbackHour(h int) time.Time {
	return time.Date(2026, 9, 1, h, 0, 0, 0, wpLoopbackTestZone)
}

// writeWPLoopbackLog writes lines in the order the server logged them and
// returns the log path.
func writeWPLoopbackLog(t *testing.T, dir, name string, lines []wpLoopbackLine) string {
	t.Helper()
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].writtenAt().Before(lines[j].writtenAt()) })
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.String())
		b.WriteByte('\n')
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// withWPLoopbackHostAddress makes 203.0.113.10 one of this server's own
// addresses, the way cPanel hosts reach their own sites over the public IP.
func withWPLoopbackHostAddress(t *testing.T) {
	t.Helper()
	prev := wpLoopbackFromHost
	wpLoopbackFromHost = func(ip string) bool { return ip == "127.0.0.1" || ip == wpLoopbackTestHostIP }
	t.Cleanup(func() { wpLoopbackFromHost = prev })
}

func sustainedLoopbacks(ip string, perHour ...int) []wpLoopbackLine {
	var out []wpLoopbackLine
	for i, n := range perHour {
		out = append(out, loopbacks(ip, wpLoopbackHour(12+i), n, wpLoopbackTestTarget)...)
	}
	return out
}

func scanWPLoopbackForTest(t *testing.T, lines []wpLoopbackLine) []alert.Finding {
	t.Helper()
	withWPLoopbackHostAddress(t)
	path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", lines)
	return scanWPLoopbackLogs(context.Background(), []string{path}, wpLoopbackTestNow)
}

// The common failure: a plugin reschedules its own job for "now" and fires a
// loopback on almost every page view, well over one a minute, all day.
func TestWPLoopbackFlagsSustainedSelfRequests(t *testing.T) {
	lines := sustainedLoopbacks(wpLoopbackTestHostIP, 70, 90, 80)
	// A few of the runs failed, which the finding should surface.
	for i := 0; i < 4; i++ {
		lines[i].status = 500
	}
	// Custom status codes outside 500-599 are not 5xx responses.
	lines[4].status = 600
	lines[5].status = 999

	findings := scanWPLoopbackForTest(t, lines)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1", findings)
	}
	f := findings[0]
	if f.Check != "perf_wp_loopback" || f.Severity != alert.Warning {
		t.Errorf("check/severity = %s/%v, want perf_wp_loopback/Warning", f.Check, f.Severity)
	}
	if want := "Sustained WordPress loopback requests on example.com: POST " + wpLoopbackTestTarget; f.Message != want {
		t.Errorf("message = %q, want %q", f.Message, want)
	}
	for _, want := range []string{"70, 90, 80 per hour", "4 answered with a 5xx error", "User-Agent: " + wpLoopbackTestUA} {
		if !strings.Contains(f.Details, want) {
			t.Errorf("details %q lack %q", f.Details, want)
		}
	}
}

// WordPress's cron spawn and Action Scheduler's admin dispatch hold a 60-second
// lock, so one a minute is the ceiling for normal self-requests. An hour at
// exactly that rate is not over it.
func TestWPLoopbackRequiresMoreThanOnePerMinuteEveryHour(t *testing.T) {
	for _, perHour := range [][]int{{60, 90, 90}, {90, 60, 90}, {90, 90, 60}, {0, 200, 200}} {
		t.Run(fmt.Sprint(perHour), func(t *testing.T) {
			if got := scanWPLoopbackForTest(t, sustainedLoopbacks(wpLoopbackTestHostIP, perHour...)); len(got) != 0 {
				t.Fatalf("findings = %+v, want none", got)
			}
		})
	}
	if got := scanWPLoopbackForTest(t, sustainedLoopbacks(wpLoopbackTestHostIP, 61, 61, 61)); len(got) != 1 {
		t.Fatalf("61 per hour for three hours: findings = %d, want 1", len(got))
	}
}

// The hour in progress is incomplete; it neither completes a streak nor breaks
// one, and lines from the future are not counted in any hour.
func TestWPLoopbackUsesOnlyCompleteHours(t *testing.T) {
	lines := sustainedLoopbacks(wpLoopbackTestHostIP, 50, 90, 90)
	lines = append(lines, loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(15), 90, wpLoopbackTestTarget)...)
	if got := scanWPLoopbackForTest(t, lines); len(got) != 0 {
		t.Fatalf("current hour completed a streak: %+v", got)
	}
}

// A loopback is the server calling itself. The same request shape from any
// other address is another site or a client, not this site's own loop.
func TestWPLoopbackIgnoresRequestsFromOtherAddresses(t *testing.T) {
	if got := scanWPLoopbackForTest(t, sustainedLoopbacks("198.51.100.7", 90, 90, 90)); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

// Requests from the loopback interface count the same as the public address.
func TestWPLoopbackCountsLoopbackInterface(t *testing.T) {
	if got := scanWPLoopbackForTest(t, sustainedLoopbacks("127.0.0.1", 90, 90, 90)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

// Only WordPress's own HTTP API posts count: the host's monitoring, a cache
// preloader or plain GETs from the same address are not loopback jobs.
func TestWPLoopbackIgnoresOtherAgentsAndMethods(t *testing.T) {
	lines := sustainedLoopbacks(wpLoopbackTestHostIP, 90, 90, 90)
	for i := range lines {
		if i%2 == 0 {
			lines[i].ua = "curl/8.9.1"
		} else {
			lines[i].method = "GET"
		}
	}
	if got := scanWPLoopbackForTest(t, lines); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

// Rates are per job: two unrelated actions at 40 an hour each are two normal
// jobs, not one runaway loop.
func TestWPLoopbackCountsEachTargetSeparately(t *testing.T) {
	var lines []wpLoopbackLine
	for h := 12; h < 15; h++ {
		lines = append(lines, loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(h), 40, "/wp-admin/admin-ajax.php?action=first&nonce=a1")...)
		lines = append(lines, loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(h), 40, "/wp-admin/admin-ajax.php?action=second")...)
	}
	if got := scanWPLoopbackForTest(t, lines); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

// The action names the job, whatever else is in the query string, and a
// security plugin that renames admin-ajax.php does not hide it.
func TestWPLoopbackTargetIgnoresNoncesAndKeepsRenamedPaths(t *testing.T) {
	var lines []wpLoopbackLine
	for h := 12; h < 15; h++ {
		for i, l := range loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(h), 70, "") {
			l.uri = fmt.Sprintf("/ajax-call?nonce=%d&action=shop_sync_async", i)
			lines = append(lines, l)
		}
	}

	findings := scanWPLoopbackForTest(t, lines)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1", findings)
	}
	if want := "Sustained WordPress loopback requests on example.com: POST /ajax-call?action=shop_sync_async"; findings[0].Message != want {
		t.Fatalf("message = %q, want %q", findings[0].Message, want)
	}
}

// Any tenant's PHP can post to any site from this server, so the job name is
// shown as logged: percent-encoding is not decoded, and a raw control
// character is shown as '?'.
func TestWPLoopbackTargetStaysPrintable(t *testing.T) {
	cases := map[string]string{
		"/wp-admin/admin-ajax.php?action=sync%0AFAKE%20LINE": "/wp-admin/admin-ajax.php?action=sync%0AFAKE%20LINE",
		"/wp-admin/admin-ajax.php?action=a\x1bb&action=c":    "/wp-admin/admin-ajax.php?action=a?b",
		"/wp-cron.php?doing_wp_cron=1758800000.1234":         "/wp-cron.php",
	}
	for uri, want := range cases {
		lines := sustainedLoopbacks(wpLoopbackTestHostIP, 61, 61, 61)
		for i := range lines {
			lines[i].uri = uri
		}
		got := scanWPLoopbackForTest(t, lines)
		if len(got) != 1 || !strings.HasSuffix(got[0].Message, "POST "+want) {
			t.Errorf("display for %q = %+v, want %q", uri, got, want)
		}
	}
}

// Rates change every run; the finding must stay one finding so the
// Performance page does not fill with copies and a dismissal sticks.
func TestWPLoopbackKeyIsStableAcrossRates(t *testing.T) {
	first := scanWPLoopbackForTest(t, sustainedLoopbacks(wpLoopbackTestHostIP, 70, 70, 70))
	second := scanWPLoopbackForTest(t, sustainedLoopbacks(wpLoopbackTestHostIP, 200, 150, 90))
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("findings = %d and %d, want 1 each", len(first), len(second))
	}
	if first[0].Key() != second[0].Key() {
		t.Fatalf("key changed with the rate: %q -> %q", first[0].Key(), second[0].Key())
	}
}

// Neither older history nor a request stamped a moment before the window is
// counted, even when a busy log contains much more history than current data.
func TestWPLoopbackCountsOnlyTheWindowInALargeLog(t *testing.T) {
	var lines []wpLoopbackLine
	for h := 0; h < 12; h++ {
		lines = append(lines, loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(h), 500, wpLoopbackTestTarget)...)
		lines = append(lines, siteTraffic(wpLoopbackHour(h), 2000, 0)...)
	}
	lines = append(lines, sustainedLoopbacks(wpLoopbackTestHostIP, 61, 62, 63)...)
	lines = append(lines, wpLoopbackLine{ip: wpLoopbackTestHostIP, at: wpLoopbackHour(12).Add(-2 * time.Second),
		method: "POST", uri: wpLoopbackTestTarget, status: 200, ua: wpLoopbackTestUA})

	findings := scanWPLoopbackForTest(t, lines)

	if len(findings) != 1 || !strings.Contains(findings[0].Details, "61, 62, 63 per hour") {
		t.Fatalf("findings = %+v, want one with 61, 62, 63 per hour", findings)
	}
}

// siteTraffic is n visitor requests per hour from hourStart. Requests are
// stamped when they start but logged when they finish, so with a lag two in
// three are written lag after their stamp, among later lines.
func siteTraffic(hourStart time.Time, n int, lag time.Duration) []wpLoopbackLine {
	out := make([]wpLoopbackLine, 0, n)
	for i := 0; i < n; i++ {
		at := hourStart.Add(time.Duration(i) * time.Hour / time.Duration(n))
		l := wpLoopbackLine{ip: "198.51.100.7", at: at, method: "GET", uri: "/", status: 200, ua: "Mozilla/5.0"}
		if lag > 0 && i%3 != 0 {
			l.logged = at.Add(lag)
		}
		out = append(out, l)
	}
	return out
}

// Slow requests are written well after the time stamped in them, so a line
// can be much older than its neighbours. The window must include all records
// even when their start timestamps are interleaved.
func TestWPLoopbackToleratesSlowRequestsInTheLog(t *testing.T) {
	var lines []wpLoopbackLine
	for h := 8; h < 16; h++ {
		lines = append(lines, siteTraffic(wpLoopbackHour(h), 3000, 25*time.Minute)...)
	}
	lines = append(lines, sustainedLoopbacks(wpLoopbackTestHostIP, 61, 62, 63)...)

	findings := scanWPLoopbackForTest(t, lines)

	if len(findings) != 1 || !strings.Contains(findings[0].Details, "61, 62, 63 per hour") {
		t.Fatalf("findings = %+v, want one with 61, 62, 63 per hour", findings)
	}
}

// The substring prefilter is only a shortcut: the parsed request must itself
// be a POST sent by WordPress. A client can put either token in its Referer.
func TestWPLoopbackMatchesTheParsedRequestNotTheRawLine(t *testing.T) {
	variants := map[string]func(*wpLoopbackLine){
		"other agent, WordPress referer": func(l *wpLoopbackLine) { l.ua, l.referer = "curl/8.9.1", wpLoopbackTestUA },
		"GET with a POST referer":        func(l *wpLoopbackLine) { l.method, l.referer = "GET", "POST /" },
	}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			lines := sustainedLoopbacks(wpLoopbackTestHostIP, 90, 90, 90)
			for i := range lines {
				mutate(&lines[i])
			}
			if got := scanWPLoopbackForTest(t, lines); len(got) != 0 {
				t.Fatalf("findings = %+v, want none", got)
			}
		})
	}
}

// A line longer than any real log line is not trusted as a record, and the
// lines after it are still read.
func TestWPLoopbackSkipsOverlongLines(t *testing.T) {
	lines := sustainedLoopbacks(wpLoopbackTestHostIP, 60, 60, 60)
	for h := 12; h < 15; h++ {
		lines = append(lines, wpLoopbackLine{ip: wpLoopbackTestHostIP, at: wpLoopbackHour(h).Add(30 * time.Minute),
			method: "POST", uri: wpLoopbackTestTarget, status: 200,
			referer: strings.Repeat("r", wpLoopbackMaxLineBytes), ua: wpLoopbackTestUA})
	}
	if got := scanWPLoopbackForTest(t, lines); len(got) != 0 {
		t.Fatalf("overlong lines were counted: %+v", got)
	}
	lines = append(lines, sustainedLoopbacks(wpLoopbackTestHostIP, 1, 1, 1)...)
	if got := scanWPLoopbackForTest(t, lines); len(got) != 1 {
		t.Fatalf("lines after an overlong line were lost: findings = %d, want 1", len(got))
	}
}

// Finding the window requires streaming the old prefix: completion order does
// not justify skipping any unexamined chunk based on its start timestamps.
func TestWPLoopbackCountsWindowAfterLargeOldPrefix(t *testing.T) {
	var lines []wpLoopbackLine
	for h := 0; h < 16; h++ {
		lines = append(lines, siteTraffic(wpLoopbackHour(h), 1500, 0)...)
	}
	lines = append(lines, sustainedLoopbacks(wpLoopbackTestHostIP, 61, 62, 63)...)
	got := scanWPLoopbackForTest(t, lines)
	if len(got) != 1 || !strings.Contains(got[0].Details, "61, 62, 63 per hour") {
		t.Fatalf("findings = %+v, want one with 61, 62, 63 per hour", got)
	}
}

// Long unrelated records must not hide the smaller loopback lines between
// them, including the first records in the window.
func TestWPLoopbackReadsWindowAmongLongLines(t *testing.T) {
	long := "/?q=" + strings.Repeat("a", wpLoopbackMaxLineBytes/2)
	var lines []wpLoopbackLine
	for h := 8; h < 16; h++ {
		for i := 0; i < 40; i++ {
			lines = append(lines, wpLoopbackLine{ip: "198.51.100.7", at: wpLoopbackHour(h).Add(time.Duration(i) * 90 * time.Second),
				method: "GET", uri: long, status: 200, ua: "Mozilla/5.0"})
		}
	}
	lines = append(lines, sustainedLoopbacks(wpLoopbackTestHostIP, 61, 62, 63)...)

	findings := scanWPLoopbackForTest(t, lines)

	if len(findings) != 1 || !strings.Contains(findings[0].Details, "61, 62, 63 per hour") {
		t.Fatalf("findings = %+v, want one with 61, 62, 63 per hour", findings)
	}
}

// Each site's log is judged on its own, and findings come out in a stable
// order.
func TestWPLoopbackReportsEachSite(t *testing.T) {
	withWPLoopbackHostAddress(t)
	dir := t.TempDir()
	b := writeWPLoopbackLog(t, dir, "b.example.net-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 90, 90, 90))
	a := writeWPLoopbackLog(t, dir, "a.example.org-ssl_log", sustainedLoopbacks("127.0.0.1", 90, 90, 90))
	quiet := writeWPLoopbackLog(t, dir, "quiet.example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 10, 10, 10))

	findings := scanWPLoopbackLogs(context.Background(), []string{b, quiet, a}, wpLoopbackTestNow)

	var got []string
	for _, f := range findings {
		got = append(got, strings.SplitN(strings.TrimPrefix(f.Message, "Sustained WordPress loopback requests on "), ":", 2)[0])
	}
	if strings.Join(got, ",") != "a.example.org,b.example.net" {
		t.Fatalf("sites = %v, want [a.example.org b.example.net]", got)
	}
}

// Wiring: the check reads the platform's domlogs and honours the performance
// switch.
func TestCheckWPLoopbackRequestsReadsPlatformDomlogs(t *testing.T) {
	now := time.Now()
	prevNow := wpLoopbackNow
	wpLoopbackNow = func() time.Time { return now }
	t.Cleanup(func() { wpLoopbackNow = prevNow })
	withWPLoopbackHostAddress(t)

	start := now.Truncate(time.Hour).Add(-3 * time.Hour)
	var lines []wpLoopbackLine
	for h := 0; h < 3; h++ {
		lines = append(lines, loopbacks(wpLoopbackTestHostIP, start.Add(time.Duration(h)*time.Hour), 90, wpLoopbackTestTarget)...)
	}
	dir := t.TempDir()
	writeWPLoopbackLog(t, dir, "example.com-ssl_log", lines)
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{filepath.Join(dir, "*-ssl_log")}})
	t.Cleanup(platform.ResetForTest)

	cfg := &config.Config{}
	if got := CheckWPLoopbackRequests(context.Background(), cfg, nil); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	disabled := false
	cfg.Performance.Enabled = &disabled
	if got := CheckWPLoopbackRequests(context.Background(), cfg, nil); len(got) != 0 {
		t.Fatalf("disabled performance checks still reported %d", len(got))
	}
}

// The detector judges complete clock hours, so it runs in both deep tiers at
// most hourly, owns its findings for the latest-findings purge, and is
// classified like the other performance checks.
func TestWPLoopbackIsWiredIntoDeepScans(t *testing.T) {
	for tier, checks := range map[string][]namedCheck{"deep": deepChecks(), "reduced deep": reducedDeepChecks()} {
		found := false
		for _, c := range checks {
			found = found || c.name == "perf_wp_loopback"
		}
		if !found {
			t.Errorf("perf_wp_loopback missing from the %s tier", tier)
		}
	}
	if got := checkThrottleMin["perf_wp_loopback"]; got != 60 {
		t.Errorf("throttle = %d minutes, want 60", got)
	}
	purge := LatestPurgeCheckNamesForTier(TierDeep)
	if !slices.Contains(purge, "perf_wp_loopback") {
		t.Errorf("deep purge names lack perf_wp_loopback: %v", purge)
	}
	info, ok := LookupCheck("perf_wp_loopback")
	if !ok || info.Category != CategoryPerformance {
		t.Errorf("registry entry = %+v, %v; want a performance check", info, ok)
	}
}

// A run cut short by its deadline has not looked at every log. It must say so,
// so the runner keeps the findings it cannot confirm are gone.
func TestWPLoopbackCancelledRunIsIncomplete(t *testing.T) {
	withWPLoopbackHostAddress(t)
	path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 90, 90, 90))
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	cancel()

	if got := scanWPLoopbackLogs(ctx, []string{path}, wpLoopbackTestNow); len(got) != 0 {
		t.Fatalf("cancelled run returned findings: %+v", got)
	}
	if !incomplete.contains("perf_wp_loopback") {
		t.Fatal("cancelled run must mark perf_wp_loopback incomplete")
	}
}

// A whole batch of slow requests can finish after the window begins. Even
// the newest start timestamp in that batch predates an earlier window line.
func TestWPLoopbackDelayedBatchDoesNotHideWindow(t *testing.T) {
	lines := sustainedLoopbacks(wpLoopbackTestHostIP, 61, 62, 63)
	for i := 0; i < 4000; i++ {
		lines = append(lines, wpLoopbackLine{
			ip: "198.51.100.7", at: wpLoopbackHour(11),
			logged: wpLoopbackHour(12).Add(30 * time.Second),
			method: "GET", uri: "/slow", status: 200, ua: "Mozilla/5.0",
		})
	}
	got := scanWPLoopbackForTest(t, lines)
	if len(got) != 1 || !strings.Contains(got[0].Details, "61, 62, 63 per hour") {
		t.Fatalf("delayed batch hid window requests: %+v", got)
	}
}

func TestWPLoopbackKeepsFullTargetIdentity(t *testing.T) {
	for name, prefix := range map[string]string{
		"display limit": "/ajax?action=" + strings.Repeat("a", 256),
		"parser limit":  "/ajax?action=" + strings.Repeat("a", 4096),
		"controls":      "/ajax?action=",
	} {
		t.Run(name, func(t *testing.T) {
			var lines []wpLoopbackLine
			for h := 12; h < 15; h++ {
				for _, suffix := range []string{"\x1b", "\x7f"} {
					lines = append(lines, loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(h), 40, prefix+suffix)...)
				}
			}
			if got := scanWPLoopbackForTest(t, lines); len(got) != 0 {
				t.Fatalf("distinct jobs combined into a warning: %+v", got)
			}
			lines = nil
			for h := 12; h < 15; h++ {
				for _, suffix := range []string{"\x1b", "\x7f"} {
					lines = append(lines, loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(h), 61, prefix+suffix)...)
				}
			}
			got := scanWPLoopbackForTest(t, lines)
			if len(got) != 2 || got[0].Key() == got[1].Key() {
				t.Fatalf("distinct sustained jobs need distinct findings: %+v", got)
			}
			for _, finding := range got {
				if strings.ContainsFunc(finding.Message, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
					t.Errorf("unsafe display: %q", finding.Message)
				}
			}
		})
	}
}

func TestWPLoopbackReadFailuresAreIncomplete(t *testing.T) {
	for _, failure := range []string{"open", "stat", "read"} {
		t.Run(failure, func(t *testing.T) {
			path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 90, 90, 90))
			withMockOS(t, &mockOS{open: func(string) (*os.File, error) {
				if failure == "open" {
					return nil, os.ErrPermission
				}
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err == nil && failure == "stat" {
					err = file.Close()
				}
				return file, err
			}})
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			if got := scanWPLoopbackLogs(ctx, []string{path}, wpLoopbackTestNow); len(got) != 0 {
				t.Fatalf("unreadable log produced findings: %+v", got)
			}
			if !incomplete.contains("perf_wp_loopback") {
				t.Fatal("unreadable log must preserve prior findings")
			}
		})
	}
}

func TestCheckWPLoopbackDiscoveryFailuresAreIncomplete(t *testing.T) {
	for _, failure := range []string{"glob", "stat"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			path := writeWPLoopbackLog(t, dir, "example.com-ssl_log", nil)
			platform.ResetForTest()
			platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{filepath.Join(dir, "*-ssl_log")}})
			t.Cleanup(platform.ResetForTest)
			withMockOS(t, &mockOS{
				glob: func(string) ([]string, error) {
					if failure == "glob" {
						return nil, os.ErrPermission
					}
					return []string{path}, nil
				},
				stat: func(string) (os.FileInfo, error) { return nil, os.ErrPermission },
			})
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			CheckWPLoopbackRequests(ctx, &config.Config{}, nil)
			if !incomplete.contains("perf_wp_loopback") {
				t.Fatal("failed log discovery must preserve prior findings")
			}
		})
	}
}

func TestWPLoopbackUsesLocalCompleteHours(t *testing.T) {
	for _, offset := range []int{5*3600 + 30*60, 5*3600 + 45*60, -3*3600 - 30*60} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			withWPLoopbackHostAddress(t)
			zone := time.FixedZone("test", offset)
			now := time.Date(2026, 9, 1, 15, 20, 0, 0, zone)
			var lines []wpLoopbackLine
			for h := 12; h < 15; h++ {
				at := time.Date(2026, 9, 1, h, 0, 0, 0, zone)
				lines = append(lines, loopbacks(wpLoopbackTestHostIP, at, 61, wpLoopbackTestTarget)...)
			}
			path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", lines)
			got := scanWPLoopbackLogs(context.Background(), []string{path}, now)
			if len(got) != 1 || !strings.Contains(got[0].Details, "61, 61, 61 per hour") {
				t.Fatalf("incomplete local hours counted: %+v", got)
			}
		})
	}
}

func TestWPLoopbackBoundsDistinctJobs(t *testing.T) {
	withWPLoopbackHostAddress(t)
	lines := loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(12), 10000, "")
	for i := range lines {
		lines[i].uri = fmt.Sprintf("/ajax?action=job%d", i)
	}
	path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", lines)
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings, st := scanWPLoopbackLogsState(ctx, []string{path}, wpLoopbackTestNow, nil)
	if len(findings) != 0 || st[path] != nil || !incomplete.contains("perf_wp_loopback") {
		t.Fatalf("unbounded jobs: findings = %d, retained state = %v, incomplete = %v",
			len(findings), st[path] != nil, incomplete.contains("perf_wp_loopback"))
	}
}

func TestWPLoopbackTruncatedReadIsIncomplete(t *testing.T) {
	path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 1000, 1000, 1000))
	previous := wpLoopbackFromHost
	wpLoopbackFromHost = func(string) bool {
		if err := os.Truncate(path, 0); err != nil {
			t.Fatal(err)
		}
		return true
	}
	t.Cleanup(func() { wpLoopbackFromHost = previous })
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	if got := scanWPLoopbackLogs(ctx, []string{path}, wpLoopbackTestNow); len(got) != 0 {
		t.Fatalf("partial log produced findings: %+v", got)
	}
	if !incomplete.contains("perf_wp_loopback") {
		t.Fatal("truncated log must preserve prior findings")
	}
}

type cancelDomlogReader struct {
	cancel context.CancelFunc
	reads  int
}

func (r *cancelDomlogReader) Read(p []byte) (int, error) {
	r.reads++
	for i := range p {
		p[i] = 'x'
	}
	if r.reads == 2 {
		r.cancel()
	}
	if r.reads > 10 {
		return 0, io.EOF
	}
	return len(p), nil
}

func TestWPLoopbackCancelsInsideOverlongLine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &cancelDomlogReader{cancel: cancel}
	line, _, err := readDomlogLine(ctx, bufio.NewReaderSize(source, wpLoopbackMaxLineBytes))
	if err != context.Canceled || line != nil || source.reads != 2 {
		t.Fatalf("line length = %d, error = %v, reads = %d; want cancellation after 2 reads", len(line), err, source.reads)
	}
}

// appendWPLoopbackLog appends lines, in logged order, to an existing log.
func appendWPLoopbackLog(t *testing.T, path string, lines []wpLoopbackLine) {
	t.Helper()
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].writtenAt().Before(lines[j].writtenAt()) })
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := f.WriteString(l.String() + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// Each hourly run reads only what was appended since the last one; the hours
// it read before are carried in state. A busy host's logs are gigabytes, so
// re-reading them every hour is not an option.
func TestWPLoopbackStateReadsOnlyAppendedBytes(t *testing.T) {
	withWPLoopbackHostAddress(t)
	path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 61, 62, 63))
	findings, st := scanWPLoopbackLogsState(context.Background(), []string{path}, wpLoopbackTestNow, nil)
	if len(findings) != 1 || !strings.Contains(findings[0].Details, "61, 62, 63 per hour") {
		t.Fatalf("first run = %+v", findings)
	}

	// Rewrite already-read requests in place to another job, same length. A
	// run that re-read them would see a second job and lose counts.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	head, anchor := 512, len(data)-512
	rewritten := string(data[:head]) +
		strings.ReplaceAll(string(data[head:anchor]), "shop_sync_async", "shop_sync_asynX") +
		string(data[anchor:])
	if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}
	appendWPLoopbackLog(t, path, loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(15), 64, wpLoopbackTestTarget))

	findings, _ = scanWPLoopbackLogsState(context.Background(), []string{path}, wpLoopbackTestNow.Add(time.Hour), st)
	if len(findings) != 1 || !strings.Contains(findings[0].Details, "62, 63, 64 per hour") {
		t.Fatalf("second run = %+v, want one finding with 62, 63, 64 per hour", findings)
	}
}

// Rotation or truncation starts a new file; reading resumes at its start and
// the hours already counted are kept.
func TestWPLoopbackStateRestartsAfterTruncation(t *testing.T) {
	withWPLoopbackHostAddress(t)
	path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 61, 62, 63))
	_, st := scanWPLoopbackLogsState(context.Background(), []string{path}, wpLoopbackTestNow, nil)

	writeWPLoopbackLog(t, filepath.Dir(path), filepath.Base(path), loopbacks(wpLoopbackTestHostIP, wpLoopbackHour(15), 64, wpLoopbackTestTarget))

	findings, _ := scanWPLoopbackLogsState(context.Background(), []string{path}, wpLoopbackTestNow.Add(time.Hour), st)
	if len(findings) != 1 || !strings.Contains(findings[0].Details, "62, 63, 64 per hour") {
		t.Fatalf("after truncation = %+v, want one finding with 62, 63, 64 per hour", findings)
	}
}

// A line still being written when a run reads the log is left for the next
// run and counted once, when complete.
func TestWPLoopbackStateLeavesPartialLineForNextRun(t *testing.T) {
	withWPLoopbackHostAddress(t)
	path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 61, 61, 60))
	last := wpLoopbackLine{ip: wpLoopbackTestHostIP, at: wpLoopbackHour(14).Add(59 * time.Minute), method: "POST",
		uri: wpLoopbackTestTarget, status: 200, ua: wpLoopbackTestUA}.String()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(last[:40]); err != nil {
		t.Fatal(err)
	}
	findings, st := scanWPLoopbackLogsState(context.Background(), []string{path}, wpLoopbackTestNow, nil)
	if len(findings) != 0 {
		t.Fatalf("partial line counted: %+v", findings)
	}
	if _, err := f.WriteString(last[40:] + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	findings, _ = scanWPLoopbackLogsState(context.Background(), []string{path}, wpLoopbackTestNow.Add(5*time.Minute), st)
	if len(findings) != 1 || !strings.Contains(findings[0].Details, "61, 61, 61 per hour") {
		t.Fatalf("completed line = %+v, want one finding with 61, 61, 61 per hour", findings)
	}
}

// State covers the logs active in the window; a log that went quiet is
// forgotten, and hours that fell out of the window are pruned.
func TestWPLoopbackStateForgetsQuietLogsAndOldHours(t *testing.T) {
	withWPLoopbackHostAddress(t)
	dir := t.TempDir()
	active := writeWPLoopbackLog(t, dir, "a.example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 61, 61, 61))
	quiet := writeWPLoopbackLog(t, dir, "b.example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 61, 61, 61))
	_, st := scanWPLoopbackLogsState(context.Background(), []string{active, quiet}, wpLoopbackTestNow, nil)

	_, st = scanWPLoopbackLogsState(context.Background(), []string{active}, wpLoopbackTestNow.Add(2*time.Hour), st)

	if _, ok := st[quiet]; ok {
		t.Fatal("state kept a log that was not active")
	}
	for _, job := range st[active].Jobs {
		for hour := range job.Hours {
			if hour < wpLoopbackHour(14).Unix() {
				t.Fatalf("state kept hour %d from before the window", hour)
			}
		}
	}
}

// A log that could not be read keeps its previous position and counts, so
// the next successful run neither loses nor double counts its requests.
func TestWPLoopbackStateKeepsLogOnReadFailure(t *testing.T) {
	withWPLoopbackHostAddress(t)
	path := writeWPLoopbackLog(t, t.TempDir(), "example.com-ssl_log", sustainedLoopbacks(wpLoopbackTestHostIP, 61, 62, 63))
	_, st := scanWPLoopbackLogsState(context.Background(), []string{path}, wpLoopbackTestNow, nil)
	before := st[path]

	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return nil, os.ErrPermission }})
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	_, after := scanWPLoopbackLogsState(ctx, []string{path}, wpLoopbackTestNow.Add(time.Hour), st)

	if !incomplete.contains("perf_wp_loopback") {
		t.Fatal("read failure must mark the check incomplete")
	}
	if after[path] != before {
		t.Fatal("read failure replaced the log's saved state")
	}
}

// The daemon path persists state between runs in the scan state store.
func TestCheckWPLoopbackRequestsPersistsState(t *testing.T) {
	now := time.Now()
	prevNow := wpLoopbackNow
	wpLoopbackNow = func() time.Time { return now }
	t.Cleanup(func() { wpLoopbackNow = prevNow })
	withWPLoopbackHostAddress(t)

	start := wpLoopbackWindowEnd(now).Add(-3 * time.Hour)
	var lines []wpLoopbackLine
	for h := 0; h < 3; h++ {
		lines = append(lines, loopbacks(wpLoopbackTestHostIP, start.Add(time.Duration(h)*time.Hour), 90, wpLoopbackTestTarget)...)
	}
	dir := t.TempDir()
	path := writeWPLoopbackLog(t, dir, "example.com-ssl_log", lines)
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{filepath.Join(dir, "*-ssl_log")}})
	t.Cleanup(platform.ResetForTest)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if got := CheckWPLoopbackRequests(context.Background(), &config.Config{}, store); len(got) != 1 {
		t.Fatalf("first run findings = %d, want 1", len(got))
	}
	// Emptying the already-read part of the file in place would change what a
	// full re-read sees; the second run must still report from saved state.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if got := CheckWPLoopbackRequests(context.Background(), &config.Config{}, store); len(got) != 1 {
		t.Fatalf("second run findings = %d, want 1 from saved state", len(got))
	}
}

// Logs that discovery failed to list were not read, not gone: their saved
// position and counts survive the run.
func TestCheckWPLoopbackKeepsStateWhenDiscoveryFails(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	saved := wpLoopbackState{"/var/log/example.com-ssl_log": {Follow: followState{Offset: 42}}}
	storeWPLoopbackState(store, saved)

	dir := t.TempDir()
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{filepath.Join(dir, "*-ssl_log")}})
	t.Cleanup(platform.ResetForTest)
	withMockOS(t, &mockOS{glob: func(string) ([]string, error) { return nil, os.ErrPermission }})

	CheckWPLoopbackRequests(context.Background(), &config.Config{}, store)

	got := loadWPLoopbackState(store)["/var/log/example.com-ssl_log"]
	if got == nil || got.Follow.Offset != 42 {
		t.Fatalf("saved state after failed discovery = %+v, want offset 42 kept", got)
	}
}
