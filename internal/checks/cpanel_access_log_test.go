package checks

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestCpanelAccessRecordProxyIdent(t *testing.T) {
	for _, ip := range []string{"192.0.2.66", "2001:db8::66"} {
		for _, user := range []string{"-", `user name " [11/10/2026:09:00:00 -0000] "fake`} {
			line := ip + ` proxy ` + user + ` [11/09/2026:12:00:00 -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "agent" "-" "198.51.100.7" 2087`
			got, ok := ParseCpanelAccessRecord(line)
			if !ok || got.IP != ip || !got.Proxy || !hasCpanelRequest(got, "GET", "/scripts2/listaccts") || got.Port != "2087" {
				t.Fatalf("proxy record lost or changed: %+v (%v)", got, ok)
			}
			if !got.At.IsZero() {
				t.Fatalf("proxy record supplied an observation time: %v", got.At)
			}
		}
	}
}

func TestCpanelProxyRequestsCannotExplainDirectFailures(t *testing.T) {
	line := `192.0.2.66 proxy alice [11/09/2026:12:00:00 -0000] "GET /cpsess123/execute/Themes/list HTTP/1.1" 401 0 "-" "agent" "s" "198.51.100.7" 2083`
	if got, ok := ParseStaleSessionRequest(line); ok {
		t.Fatalf("proxy record can explain direct failures: %+v", got)
	}
}

func TestCpanelProxyScansDoNotSupplyPeerEvidence(t *testing.T) {
	for _, tc := range []struct {
		check     string
		request   string
		port      string
		threshold int
		run       func() []alert.Finding
	}{
		{"api_auth_failure", "GET /execute/Themes/list", "2083", apiFailThreshold, func() []alert.Finding {
			return CheckAPIAuthFailures(context.Background(), &config.Config{}, nil)
		}},
		{"webmail_bruteforce", "POST /login/", "2096", webmailThreshold, func() []alert.Finding {
			return CheckWebmailLogins(context.Background(), &config.Config{}, nil)
		}},
	} {
		t.Run(tc.check, func(t *testing.T) {
			for _, stamp := range []string{"11/09/2026:12:00:00 -0000", "bad -0000", "12/31/2099:00:00:00 -0000"} {
				for _, direct := range []bool{false, true} {
					line := `192.0.2.66 proxy - [` + stamp + `] "` + tc.request + ` HTTP/1.1" 401 0 "-" "agent" "-" "198.51.100.7" ` + tc.port
					lines := make([]string, tc.threshold)
					for i := range lines {
						lines[i] = line
					}
					if direct {
						lines = append(lines, `192.0.2.66 - - [11/09/2026:12:00:01 -0000] "`+tc.request+` HTTP/1.1" 401 0 "-" "agent" "-" "-" `+tc.port)
					}
					cpanelScanLog(t, lines)
					got := tc.run()
					if len(got) != 1 || got[0].Check != tc.check || got[0].Attribution != admission.AttributionUnknown {
						t.Fatalf("proxy count lost or promoted to peer evidence (stamp %q, direct %v): %+v", stamp, direct, got)
					}
					if got[0].SourceIP != "" || !strings.Contains(got[0].Details, "192.0.2.66") || extractIPFromFinding(got[0]) != "" {
						t.Fatalf("unverified address escaped the finding details: %+v", got[0])
					}
					if got[0].Observation != (alert.Observation{}) {
						t.Fatalf("proxy count dated a scan observation: %+v", got[0].Observation)
					}
					if !strings.HasSuffix(got[0].Message, ": "+strconv.Itoa(tc.threshold)+" attempts") {
						t.Fatalf("direct requests changed the proxy count: %s", got[0].Message)
					}
					if _, _, err := AdmissionEvidence(got[0]); err == nil {
						t.Fatal("proxy count authorized an IP response")
					}
				}
			}
		})
	}
}

func TestCpanelProxyScansCannotBlockOrScoreLoggedAddress(t *testing.T) {
	withTestThreatStore(t)
	blocker := &recordingIPBlocker{}
	oldBlocker := getIPBlocker()
	SetIPBlocker(blocker)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockCpanelLogins = true
	setAutoResponseLive(cfg)
	var lines []string
	for range apiFailThreshold {
		lines = append(lines, `192.0.2.66 proxy - [11/09/2026:12:00:00 -0000] "GET /execute/Themes/list HTTP/1.1" 401 0 "-" "agent" "-" "198.51.100.7" 2083`)
	}
	cpanelScanLog(t, lines)
	findings := CheckAPIAuthFailures(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("proxy requests produced %d findings, want one", len(findings))
	}
	if actions := AutoBlockIPs(cfg, findings); len(actions) != 0 || len(blocker.blocked) != 0 {
		t.Fatalf("proxy requests authorized blocks: actions %+v, blocked %v", actions, blocker.blocked)
	}
	db := attackdb.NewForTest(nil)
	db.RecordFinding(findings[0])
	if got := db.LookupIP("192.0.2.66"); got != nil {
		t.Fatalf("proxy requests created an address history: %+v", got)
	}
}

func TestCpanelProxyScansCannotDowngradeDirectCounts(t *testing.T) {
	for _, tc := range []struct {
		check     string
		request   string
		port      string
		threshold int
		run       func() []alert.Finding
	}{
		{"api_auth_failure", "GET /execute/Themes/list", "2083", apiFailThreshold, func() []alert.Finding {
			return CheckAPIAuthFailures(context.Background(), &config.Config{}, nil)
		}},
		{"webmail_bruteforce", "POST /login/", "2096", webmailThreshold, func() []alert.Finding {
			return CheckWebmailLogins(context.Background(), &config.Config{}, nil)
		}},
	} {
		t.Run(tc.check, func(t *testing.T) {
			line := `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "` + tc.request + ` HTTP/1.1" 401 0 "-" "agent" "-" "-" ` + tc.port
			lines := make([]string, tc.threshold)
			for i := range lines {
				lines[i] = line
			}
			lines = append(lines, strings.Replace(line, " - - [", " proxy - [", 1))
			cpanelScanLog(t, lines)
			got := tc.run()
			if len(got) != 1 || got[0].Check != tc.check || got[0].SourceIP != "192.0.2.66" || got[0].Attribution != admission.AttributionPeer {
				t.Fatalf("proxy request downgraded direct evidence: %+v", got)
			}
			if !strings.HasSuffix(got[0].Message, ": "+strconv.Itoa(tc.threshold)+" attempts") {
				t.Fatalf("proxy request changed the direct count: %s", got[0].Message)
			}
		})
	}
}

func TestCpanelProxyScansDoNotTrustAddressExemptions(t *testing.T) {
	for _, tc := range []struct {
		check, request, port, status string
		count                        int
		run                          func(context.Context, *config.Config, *state.Store) []alert.Finding
	}{
		{"api_auth_failure", "GET /execute/Themes/list", "2083", "401", apiFailThreshold, CheckAPIAuthFailures},
		{"webmail_bruteforce", "POST /login/", "2096", "401", webmailThreshold, CheckWebmailLogins},
		{"cpanel_file_upload", "POST /fileman/upload_files", "2083", "200", 1, CheckCpanelFileManager},
		{"whm_password_change", "POST /json-api/passwd", "2087", "200", 1, CheckWHMAccess},
		{"whm_account_action", "POST /json-api/createacct", "2087", "200", 1, CheckWHMAccess},
	} {
		t.Run(tc.check, func(t *testing.T) {
			line := `192.0.2.66 proxy - [11/09/2026:12:00:00 -0000] "` + tc.request + ` HTTP/1.1" ` + tc.status + ` 0 "-" "agent" "-" "198.51.100.7" ` + tc.port
			lines := make([]string, tc.count)
			for i := range lines {
				lines[i] = line
			}
			cpanelScanLog(t, lines)
			got := tc.run(context.Background(), &config.Config{InfraIPs: []string{"192.0.2.66"}}, nil)
			if len(got) != 1 || got[0].Check != tc.check || got[0].SourceIP != "" || got[0].Attribution != admission.AttributionUnknown {
				t.Fatalf("unverified proxy address hid an alert or supplied evidence: %+v", got)
			}
			if strings.Contains(got[0].Message, "192.0.2.66") || !strings.Contains(got[0].Details, "192.0.2.66") {
				t.Fatalf("unverified address escaped the finding details: %+v", got[0])
			}
		})
	}
}

func TestCpanelAccessRecordLongMethod(t *testing.T) {
	method := strings.Repeat("M", 64)
	for _, raw := range []string{method, strings.Repeat(`\x4d`, 64)} {
		line := `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "` + raw + ` /execute/Themes/list HTTP/1.1" 401 0 "-" "agent" "-" "-" 2083`
		got, ok := ParseCpanelAccessRecord(line)
		if !ok || !hasCpanelRequest(got, method, "/execute/Themes/list") || got.Status != "401" || got.Port != "2083" ||
			!got.At.Equal(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)) {
			t.Fatalf("valid long method lost its request: %+v (%v)", got, ok)
		}
		var lines []string
		for range apiFailThreshold {
			lines = append(lines, line)
		}
		cpanelScanLog(t, lines)
		findings := CheckAPIAuthFailures(context.Background(), &config.Config{}, nil)
		if len(findings) != 1 || findings[0].Check != "api_auth_failure" || findings[0].SourceIP != "192.0.2.66" {
			t.Fatalf("valid long methods hid API failures: %+v", findings)
		}
	}
	for _, invalid := range []string{method + "(", method + `\x00`, method + `\x20`} {
		line := `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "` + invalid + ` /execute/Themes/list HTTP/1.1" 401 0 "-" "agent" "-" "-" 2083`
		if got, ok := ParseCpanelAccessRecord(line); ok || got != (CpanelAccessRecord{}) {
			t.Fatalf("invalid bytes after a long method were ignored: %+v (%v)", got, ok)
		}
	}
}

func TestCpanelScansCountUndatedForgedUserRecords(t *testing.T) {
	for _, tc := range []struct {
		check     string
		request   string
		port      string
		threshold int
		run       func() []alert.Finding
	}{
		{"api_auth_failure", "GET /execute/Themes/list", "2083", apiFailThreshold, func() []alert.Finding {
			return CheckAPIAuthFailures(context.Background(), &config.Config{}, nil)
		}},
		{"webmail_bruteforce", "POST /login/", "2096", webmailThreshold, func() []alert.Finding {
			return CheckWebmailLogins(context.Background(), &config.Config{}, nil)
		}},
	} {
		t.Run(tc.check, func(t *testing.T) {
			user := `x [bad] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2087`
			line := `192.0.2.66 - ` + user + ` [bad -0000] "` + tc.request + ` HTTP/1.1" 401 0 "-" "-" "-" "-" ` + tc.port
			var lines []string
			for range tc.threshold {
				lines = append(lines, line)
			}
			cpanelScanLog(t, lines)
			got := tc.run()
			if len(got) != 1 || got[0].Check != tc.check || got[0].SourceIP != "192.0.2.66" || got[0].Observation != (alert.Observation{}) {
				t.Fatalf("undated records: got %+v, want one %s without observation", got, tc.check)
			}
		})
	}
}

// Client-chosen bracketed fields must not hide the server's request, even
// when the server time cannot date an observation.
func TestParseCpanelAccessRecordUndatedUserFields(t *testing.T) {
	for _, stamp := range []string{"bad -0000", "09/Nov/2026:12:00:00 +0000", "11/09/2026:12:00:00 -0000"} {
		for _, user := range []string{
			`x [bad] "y`,
			`x ] "y`,
			`x [bad] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083`,
			`x [11/10/2026:09:00:00 -0000] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083`,
		} {
			line := `192.0.2.66 - ` + user + ` [` + stamp + `] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "-" "-" "-" 2087`
			got, ok := ParseCpanelAccessRecord(line)
			var want time.Time
			if stamp == "11/09/2026:12:00:00 -0000" && !strings.Contains(user, "[11/10/2026:") {
				want = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
			}
			if !ok || !hasCpanelRequest(got, "GET", "/scripts2/listaccts") || !got.MayHaveStatus("401") ||
				got.Port != "2087" || !got.At.Equal(want) {
				t.Errorf("user %q, stamp %q: got %+v (%v), want the real request at %v", user, stamp, got, ok, want)
			}
		}
	}
}

// A repeated close bracket must not rescan the growing user prefix to find
// its opening bracket. All suffix candidates still lead to the real request.
func TestParseCpanelAccessRecordUndatedIsLinear(t *testing.T) {
	cost := func(n int) time.Duration {
		user := `x [` + strings.Repeat(`] "x `, n)
		line := `192.0.2.66 - ` + user + ` [bad -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "-" "-" "-" 2087`
		best := time.Duration(1<<63 - 1)
		for range 5 {
			start := time.Now()
			got, ok := ParseCpanelAccessRecord(line)
			found := hasCpanelRequest(got, "GET", "/scripts2/listaccts")
			elapsed := time.Since(start)
			if !ok || !found || got.Port != "2087" || !got.At.IsZero() {
				t.Fatalf("%d candidates lost the undated request", n)
			}
			best = min(best, elapsed)
		}
		return best
	}
	small, large := cost(20000), cost(160000)
	if large > 32*small+time.Millisecond {
		t.Fatalf("8x the candidates cost %v against %v: the scan is not linear", large, small)
	}
}

// Escaped header quotes are data, even when they enclose another request
// and timestamp. Neither suffix fields nor the user can choose the port.
func TestParseCpanelAccessRecordEscapedHeaderFields(t *testing.T) {
	for _, client := range []string{
		`agent \"quoted\"`,
		`[11/10/2026:09:00:00 -0000] \"POST /index.html HTTP/1.1\" 200 0 \"example.com:2083\"`,
		`agent\\`,
	} {
		for _, headers := range []string{`"` + client + `" "agent"`, `"-" "` + client + `"`} {
			for _, stamp := range []string{"11/09/2026:12:00:00 -0000", "bad -0000"} {
				line := `192.0.2.66 - - [` + stamp + `] "GET /scripts2/listaccts HTTP/1.1" 401 0 ` + headers + ` "-" "-" 2087`
				got, ok := ParseCpanelAccessRecord(line)
				if !ok || !hasCpanelRequest(got, "GET", "/scripts2/listaccts") || !got.MayHaveStatus("401") || got.Port != "2087" {
					t.Errorf("escaped header %q: got %+v (%v)", client, got, ok)
				}
			}
		}
	}
}

func TestParseCpanelAccessRecordFields(t *testing.T) {
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	get := func(target string) CpanelRequest { return CpanelRequest{Method: "GET", Target: target} }
	cases := map[string]struct {
		line               string
		user, status, port string
		at                 time.Time
		requests           []CpanelRequest
	}{
		"native bare port": {
			`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "POST /login/?login_only=1 HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2087`,
			"-", "200", "2087", at, []CpanelRequest{{Method: "POST", Target: "/login/?login_only=1"}},
		},
		"quoted host port": {
			`192.0.2.66 - alice [11/09/2026:12:00:00 -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "curl/8.4.0" "host.example.com:2086"`,
			"alice", "401", "2086", at, []CpanelRequest{get("/scripts2/listaccts")},
		},
		"agent is not the host": {
			`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "agent:2087"`,
			"-", "200", "", at, []CpanelRequest{get("/")},
		},
		// A quote in the user must not hide the request (it used to be
		// read as the first quoted pair on the line).
		"quote in user": {
			`192.0.2.66 - x" [11/09/2026:12:00:00 -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "-" "-" "-" 2087`,
			`x"`, "401", "2087", at, []CpanelRequest{get("/scripts2/listaccts")},
		},
		// cpsrvd writes client quotes raw. They cannot move the request or
		// the port; they leave the line undated.
		"raw quotes in query and agent": {
			`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET /x?q={"a":1}&b"c" HTTP/1.1" 401 0 "-" "curl "8" x" "-" "-" 2087`,
			"-", "401", "2087", time.Time{}, []CpanelRequest{get(`/x?q={"a":1}&b"c"`)},
		},
		// A forged record in the user adds a request; the real one stays,
		// and the line carries no time or single status.
		"forged record in user": {
			`192.0.2.66 - x [11/10/2026:09:00:00 -0000] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083 [11/09/2026:12:00:00 -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "-" "-" "-" 2087`,
			"x", "", "2087", time.Time{}, []CpanelRequest{get("/index.html"), get("/scripts2/listaccts")},
		},
		// A time cpsrvd would not write leaves the line undated, not unread.
		"other time form": {
			`192.0.2.66 - - [bad -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "-" "-" "-" 2087`,
			"-", "401", "2087", time.Time{}, []CpanelRequest{get("/scripts2/listaccts")},
		},
		"no served port": {
			`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "-" "-" "-" 2087 junk`,
			"-", "200", "", time.Time{}, []CpanelRequest{get("/")},
		},
	}
	for name, tc := range cases {
		got, ok := ParseCpanelAccessRecord(tc.line)
		requests := slices.Collect(got.Requests())
		if !ok || got.IP != "192.0.2.66" || got.User != tc.user || got.Status != tc.status || got.Port != tc.port ||
			!got.At.Equal(tc.at) || !slices.Equal(requests, tc.requests) {
			t.Errorf("%s: got %+v with %v (%v), want user %q status %q port %q at %v requests %v",
				name, got, requests, ok, tc.user, tc.status, tc.port, tc.at, tc.requests)
		}
	}
	for name, line := range map[string]string{
		"ident not dash":  `192.0.2.66 x - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "-" "-" "-" 2087`,
		"no quotes":       "no quotes here",
		"peer not an ip":  `host.example.com - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "-" "-" "-" 2087`,
		"no request line": `192.0.2.66 - - [11/09/2026:12:00:00 -0000]`,
		"no method":       `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "\x16\x03\x01" 400 0 "-" "-" "-" "-" 2087`,
	} {
		if got, ok := ParseCpanelAccessRecord(line); ok || got != (CpanelAccessRecord{}) {
			t.Errorf("%s: parsed as %+v", name, got)
		}
	}
}

// hasCpanelRequest reports whether rec may hold method and target.
func hasCpanelRequest(rec CpanelAccessRecord, method, target string) bool {
	return rec.Any(func(q CpanelRequest) bool { return q.Method == method && q.Target == target })
}

func TestCpanelAccessRecordWebmailLogin(t *testing.T) {
	for line, want := range map[string]bool{
		`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "POST /login/?login_only=1 HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2096`:       true,
		`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "POST /login/ HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2095`:                    true,
		`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "POST /cpsess1/3rdparty/roundcube/ HTTP/1.1" 200 0 "-" "Postman" "-" "-" 2096`:   false,
		`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET /login/ HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2096`:                     false,
		`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "POST /login/ HTTP/1.1" 200 0 "https://host.example.com:2096/" "-" "-" "-" 2083`: false,
	} {
		rec, _ := ParseCpanelAccessRecord(line)
		if got := rec.WebmailLogin(); got != want {
			t.Errorf("%q: webmail login = %v, want %v", line, got, want)
		}
	}
}

// A "proxy" ident record parses, but its leading address came through a
// service subdomain: it never dates a scan observation and never explains
// a failure as a stale browser session.
func TestCpanelAccessProxyIdentIsNotPeerEvidence(t *testing.T) {
	line := `192.0.2.77 proxy - [11/09/2026:12:00:00 -0000] "GET /cpsess0123456789/execute/Themes/list HTTP/1.1" 401 0 "-" "agent" "-" "198.51.100.7" 2083`
	rec, ok := ParseCpanelAccessRecord(line)
	if !ok || rec.IP != "192.0.2.77" || rec.Port != "2083" || rec.Status != "401" {
		t.Fatalf("record = %+v (%v)", rec, ok)
	}
	if at, ok := cpanelAccessLogTime(line); ok || !at.IsZero() {
		t.Fatalf("proxy record dated %v", at)
	}
	if r, ok := ParseStaleSessionRequest(line); ok {
		t.Fatalf("proxy record parsed as stale session evidence: %+v", r)
	}
}
