package checks

import (
	"context"
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
			if !ok || got.IP != ip || got.User != user || got.Method != "GET" || got.Target != "/scripts2/listaccts" || got.Status != "401" || got.Port != "2087" {
				t.Fatalf("proxy record lost or changed: %+v (%v)", got, ok)
			}
			if user != "-" && !got.At.IsZero() {
				t.Fatalf("proxy user supplied an observation time: %v", got.At)
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
		if !ok || got.Method != method || got.Target != "/execute/Themes/list" || got.Status != "401" || got.Port != "2083" ||
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
			want := CpanelAccessRecord{IP: "192.0.2.66", User: user, Method: "GET", Target: "/scripts2/listaccts", Status: "401", Port: "2087"}
			if stamp == "11/09/2026:12:00:00 -0000" && !strings.Contains(user, "[11/10/2026:") {
				want.At = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
			}
			at := got.At
			got.At = want.At
			if !ok || got != want || !at.Equal(want.At) {
				t.Errorf("user %q, stamp %q: got %+v at %v (%v), want %+v", user, stamp, got, at, ok, want)
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
			elapsed := time.Since(start)
			if !ok || got.User != user || got.Target != "/scripts2/listaccts" || got.Port != "2087" || !got.At.IsZero() {
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
				if !ok || got.Method != "GET" || got.Target != "/scripts2/listaccts" || got.Status != "401" || got.Port != "2087" {
					t.Errorf("escaped header %q: got %+v (%v)", client, got, ok)
				}
			}
		}
	}
}

func TestParseCpanelAccessRecordFields(t *testing.T) {
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	cases := map[string]struct {
		line string
		want CpanelAccessRecord
	}{
		"native bare port": {
			`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "POST /login/?login_only=1 HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2087`,
			CpanelAccessRecord{IP: "192.0.2.66", User: "-", Method: "POST", Target: "/login/?login_only=1", Status: "200", Port: "2087", At: at},
		},
		"quoted host port": {
			`192.0.2.66 - alice [11/09/2026:12:00:00 -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "curl/8.4.0" "host.example.com:2086"`,
			CpanelAccessRecord{IP: "192.0.2.66", User: "alice", Method: "GET", Target: "/scripts2/listaccts", Status: "401", Port: "2086", At: at},
		},
		"agent is not the host": {
			`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "agent:2087"`,
			CpanelAccessRecord{IP: "192.0.2.66", User: "-", Method: "GET", Target: "/", Status: "200", At: at},
		},
		// A quote in the user must not hide the request (it used to be
		// read as the first quoted pair on the line).
		"quote in user": {
			`192.0.2.66 - x" [11/09/2026:12:00:00 -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "-" "-" "-" 2087`,
			CpanelAccessRecord{IP: "192.0.2.66", User: `x"`, Method: "GET", Target: "/scripts2/listaccts", Status: "401", Port: "2087", At: at},
		},
		// A forged record in the user runs into the real timestamp, so the
		// real request still parses; the line just carries no time.
		"forged record in user": {
			`192.0.2.66 - x [11/10/2026:09:00:00 -0000] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083 [11/09/2026:12:00:00 -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "-" "-" "-" 2087`,
			CpanelAccessRecord{IP: "192.0.2.66", User: `x [11/10/2026:09:00:00 -0000] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083`, Method: "GET", Target: "/scripts2/listaccts", Status: "401", Port: "2087"},
		},
		// A time cpsrvd would not write leaves the line undated, not unread.
		"other time form": {
			`192.0.2.66 - - [bad -0000] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "-" "-" "-" 2087`,
			CpanelAccessRecord{IP: "192.0.2.66", User: "-", Method: "GET", Target: "/scripts2/listaccts", Status: "401", Port: "2087"},
		},
	}
	for name, tc := range cases {
		got, ok := ParseCpanelAccessRecord(tc.line)
		gotAt, wantAt := got.At, tc.want.At
		got.At, tc.want.At = time.Time{}, time.Time{}
		if !ok || got != tc.want || !gotAt.Equal(wantAt) {
			t.Errorf("%s: got %+v at %v (%v), want %+v at %v", name, got, gotAt, ok, tc.want, wantAt)
		}
	}
	for name, line := range map[string]string{
		"ident not dash":  `192.0.2.66 x - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "-" "-" "-" 2087`,
		"no quotes":       "no quotes here",
		"trailing junk":   `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "-" "-" "-" 2087 junk`,
		"port 0":          `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "-" "-" "-" 0`,
		"peer not an ip":  `host.example.com - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "-" "-" "-" 2087`,
		"unterminated":    `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1 200 0`,
		"no request line": `192.0.2.66 - - [11/09/2026:12:00:00 -0000]`,
	} {
		if got, ok := ParseCpanelAccessRecord(line); ok || got != (CpanelAccessRecord{}) {
			t.Errorf("%s: parsed as %+v", name, got)
		}
	}
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
