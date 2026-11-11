package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

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
