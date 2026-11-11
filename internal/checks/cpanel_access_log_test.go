package checks

import (
	"testing"
	"time"
)

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
