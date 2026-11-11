package checks

import (
	"strings"
	"testing"
	"time"
)

// User text is opaque, including complete fake records. It can add requests
// and invalidate the observation time, but cannot hide the real request or
// change the listener.
func FuzzCpanelAccessRecordUserField(f *testing.F) {
	for _, user := range []string{
		"-", "user name", `x"`, `x [bad] "y`, `x ] "y`,
		`x [11/10/2026:09:00:00 -0000] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083`,
		strings.Repeat(`] "x `, 100),
	} {
		f.Add(user)
	}
	f.Fuzz(func(t *testing.T, user string) {
		user = strings.NewReplacer("\r", "_", "\n", "_").Replace(user)
		if user == "" {
			user = "-"
		}
		for _, ident := range []string{"-", "proxy"} {
			for _, stamp := range []string{"11/09/2026:12:00:00 -0000", "bad -0000"} {
				for _, prefix := range []string{"", `x [11/10/2026:09:00:00 -0000] "y `} {
					line := `192.0.2.66 ` + ident + ` ` + prefix + user + ` [` + stamp + `] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "agent" "-" "-" 2087`
					got, ok := ParseCpanelAccessRecord(line)
					if !ok || got.IP != "192.0.2.66" || got.Proxy != (ident == "proxy") || !hasCpanelRequest(got, "GET", "/scripts2/listaccts") ||
						!got.MayHaveStatus("401") || got.Port != "2087" {
						t.Fatalf("ident %q, user %q changed the request: %+v (%v)", ident, prefix+user, got, ok)
					}
					if !got.At.IsZero() && (ident == "proxy" || prefix != "" || stamp == "bad -0000" || !got.At.Equal(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))) {
						t.Fatalf("user %q supplied time %v", prefix+user, got.At)
					}
				}
			}
		}
	})
}

// Client fields may add readings, but cannot replace the server metadata
// or erase the request and response that it wrote.
func FuzzCpanelAccessRecordClientFields(f *testing.F) {
	for _, client := range []string{
		"plain", `a"b`, `" 403 0 "`,
		`[bad] "GET / HTTP/1.1" 200 0 "-" "-" "host.example:2096`,
		`[11/10/2026:09:00:00 -0000] "POST /login/ HTTP/1.1" 200 0 "-" "-" "-`,
	} {
		f.Add(client)
	}
	f.Fuzz(func(t *testing.T, client string) {
		// cpsrvd escapes control bytes in request text before logging it.
		client = strings.Map(func(r rune) rune {
			if r < ' ' || r == 0x7f {
				return '_'
			}
			return r
		}, client)
		server := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
		for _, ident := range []string{"-", "proxy"} {
			for _, stamp := range []string{"11/09/2026:12:00:00 -0000", "bad"} {
				for _, fields := range [][3]string{
					{client, "-", "agent"}, {"", client, "agent"}, {"", "-", client},
				} {
					line := `192.0.2.66 ` + ident + ` - [` + stamp + `] "GET /scripts2/listaccts?x=` + fields[0] +
						` HTTP/1.1" 401 0 "` + fields[1] + `" "` + fields[2] + `" "-" "-" 2087`
					rec, ok := ParseCpanelAccessRecord(line)
					if !ok || rec.IP != "192.0.2.66" || rec.Proxy != (ident == "proxy") || rec.Port != "2087" ||
						!rec.TargetContains("/scripts2/listaccts") || !rec.MayHaveStatus("401") {
						t.Fatalf("client text changed the server record: %+v (%v)", rec, ok)
					}
					if !rec.At.IsZero() && (ident == "proxy" || stamp == "bad" || !rec.At.Equal(server)) {
						t.Fatalf("client text supplied time %v", rec.At)
					}
				}
			}
		}
	})
}
