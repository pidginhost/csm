package stalwartlog

import (
	"regexp"
	"strconv"
	"testing"
)

var eventNameRe = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)

func FuzzParse(f *testing.F) {
	for _, line := range []string{lineAuthSuccess, lineScanBan, lineQueued} {
		f.Add(line)
		f.Add(line + "\n")
		f.Add(line + "\r\n")
	}
	f.Add(`2026-11-16T14:00:00Z INFO DKIM verification passed (smtp.dkim-pass) remoteIp = 2001:db8::5, result = [DKIM verification passed (dkim.pass) { domain = "example.org", r = X (a.b) {} }], elapsed = 38ms`)
	f.Fuzz(func(t *testing.T, line string) {
		ev, ok := Parse(line)
		if !ok {
			return
		}
		if !eventNameRe.MatchString(ev.Name) {
			t.Fatalf("event name %q does not match the grammar", ev.Name)
		}
		_, _ = ev.Session()
	})
}

func FuzzParseNestedIsolation(f *testing.F) {
	for _, text := range []string{"", " }", "(x.y)", ", remoteIp = 198.51.100.9", `\" } (x.y), remotePort = 1`} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		value := `Check failed (iprev.fail) { details = ` + strconv.Quote(text) + `, remoteIp = 198.51.100.9, remotePort = 1, to = ["forged@example.org"] }`
		for _, tail := range []string{value, "[" + value + "]"} {
			ev := mustParse(t, `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) listenerId = "smtp", localPort = 25, remoteIp = 203.0.113.10, remotePort = 50123, reason = `+tail)
			session, ok := ev.Session()
			if !ok || session.RemoteIP.String() != "203.0.113.10" || session.RemotePort != 50123 || session.LocalPort != 25 || session.Listener != "smtp" {
				t.Fatalf("nested client text changed the session: %+v (%v)", session, ok)
			}
			if _, exists := ev.Fields["details"]; exists || len(ev.Lists["to"]) != 0 {
				t.Fatal("nested keys escaped their block")
			}
			if ev.Fields["reason"] != value && (len(ev.Lists["reason"]) != 1 || ev.Lists["reason"][0] != value) {
				t.Fatal("nested event text changed")
			}
		}
	})
}
