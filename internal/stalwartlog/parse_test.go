package stalwartlog

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Synthetic lines in the layout Stalwart 1.0 writes. Never paste a live line.
const (
	lineAuthSuccess = `2026-11-11T10:00:00Z INFO Authentication successful (auth.success) listenerId = "imaps", localPort = 993, remoteIp = 203.0.113.10, remotePort = 50123, accountName = "user@example.com", accountId = 7`
	lineScanBan     = `2026-11-11T10:01:00Z INFO IP banned for port scanning (security.scan-ban) listenerId = "smtp", localPort = 25, remotePort = 41000, remoteIp = 198.51.100.20, reason = "scan"`
	lineQueued      = `2026-11-11T10:02:00Z INFO Authenticated message queued for delivery (queue.authenticated-message-queued) listenerId = "submission", localPort = 587, remoteIp = 203.0.113.10, remotePort = 50124, queueId = 99, from = "user@example.com", to = ["a@example.org", "b@example.net"], size = 1200, nextRetry = 2026-11-11T10:02:00Z, nextDsn = 2026-11-11T14:02:00Z, expires = 2026-11-16T10:02:00Z`
)

func mustParse(t *testing.T, line string) Event {
	t.Helper()
	ev, ok := Parse(line)
	if !ok {
		t.Fatalf("Parse(%q) failed", line)
	}
	return ev
}

func TestParseAuthSuccess(t *testing.T) {
	ev := mustParse(t, lineAuthSuccess)
	if ev.Name != "auth.success" || ev.Level != "INFO" {
		t.Fatalf("name/level = %q/%q", ev.Name, ev.Level)
	}
	if want := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC); !ev.Time.Equal(want) {
		t.Fatalf("time = %v, want %v", ev.Time, want)
	}
	if got := ev.Fields["accountName"]; got != "user@example.com" {
		t.Fatalf("accountName = %q", got)
	}
	s, ok := ev.Session()
	want := Session{Listener: "imaps", LocalPort: 993, RemoteIP: netip.MustParseAddr("203.0.113.10"), RemotePort: 50123}
	if !ok || s != want {
		t.Fatalf("Session() = %+v, %v; want %+v", s, ok, want)
	}
}

func TestParseLineEndings(t *testing.T) {
	for _, line := range []string{
		lineAuthSuccess, lineScanBan, lineQueued,
		`2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) listenerId = "smtp", localPort = 587, remoteIp = 203.0.113.10, remotePort = 50123, accountName = "user@example.com", reason = "Invalid credentials"`,
		`2026-11-11T10:00:00Z INFO Stalwart started (server.startup)`,
	} {
		want := mustParse(t, line)
		for _, ending := range []string{"\n", "\r\n"} {
			if got, ok := Parse(line + ending); !ok || !reflect.DeepEqual(got, want) {
				t.Errorf("Parse(%q) = %+v, %v; want %+v", line+ending, got, ok, want)
			}
		}
	}
}

func TestParseKeyOrderDoesNotMatter(t *testing.T) {
	ev := mustParse(t, lineScanBan)
	s, ok := ev.Session()
	if !ok || s.RemoteIP != netip.MustParseAddr("198.51.100.20") || s.RemotePort != 41000 || s.LocalPort != 25 {
		t.Fatalf("Session() = %+v, %v", s, ok)
	}
	if got := ev.Fields["reason"]; got != "scan" {
		t.Fatalf("reason = %q", got)
	}
}

func TestParseList(t *testing.T) {
	ev := mustParse(t, lineQueued)
	if got := ev.Lists["to"]; !slices.Equal(got, []string{"a@example.org", "b@example.net"}) {
		t.Fatalf("to = %q", got)
	}
	if got := ev.Fields["from"]; got != "user@example.com" {
		t.Fatalf("from = %q", got)
	}
	if got := ev.Fields["nextDsn"]; got != "2026-11-11T14:02:00Z" {
		t.Fatalf("nextDsn = %q", got)
	}
}

func TestParseQuotedValueCannotOverrideSessionKey(t *testing.T) {
	line := strings.Replace(lineAuthSuccess, `accountName = "user@example.com"`, `accountName = "x\", remoteIp = 198.51.100.9"`, 1)
	ev := mustParse(t, line)
	s, ok := ev.Session()
	if !ok || s.RemoteIP != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("Session() = %+v, %v; injected address won", s, ok)
	}
	if got, want := ev.Fields["accountName"], `x", remoteIp = 198.51.100.9`; got != want {
		t.Fatalf("accountName = %q, want %q", got, want)
	}
}

func TestParseFirstKeyWins(t *testing.T) {
	ev := mustParse(t, `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) listenerId = "smtp", localPort = 587, remoteIp = 203.0.113.10, remotePort = 1, remoteIp = 198.51.100.9`)
	if got := ev.Fields["remoteIp"]; got != "203.0.113.10" {
		t.Fatalf("remoteIp = %q, want the first value", got)
	}
}

func TestParseQuotedEventAndSessionInjection(t *testing.T) {
	line := `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) listenerId = "http", localPort = 8080, remoteIp = 203.0.113.10, remotePort = 50123, accountName = "x\" (security.scan-ban) localPort = 25, remoteIp = 198.51.100.9", reason = "invalid credentials"` + "\n"
	ev := mustParse(t, line)
	s, ok := ev.Session()
	if ev.Name != "auth.failed" || !ok || s.LocalPort != 8080 || s.RemoteIP.String() != "203.0.113.10" {
		t.Fatalf("quoted client data changed event or session: %+v, %+v, %v", ev, s, ok)
	}
	for _, first := range []string{"(null)", "[]", `"invalid"`} {
		ev := mustParse(t, `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) localPort = 587, remotePort = 50123, remoteIp = `+first+`, remoteIp = 198.51.100.9`+"\n")
		if s, ok := ev.Session(); ok {
			t.Fatalf("duplicate replaced first remoteIp %s: %+v", first, s)
		}
	}
}

func TestParseNullIsAbsent(t *testing.T) {
	ev := mustParse(t, `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) listenerId = "smtp", accountName = (null), reason = "bad"`)
	if _, ok := ev.Fields["accountName"]; ok {
		t.Fatal("a null value must leave the key absent")
	}
	if ev.Fields["reason"] != "bad" {
		t.Fatalf("reason = %q", ev.Fields["reason"])
	}
}

func TestParseDescriptionWithParentheses(t *testing.T) {
	ev := mustParse(t, `2026-11-11T10:00:00Z INFO Login (legacy) failed (auth.failed) remoteIp = 203.0.113.10`)
	if ev.Name != "auth.failed" {
		t.Fatalf("name = %q", ev.Name)
	}
}

func TestParseNoFields(t *testing.T) {
	ev := mustParse(t, `2026-11-11T10:00:00Z INFO Stalwart started (server.startup)`)
	if ev.Name != "server.startup" || len(ev.Fields) != 0 {
		t.Fatalf("event = %+v", ev)
	}
}

func TestParseEscapes(t *testing.T) {
	ev := mustParse(t, `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) accountName = "a\\b\tc\nd"`)
	if got := ev.Fields["accountName"]; got != "a\\b\tc\nd" {
		t.Fatalf("accountName = %q", got)
	}
}

func TestParseRejects(t *testing.T) {
	for _, line := range []string{
		"",
		"garbage",
		`2026-13-01T00:00:00Z INFO Authentication failed (auth.failed) remoteIp = 203.0.113.10`,
		`2026-11-11T10:00:00Z INFO Authentication failed remoteIp = 203.0.113.10`,
		`2026-11-11T10:00:00Z info Authentication failed (auth.failed) remoteIp = 203.0.113.10`,
		`2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) accountName = "abc`,
		`2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) to = ["a@example.org"`,
		`2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) accountName "abc"`,
		`2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) accountName = "abc" remoteIp = 203.0.113.10`,
	} {
		if ev, ok := Parse(line); ok {
			t.Errorf("Parse(%q) = %+v, want rejection", line, ev)
		}
	}
}

func TestSessionRejectsMalformed(t *testing.T) {
	for _, tail := range []string{
		`listenerId = "smtp", localPort = 70000, remoteIp = 203.0.113.10, remotePort = 1`,
		`listenerId = "smtp", localPort = 25, remoteIp = not-an-ip, remotePort = 1`,
		`listenerId = "smtp", localPort = 25, remoteIp = 203.0.113.10`,
	} {
		ev := mustParse(t, `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) `+tail)
		if s, ok := ev.Session(); ok {
			t.Errorf("Session() for %q = %+v, want rejection", tail, s)
		}
	}
}

func TestSessionUnmapsIPv4Mapped(t *testing.T) {
	ev := mustParse(t, strings.Replace(lineAuthSuccess, "remoteIp = 203.0.113.10", "remoteIp = ::ffff:203.0.113.10", 1))
	s, ok := ev.Session()
	if !ok || s.RemoteIP.String() != "203.0.113.10" {
		t.Fatalf("Session() = %+v, %v", s, ok)
	}
}

func TestParseUnicodeEscapes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`\u{e9}`, "\u00e9"},
		{`\u{1F600}`, "\U0001F600"},
		{`\u{110000}`, "u{110000}"},
		{`\u{FFFFFFFF}`, "u{FFFFFFFF}"},
		{`\u{zz}`, "u{zz}"},
		{`\u`, "u"},
	} {
		ev := mustParse(t, `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) accountName = "`+tc.in+`"`)
		if got := ev.Fields["accountName"]; got != tc.want {
			t.Errorf("%s decoded to %q, want %q", tc.in, got, tc.want)
		}
	}
}
