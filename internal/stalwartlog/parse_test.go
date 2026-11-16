package stalwartlog

import (
	"net/netip"
	"reflect"
	"slices"
	"strconv"
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

// The rejected-login layouts Stalwart 1.0 writes: remoteIp near the end, the
// account absent when the domain is unknown, and no id on SMTP.
func TestParseAuthFailedLayouts(t *testing.T) {
	for _, tc := range []struct {
		line    string
		port    uint16
		account string
	}{
		{`2026-11-13T06:09:54Z INFO Authentication failed (auth.failed) listenerId = "imaps", localPort = 993, remotePort = 38562, accountName = "nobody@example.com", reason = "Account not found", remoteIp = 203.0.113.10, id = "A002"`, 993, "nobody@example.com"},
		{`2026-11-13T06:09:54Z INFO Authentication failed (auth.failed) listenerId = "imaps", localPort = 993, remotePort = 38562, domain = "invalid.example", reason = "Domain not found", remoteIp = 203.0.113.10, id = "A002"`, 993, ""},
		{`2026-11-13T06:09:54Z INFO Authentication failed (auth.failed) listenerId = "submissions", localPort = 465, remotePort = 38562, accountName = "nobody@example.com", reason = "Account not found", remoteIp = 2001:db8::10`, 465, "nobody@example.com"},
	} {
		ev := mustParse(t, tc.line)
		s, ok := ev.Session()
		if ev.Name != "auth.failed" || !ok || s.LocalPort != tc.port || ev.Fields["accountName"] != tc.account {
			t.Fatalf("%s\nparsed as %+v, session %+v (%v)", tc.line, ev, s, ok)
		}
	}
}

func TestParseNestedEventValues(t *testing.T) {
	failed := mustParse(t, `2026-11-16T14:00:00Z INFO Delivery failed (delivery.failed) from = "a@example.org", size = 5950, total = 1, queueId = 7, queueName = "remote", to = "b@example.net", reason = SMTP error occurred (delivery.unexpected-response) { details = "Unexpected reply, try later", code = 421, command = "MAIL FROM:<a@example.org>", reason = "line one\nline } two" }, details = 2026-11-16T14:00:00Z, expires = 2026-11-21T14:00:00Z`)
	if got := failed.Fields["reason"]; got != `SMTP error occurred (delivery.unexpected-response) { details = "Unexpected reply, try later", code = 421, command = "MAIL FROM:<a@example.org>", reason = "line one\nline } two" }` {
		t.Fatalf("reason = %q, want the complete nested event", got)
	}
	if got := failed.Fields["details"]; got != "2026-11-16T14:00:00Z" {
		t.Fatalf("details = %q, a nested key reached the top level", got)
	}
	if got := failed.Fields["expires"]; got != "2026-11-21T14:00:00Z" {
		t.Fatalf("expires = %q", got)
	}
	if _, ok := failed.Fields["code"]; ok {
		t.Fatal("nested key code reached the top level")
	}

	iprev := mustParse(t, `2026-11-16T14:00:00Z INFO IPREV check passed (smtp.iprev-pass) listenerId = "smtp", localPort = 25, remoteIp = 2001:db8::5, remotePort = 46541, domain = "mx.example.org", result = IPREV check passed (iprev.pass) { details = ["mx.example.org."] }, elapsed = 83ms`)
	if iprev.Fields["result"] != `IPREV check passed (iprev.pass) { details = ["mx.example.org."] }` || iprev.Fields["elapsed"] != "83ms" {
		t.Fatalf("iprev fields = %+v", iprev.Fields)
	}
	if _, ok := iprev.Lists["details"]; ok {
		t.Fatal("nested list reached the top level")
	}

	dkim := mustParse(t, `2026-11-16T14:00:00Z INFO DKIM verification passed (smtp.dkim-pass) listenerId = "smtp", localPort = 25, remoteIp = 2001:db8::5, remotePort = 46541, strict = false, result = [DKIM verification passed (dkim.pass) { domain = "example.org" }, DKIM verification failed (dkim.fail) {}], elapsed = 38ms`)
	if got := dkim.Lists["result"]; !slices.Equal(got, []string{`DKIM verification passed (dkim.pass) { domain = "example.org" }`, `DKIM verification failed (dkim.fail) {}`}) {
		t.Fatalf("result = %q", got)
	}
	if dkim.Fields["elapsed"] != "38ms" {
		t.Fatalf("elapsed = %q", dkim.Fields["elapsed"])
	}
}

func TestParseNestedKeysCannotSupplySession(t *testing.T) {
	ev := mustParse(t, `2026-11-16T14:00:00Z INFO Authentication failed (auth.failed) listenerId = "smtp", localPort = 587, reason = Check failed (iprev.fail) { remoteIp = 198.51.100.9, remotePort = 1 }, accountName = "x"`)
	for _, key := range []string{"remoteIp", "remotePort"} {
		if _, ok := ev.Fields[key]; ok {
			t.Fatalf("nested %s reached the top level", key)
		}
	}
	if _, ok := ev.Session(); ok {
		t.Fatal("a nested block supplied the session")
	}
	if ev.Fields["accountName"] != "x" {
		t.Fatalf("accountName = %q", ev.Fields["accountName"])
	}
}

func TestParseRejectsBrokenNestedValues(t *testing.T) {
	deep := `a = 1`
	for range 6 {
		deep = `r = X (a.b) { ` + deep + ` }`
	}
	for _, tail := range []string{
		`reason = SMTP error occurred (smtp.error) { code = 421`,
		`reason = SMTP error occurred (smtp.error) { code = 421 } extra`,
		`reason = SMTP error occurred (smtp.error) { code }`,
		`result = [DKIM verification passed (dkim.pass) { domain = "example.org" }`,
		deep,
	} {
		line := `2026-11-16T14:00:00Z INFO Delivery failed (delivery.failed) ` + tail
		if ev, ok := Parse(line); ok {
			t.Errorf("Parse(%q) = %+v, want rejection", line, ev)
		}
	}
}

func TestParseBareTokenWithParenthesesStaysBare(t *testing.T) {
	ev := mustParse(t, `2026-11-16T14:00:00Z INFO Delivery failed (delivery.failed) note = x (a.b)c, size = 1`)
	if ev.Fields["note"] != "x (a.b)c" || ev.Fields["size"] != "1" {
		t.Fatalf("fields = %+v", ev.Fields)
	}
}

// Event-shaped scalars were accepted before nested blocks were supported.
// Keep their text and every other field, across all daemon-consumed events.
func TestParseConsumedEventsPreserveValues(t *testing.T) {
	for _, name := range []string{"auth.failed", "auth.success", "security.authentication-ban", "security.abuse-ban", "security.scan-ban", "queue.authenticated-message-queued", "queue.message-queued", "message-ingest.ham", "message-ingest.spam", "spam.classify"} {
		for _, value := range []string{"Check failed (iprev.fail)", "Check failed (iprev.fail) {}", "Check failed (iprev.fail)]suffix", "Check failed (iprev.fail) }suffix"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				line := `2026-11-11T10:00:00Z INFO Event (` + name + `) listenerId = "smtp", localPort = 25, remoteIp = 203.0.113.10, remotePort = 50123, reason = ` + value + `, result = reject, queueId = 7, accountName = "user@example.org", to = ["a@example.org"], details = " } (x.y), remoteIp = 198.51.100.9"`
				ev := mustParse(t, line)
				want := map[string]string{"listenerId": "smtp", "localPort": "25", "remoteIp": "203.0.113.10", "remotePort": "50123", "reason": value, "result": "reject", "queueId": "7", "accountName": "user@example.org", "details": " } (x.y), remoteIp = 198.51.100.9"}
				if !reflect.DeepEqual(ev.Fields, want) || !reflect.DeepEqual(ev.Lists, map[string][]string{"to": {"a@example.org"}}) {
					t.Fatalf("fields = %#v, lists = %#v; want %#v and original recipients", ev.Fields, ev.Lists, want)
				}
			})
		}
	}
}

func TestParseNestedValuesPreserveTextAndIsolateKeys(t *testing.T) {
	values := []string{
		`Check failed (iprev.fail)`,
		`Check failed (iprev.fail) {}`,
		`Check failed (iprev.fail) { remoteIp = 198.51.100.9, remotePort = 1, to = ["forged@example.org"], details = " } (x.y), remoteIp = 198.51.100.8" }`,
	}
	for _, value := range values {
		for _, list := range []bool{false, true} {
			t.Run(value+strconv.FormatBool(list), func(t *testing.T) {
				tail := value
				wantFields := map[string]string{"reason": value, "accountName": "user@example.org"}
				wantLists := map[string][]string{}
				if list {
					tail = "[" + value + `, " } (x.y), "]`
					delete(wantFields, "reason")
					wantLists["reason"] = []string{value, " } (x.y), "}
				}
				ev := mustParse(t, `2026-11-11T10:00:00Z INFO Authentication failed (auth.failed) reason = `+tail+`, accountName = "user@example.org"`)
				if !reflect.DeepEqual(ev.Fields, wantFields) || !reflect.DeepEqual(ev.Lists, wantLists) {
					t.Fatalf("fields = %#v, lists = %#v; want %#v, %#v", ev.Fields, ev.Lists, wantFields, wantLists)
				}
				if _, ok := ev.Session(); ok {
					t.Fatal("nested values supplied a session")
				}
			})
		}
	}
}
