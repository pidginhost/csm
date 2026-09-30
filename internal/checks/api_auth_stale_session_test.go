package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

const staleSessionDeniedLine = `[2026-04-12 10:00:05 +0300] info [cpaneld] 198.51.100.7 PURGE alice:Sess1onNameAbCdEf tokendenied [Too many token failures (3/3)]`

func TestParseSessionTokenDenialReadsCpsrvdPurge(t *testing.T) {
	d, ok := ParseSessionTokenDenial(staleSessionDeniedLine)
	if !ok {
		t.Fatal("tokendenied PURGE line was not parsed")
	}
	if d.IP != "198.51.100.7" || d.Account != "alice" {
		t.Fatalf("denial = %+v, want IP 198.51.100.7 account alice", d)
	}
	want := time.Date(2026, 4, 12, 7, 0, 5, 0, time.UTC)
	if !d.At.Equal(want) {
		t.Fatalf("At = %v, want %v", d.At, want)
	}
}

func TestParseSessionTokenDenialAcceptsEachSessionService(t *testing.T) {
	for _, svc := range []string{"cpaneld", "webmaild", "whostmgrd"} {
		line := strings.Replace(staleSessionDeniedLine, "[cpaneld]", "["+svc+"]", 1)
		if _, ok := ParseSessionTokenDenial(line); !ok {
			t.Errorf("%s tokendenied line was not parsed", svc)
		}
	}
}

func TestParseSessionTokenDenialAcceptsIPv6(t *testing.T) {
	line := strings.Replace(staleSessionDeniedLine, "198.51.100.7", "2001:db8::7", 1)
	d, ok := ParseSessionTokenDenial(line)
	if !ok || d.IP != "2001:db8::7" {
		t.Fatalf("IPv6 denial = %+v ok=%v", d, ok)
	}
}

func TestParseSessionTokenDenialRejectsOtherLines(t *testing.T) {
	cases := map[string]string{
		"logout":            `[2026-04-12 10:00:05 +0300] info [cpaneld] 198.51.100.7 PURGE alice:Sess1onNameAbCdEf logout`,
		"cookie ip check":   `[2026-04-12 10:00:05 +0300] info [cpaneld] 198.51.100.7 PURGE alice:Sess1onNameAbCdEf badpass [cookie ip check: IP address has changed]`,
		"reason in bracket": `[2026-04-12 10:00:05 +0300] info [cpaneld] 198.51.100.7 PURGE alice:Sess1onNameAbCdEf badpass [tokendenied]`,
		"password change":   `[2026-04-12 10:00:05 +0300] info [security] internal PURGE alice:Sess1onNameAbCdEf password_change`,
		"internal source":   `[2026-04-12 10:00:05 +0300] info [cpaneld] internal PURGE alice:Sess1onNameAbCdEf tokendenied [Too many token failures (3/3)]`,
		"admin service":     `[2026-04-12 10:00:05 +0300] info [xml-api] 198.51.100.7 PURGE alice:Sess1onNameAbCdEf tokendenied [Too many token failures (3/3)]`,
		"new session":       `[2026-04-12 10:00:05 +0300] info [cpaneld] 198.51.100.7 NEW alice:Sess1onNameAbCdEf address=198.51.100.7,app=cpaneld,method=handle_form_login`,
		"no session name":   `[2026-04-12 10:00:05 +0300] info [cpaneld] 198.51.100.7 PURGE alice tokendenied [Too many token failures (3/3)]`,
		"no timestamp":      `info [cpaneld] 198.51.100.7 PURGE alice:Sess1onNameAbCdEf tokendenied [Too many token failures (3/3)]`,
		"text before stamp": `x [2026-04-12 10:00:05 +0300] info [cpaneld] 198.51.100.7 PURGE alice:Sess1onNameAbCdEf tokendenied`,
	}
	for name, line := range cases {
		if d, ok := ParseSessionTokenDenial(line); ok {
			t.Errorf("%s: parsed as denial %+v", name, d)
		}
	}
}

// staleSessionAccessLine is the cpsrvd access_log shape of one request from
// the stale browser tab.
func staleSessionAccessLine(ip, user, stamp, path, status string) string {
	return ip + ` - ` + user + ` [` + stamp + ` -0000] "GET ` + path + ` HTTP/1.1" ` + status + ` 0 "https://example.com:2083/" "Mozilla/5.0" "-" "-" 2083`
}

func staleSessionDenial(t *testing.T) SessionTokenDenial {
	t.Helper()
	d, ok := ParseSessionTokenDenial(staleSessionDeniedLine)
	if !ok {
		t.Fatal("fixture denial did not parse")
	}
	return d
}

func staleSessionReq(t *testing.T, line string) StaleSessionRequest {
	t.Helper()
	r, ok := ParseStaleSessionRequest(line)
	if !ok {
		t.Fatalf("fixture line did not parse: %s", line)
	}
	return r
}

const staleTabPath = "/cpsess0123456789/execute/Themes/list"

// staleSessionEvidence is what cPanel logged for the stale tab: the session
// cookie named alice, the URL token was rejected, the session was purged.
func staleSessionEvidence(t *testing.T) StaleSessionEvidence {
	t.Helper()
	return StaleSessionEvidence{
		Denials:  []SessionTokenDenial{staleSessionDenial(t)},
		Rejected: []StaleSessionRequest{staleSessionReq(t, staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:07:00:05", staleTabPath, "401"))},
	}
}

func TestParseStaleSessionRequestReadsSessionURL401(t *testing.T) {
	r, ok := ParseStaleSessionRequest(staleSessionAccessLine("2001:0db8:0:0::7", "alice", "04/12/2026:07:00:05", "/cpsess0123456789/execute/DomainInfo/domains_data?format=hash", "401"))
	if !ok {
		t.Fatal("session-URL 401 was not parsed")
	}
	want := StaleSessionRequest{IP: "2001:db8::7", User: "alice", Token: "0123456789", At: time.Date(2026, 4, 12, 7, 0, 5, 0, time.UTC)}
	if r.IP != want.IP || r.User != want.User || r.Token != want.Token || !r.At.Equal(want.At) {
		t.Fatalf("request = %+v, want %+v", r, want)
	}
}

func TestParseStaleSessionRequestRejectsOtherRequests(t *testing.T) {
	cases := map[string]string{
		"token api path":    staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", "/execute/Themes/list", "401"),
		"json-api no token": staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", "/json-api/listaccts", "401"),
		"forbidden":         staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", staleTabPath, "403"),
		"success":           staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:07:00:05", staleTabPath, "200"),
		"bad token shape":   staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", "/cpsessabc/execute/Themes/list", "401"),
		"token only":        staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", "/cpsess0123456789", "401"),
		"no timestamp":      `198.51.100.7 - - "GET /cpsess0123456789/execute/Themes/list HTTP/1.1" 401 0`,
		"apache timestamp":  `198.51.100.7 - - [12/Apr/2026:07:00:05 +0000] "GET /cpsess0123456789/execute/Themes/list HTTP/1.1" 401 0`,
		"bad address":       staleSessionAccessLine("host.example", "-", "04/12/2026:07:00:05", staleTabPath, "401"),
	}
	for name, line := range cases {
		if r, ok := ParseStaleSessionRequest(line); ok {
			t.Errorf("%s: parsed as %+v", name, r)
		}
	}
}

func TestStaleSessionEvidenceExplainsStaleTab(t *testing.T) {
	e := staleSessionEvidence(t)
	cases := map[string]string{
		"rejected request": staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:07:00:05", staleTabPath, "401"),
		"other endpoint":   staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:07:00:04", "/cpsess0123456789/execute/SSL/list_certs", "401"),
		"dead cookie":      staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", "/cpsess0123456789/execute/WebApp/list", "401"),
		"window start":     staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:07:00:00", staleTabPath, "401"),
		"window end":       staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:10", staleTabPath, "401"),
	}
	for name, line := range cases {
		if !e.Explains(staleSessionReq(t, line)) {
			t.Errorf("%s: stale-tab 401 was not explained", name)
		}
	}
}

func TestStaleSessionEvidenceRequiresMatchingEvidence(t *testing.T) {
	e := staleSessionEvidence(t)
	cases := map[string]string{
		"other ip":      staleSessionAccessLine("203.0.113.9", "-", "04/12/2026:07:00:05", staleTabPath, "401"),
		"other account": staleSessionAccessLine("198.51.100.7", "bob", "04/12/2026:07:00:05", staleTabPath, "401"),
		"before window": staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:06:59:59", staleTabPath, "401"),
		"after window":  staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:11", staleTabPath, "401"),
		// Someone else behind the same address cannot know the stale tab's
		// URL token, so their anonymous requests stay unexplained.
		"shared address, other token": staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", "/cpsess9999999999/execute/Themes/list", "401"),
	}
	for name, line := range cases {
		if e.Explains(staleSessionReq(t, line)) {
			t.Errorf("%s: 401 was explained without matching evidence", name)
		}
	}
}

// A dead-cookie request is explained only through a rejected request that
// the denial itself explains: same address, same token, the denied account,
// inside the window.
func TestStaleSessionEvidenceAnonymousNeedsExplainedRejection(t *testing.T) {
	dead := staleSessionReq(t, staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", staleTabPath, "401"))
	denial := staleSessionDenial(t)
	cases := map[string]StaleSessionEvidence{
		"denial only": {Denials: []SessionTokenDenial{denial}},
		"rejection only": {Rejected: []StaleSessionRequest{
			staleSessionReq(t, staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:07:00:05", staleTabPath, "401")),
		}},
		"rejection for other account": {Denials: []SessionTokenDenial{denial}, Rejected: []StaleSessionRequest{
			staleSessionReq(t, staleSessionAccessLine("198.51.100.7", "bob", "04/12/2026:07:00:05", staleTabPath, "401")),
		}},
		"rejection from other ip": {Denials: []SessionTokenDenial{denial}, Rejected: []StaleSessionRequest{
			staleSessionReq(t, staleSessionAccessLine("203.0.113.9", "alice", "04/12/2026:07:00:05", staleTabPath, "401")),
		}},
		"rejection outside window": {Denials: []SessionTokenDenial{denial}, Rejected: []StaleSessionRequest{
			staleSessionReq(t, staleSessionAccessLine("198.51.100.7", "alice", "04/12/2026:06:59:50", staleTabPath, "401")),
		}},
	}
	for name, e := range cases {
		if e.Explains(dead) {
			t.Errorf("%s: dead-cookie 401 explained", name)
		}
	}
}

// A credential guesser has no live session on this host, so cPanel never
// writes a token denial for its address: nothing explains its 401s.
func TestStaleSessionEvidenceEmptyExplainsNothing(t *testing.T) {
	r := staleSessionReq(t, staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", staleTabPath, "401"))
	if (StaleSessionEvidence{}).Explains(r) {
		t.Fatal("401 without any evidence was explained")
	}
}

// staleSessionLogs serves the access_log and session_log fixtures that
// CheckAPIAuthFailures reads.
func staleSessionLogs(t *testing.T, access, session []string) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"/usr/local/cpanel/logs/access_log":  dir + "/access_log",
		"/usr/local/cpanel/logs/session_log": dir + "/session_log",
	}
	if err := os.WriteFile(files["/usr/local/cpanel/logs/access_log"], []byte(strings.Join(access, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files["/usr/local/cpanel/logs/session_log"], []byte(strings.Join(session, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if p, ok := files[name]; ok {
				return os.Open(p)
			}
			return nil, os.ErrNotExist
		},
	})
}

// The 2026-09-29 shape: one page load from a stale tab, thirteen 401s in one
// second, cPanel purging the session for token failures in that second.
func staleSessionBurst(ip string) []string {
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, staleSessionAccessLine(ip, "alice", "04/12/2026:07:00:05", "/cpsess0123456789/execute/Themes/list", "401"))
	}
	for i := 0; i < 7; i++ {
		lines = append(lines, staleSessionAccessLine(ip, "-", "04/12/2026:07:00:05", "/cpsess0123456789/execute/WebApp/list", "401"))
	}
	return lines
}

const staleSessionEarlierLine = `[2026-04-12 09:50:00 +0300] info [cpaneld] 192.0.2.44 NEW carol:OtherSessionNameXy address=192.0.2.44,app=cpaneld,method=handle_form_login`

func TestCheckAPIAuthFailuresSkipsStaleSessionBurst(t *testing.T) {
	forceCPanelPlatform(t)
	staleSessionLogs(t, staleSessionBurst("198.51.100.7"), []string{staleSessionEarlierLine, staleSessionDeniedLine})

	for _, f := range CheckAPIAuthFailures(context.Background(), &config.Config{}, nil) {
		if f.Check == "api_auth_failure" {
			t.Fatalf("stale-session burst counted as API auth failures: %s", f.Message)
		}
	}
}

func TestCheckAPIAuthFailuresStillCountsWithoutDenial(t *testing.T) {
	forceCPanelPlatform(t)
	staleSessionLogs(t, staleSessionBurst("203.0.113.9"), []string{staleSessionEarlierLine, staleSessionDeniedLine})

	found := false
	for _, f := range CheckAPIAuthFailures(context.Background(), &config.Config{}, nil) {
		if f.Check == "api_auth_failure" && strings.Contains(f.Message, "203.0.113.9") {
			found = true
		}
	}
	if !found {
		t.Fatal("401 burst from an address with no token denial was not reported")
	}
}

// Anonymous 401s from the stale tab's address that use another token are not
// the stale tab and still count.
func TestCheckAPIAuthFailuresCountsSharedAddressOtherToken(t *testing.T) {
	forceCPanelPlatform(t)
	access := staleSessionBurst("198.51.100.7")
	for i := 0; i < 11; i++ {
		access = append(access, staleSessionAccessLine("198.51.100.7", "-", "04/12/2026:07:00:05", "/cpsess9999999999/execute/Themes/list", "401"))
	}
	staleSessionLogs(t, access, []string{staleSessionEarlierLine, staleSessionDeniedLine})

	for _, f := range CheckAPIAuthFailures(context.Background(), &config.Config{}, nil) {
		if f.Check == "api_auth_failure" && strings.Contains(f.Message, "198.51.100.7: 11 ") {
			return
		}
	}
	t.Fatal("other-token 401s from the stale tab's address were not counted exactly")
}
